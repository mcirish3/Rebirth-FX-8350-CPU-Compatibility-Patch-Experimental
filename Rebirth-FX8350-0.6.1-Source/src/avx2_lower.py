"""AVX2 instruction lowering for an AVX/SSE4.2-capable x64 processor.

Pure code generation. This module does not patch or launch any process.
lower(ins, ip) returns bytes to execute at ip, or None for unsupported forms.
Generated code preserves RFLAGS and all registers except architectural outputs.
Code using RIP-relative memory requires an allocation within its encoding reach.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / 'pylibs'))
import iced_x86 as ix

C, R, I, O = ix.Code, ix.Register, ix.Instruction, ix.OpKind

DIRECT = {
    C.VEX_VBROADCASTI128_YMM_M128: C.VEX_VBROADCASTF128_YMM_M128,
    C.VEX_VINSERTI128_YMM_YMM_XMMM128_IMM8: C.VEX_VINSERTF128_YMM_YMM_XMMM128_IMM8,
    C.VEX_VEXTRACTI128_XMMM128_YMM_IMM8: C.VEX_VEXTRACTF128_XMMM128_YMM_IMM8,
    C.VEX_VPERM2I128_YMM_YMM_YMMM256_IMM8: C.VEX_VPERM2F128_YMM_YMM_YMMM256_IMM8,
    C.VEX_VPAND_YMM_YMM_YMMM256: C.VEX_VANDPS_YMM_YMM_YMMM256,
    C.VEX_VPANDN_YMM_YMM_YMMM256: C.VEX_VANDNPS_YMM_YMM_YMMM256,
    C.VEX_VPOR_YMM_YMM_YMMM256: C.VEX_VORPS_YMM_YMM_YMMM256,
    C.VEX_VPXOR_YMM_YMM_YMMM256: C.VEX_VXORPS_YMM_YMM_YMMM256,
}
for _kind, _float in [('D', 'PS'), ('Q', 'PD')]:
    for _shape in ['XMM_XMM_M128','YMM_YMM_M256','M128_XMM_XMM','M256_YMM_YMM']:
        DIRECT[getattr(C, 'VEX_VPMASKMOV'+_kind+'_'+_shape)] = getattr(C, 'VEX_VMASKMOV'+_float+'_'+_shape)
for _shape in ['XMM_XMM_XMMM128_IMM8','YMM_YMM_YMMM256_IMM8']:
    DIRECT[getattr(C, 'VEX_VPBLENDD_'+_shape)] = getattr(C, 'VEX_VBLENDPS_'+_shape)

# These operations are independently defined on the two 128-bit halves.
LANE_MNEMONICS = set('''VPADDB VPADDW VPADDD VPADDQ VPADDSB VPADDSW VPADDUSB VPADDUSW
VPSUBB VPSUBW VPSUBD VPSUBQ VPSUBSB VPSUBSW VPSUBUSB VPSUBUSW
VPMULLW VPMULLD VPMULHW VPMULHUW VPMULUDQ VPMULDQ VPMULHRSW VPMADDWD VPMADDUBSW
VPAVGB VPAVGW VPMINUB VPMINSB VPMINSW VPMINSD VPMINUW VPMINUD
VPMAXUB VPMAXSB VPMAXSW VPMAXSD VPMAXUW VPMAXUD
VPCMPEQB VPCMPEQW VPCMPEQD VPCMPEQQ VPCMPGTB VPCMPGTW VPCMPGTD VPCMPGTQ
VPUNPCKLBW VPUNPCKLWD VPUNPCKLDQ VPUNPCKLQDQ VPUNPCKHBW VPUNPCKHWD VPUNPCKHDQ VPUNPCKHQDQ
VPACKSSWB VPACKSSDW VPACKUSWB VPACKUSDW
VPSLLDQ VPSRLDQ VPSLLW VPSLLD VPSLLQ VPSRLW VPSRLD VPSRLQ VPSRAW VPSRAD
VPSHUFB VPSHUFD VPSHUFLW VPSHUFHW VPALIGNR VPHADDW VPHADDD VPHADDSW
VPHSUBW VPHSUBD VPHSUBSW VPSIGNB VPSIGNW VPSIGND VPABSB VPABSW VPABSD
VPBLENDW VPBLENDVB VPSADBW'''.split())
CODE_NAMES = {v:k for k,v in vars(C).items() if isinstance(v,int)}
MNEMONIC_NAMES = {v:k for k,v in vars(ix.Mnemonic).items() if isinstance(v,int)}

def xmm(reg):
    if R.XMM0 <= reg <= R.XMM15:
        return reg
    if R.YMM0 <= reg <= R.YMM15:
        return R.XMM0 + reg - R.YMM0
    raise ValueError('Not an XMM/YMM register')

def ymm(reg):
    return R.YMM0 + xmm(reg) - R.XMM0

def memory(ins, extra=0, stack_adjust=0):
    """Preserve the effective address, including absolute RIP-relative target."""
    disp = ins.memory_displacement + extra
    if ins.memory_base in (R.RSP, R.ESP):
        disp += stack_adjust
    return ix.MemoryOperand.ctor_u64(ins.memory_base, ins.memory_index,
        ins.memory_index_scale, disp & ((1 << 64)-1), 8,
        False, ins.segment_prefix)

def _upper_duplicate(dst):
    return I.create_reg_reg_reg_i32(C.VEX_VINSERTF128_YMM_YMM_XMMM128_IMM8,
        ymm(dst), ymm(dst), xmm(dst), 1)

def _stack_mem(offset):
    return ix.MemoryOperand(R.RSP, displ=offset, displ_size=8)

def _scratch_frame(ins, count):
    """Save full scratch YMMs; no arithmetic flags or GPR values are changed."""
    used = {xmm(ins.op_register(n)) for n in range(ins.op_count)
        if ins.op_kind(n)==O.REGISTER and R.XMM0 <= ins.op_register(n) <= R.YMM15}
    regs = [R.XMM0+n for n in range(16) if R.XMM0+n not in used][:count]
    size=count*32
    before=[I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(-size))]
    after=[]
    for n,reg in enumerate(regs):
        before.append(I.create_mem_reg(C.VEX_VMOVDQU_YMMM256_YMM,_stack_mem(n*32),ymm(reg)))
        after.append(I.create_reg_mem(C.VEX_VMOVDQU_YMM_YMMM256,ymm(reg),_stack_mem(n*32)))
    after.append(I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(size)))
    return regs,size,before,after

def _adjust_memory(ins, extra, stack_adjust):
    out=ins.copy()
    disp=out.memory_displacement+extra
    if out.memory_base in (R.RSP,R.ESP):disp+=stack_adjust
    out.memory_displacement=disp&((1<<64)-1)
    out.memory_displ_size=8
    return out

def _lower_lanes(ins):
    if MNEMONIC_NAMES.get(ins.mnemonic) not in LANE_MNEMONICS or not R.YMM0 <= ins.op0_register <= R.YMM15:
        return None
    # No Windows x64 red zone exists. Decline unusual below-RSP memory sources
    # which could alias our scratch saves rather than silently changing them.
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement >= 1<<63:
        return None
    name=CODE_NAMES[ins.code].replace('YMMM256','XMMM128').replace('YMM','XMM')
    code=getattr(C,name,None)
    if code is None:return None
    unique=[]
    for n in range(1,ins.op_count):
        if ins.op_kind(n)==O.REGISTER and R.YMM0<=ins.op_register(n)<=R.YMM15 and ins.op_register(n) not in unique:
            unique.append(ins.op_register(n))
    regs,size,before,after=_scratch_frame(ins,max(1,len(unique)))
    upper=ins.copy();upper.code=code;upper.op0_register=regs[0]
    for src,scratch in zip(unique,regs):
        before.append(I.create_reg_reg_i32(C.VEX_VEXTRACTF128_XMMM128_YMM_IMM8,scratch,src,1))
    for n in range(1,ins.op_count):
        if ins.op_kind(n)==O.REGISTER and ins.op_register(n) in unique:
            upper.set_op_register(n,regs[unique.index(ins.op_register(n))])
    memory_width=ix.MemorySizeExt.info(ins.memory_size).size
    upper=_adjust_memory(upper,16 if memory_width==32 else 0,size)
    low=ins.copy();low.code=code
    for n in range(ins.op_count):
        if ins.op_kind(n)==O.REGISTER and R.YMM0<=ins.op_register(n)<=R.YMM15:
            low.set_op_register(n,xmm(ins.op_register(n)))
    low=_adjust_memory(low,0,size)
    join=I.create_reg_reg_reg_i32(C.VEX_VINSERTF128_YMM_YMM_XMMM128_IMM8,ins.op0_register,ins.op0_register,regs[0],1)
    return before+[upper,low,join]+after

def _lower_permq(ins):
    if ins.code != C.VEX_VPERMQ_YMM_YMMM256_IMM8:return None
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement >= 1<<63:return None
    regs,size,before,after=_scratch_frame(ins,2 if ins.op1_kind==O.REGISTER else 3)
    if ins.op1_kind==O.REGISTER:src=ins.op1_register
    else:
        src=ymm(regs[2]);before.append(I.create_reg_mem(C.VEX_VMOVDQU_YMM_YMMM256,src,memory(ins,stack_adjust=size)))
    indices=[(ins.immediate8>>(2*n))&3 for n in range(4)]
    a=(indices[0]>>1)|((indices[2]>>1)<<4)
    b=(indices[1]>>1)|((indices[3]>>1)<<4)
    pick=sum((v&1)<<n for n,v in enumerate(indices))
    return before+[
        I.create_reg_reg_reg_i32(C.VEX_VPERM2F128_YMM_YMM_YMMM256_IMM8,ymm(regs[0]),src,src,a),
        I.create_reg_reg_reg_i32(C.VEX_VPERM2F128_YMM_YMM_YMMM256_IMM8,ymm(regs[1]),src,src,b),
        I.create_reg_reg_reg_i32(C.VEX_VSHUFPD_YMM_YMM_YMMM256_IMM8,ins.op0_register,ymm(regs[0]),ymm(regs[1]),pick),
    ]+after

def _lower_widen(ins):
    name=MNEMONIC_NAMES.get(ins.mnemonic,'')
    if not name.startswith(('VPMOVSX','VPMOVZX')) or not R.YMM0<=ins.op0_register<=R.YMM15:
        return None
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement>=1<<63:return None
    srcbits={'B':8,'W':16,'D':32}[name[-2]]
    dstbits={'W':16,'D':32,'Q':64}[name[-1]]
    half=16*srcbits//dstbits
    native=getattr(C,'VEX_'+name+'_XMM_XMMM'+str(half*8))
    regs,size,before,after=_scratch_frame(ins,1)
    scratch=regs[0];dst=xmm(ins.op0_register)
    if ins.op1_kind==O.REGISTER:
        src=ins.op1_register
        body=[I.create_reg_reg_i32(C.VEX_VPSRLDQ_XMM_XMM_IMM8,scratch,src,half),
            I.create_reg_reg(native,scratch,scratch),I.create_reg_reg(native,dst,src)]
    elif ins.op1_kind==O.MEMORY:
        body=[I.create_reg_mem(native,scratch,memory(ins,half,size)),
            I.create_reg_mem(native,dst,memory(ins,0,size))]
    else:return None
    body.append(I.create_reg_reg_reg_i32(C.VEX_VINSERTF128_YMM_YMM_XMMM128_IMM8,ins.op0_register,ins.op0_register,scratch,1))
    return before+body+after

def _lower_broadcast_small(ins):
    if ins.mnemonic not in (ix.Mnemonic.VPBROADCASTB,ix.Mnemonic.VPBROADCASTW):return None
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement>=1<<63:return None
    regs,size,before,after=_scratch_frame(ins,1)
    scratch=regs[0];dst=xmm(ins.op0_register);word=ins.mnemonic==ix.Mnemonic.VPBROADCASTW
    if ins.op1_kind==O.MEMORY:
        before.append(I.create_reg_reg_reg(C.VEX_VPXOR_XMM_XMM_XMMM128,dst,dst,dst))
        pin=C.VEX_VPINSRW_XMM_XMM_R32M16_IMM8 if word else C.VEX_VPINSRB_XMM_XMM_R32M8_IMM8
        before.append(I.create_reg_reg_mem_i32(pin,dst,dst,memory(ins,stack_adjust=size),0))
        src=dst
    elif ins.op1_kind==O.REGISTER:src=ins.op1_register
    else:return None
    if word:
        before += [I.create_reg_reg_reg(C.VEX_VPCMPEQW_XMM_XMM_XMMM128,scratch,scratch,scratch),
            I.create_reg_reg_i32(C.VEX_VPSRLW_XMM_XMM_IMM8,scratch,scratch,15),
            I.create_reg_reg_i32(C.VEX_VPSLLW_XMM_XMM_IMM8,scratch,scratch,8)]
    else:before.append(I.create_reg_reg_reg(C.VEX_VPXOR_XMM_XMM_XMMM128,scratch,scratch,scratch))
    before.append(I.create_reg_reg_reg(C.VEX_VPSHUFB_XMM_XMM_XMMM128,dst,src,scratch))
    if R.YMM0<=ins.op0_register<=R.YMM15:before.append(_upper_duplicate(ins.op0_register))
    return before+after

def _lower_scalar_vector(ins):
    """Rare cross-lane operations via bounded scalar work on saved vectors."""
    name=MNEMONIC_NAMES.get(ins.mnemonic,'')
    shifts={'VPSLLVD':('SHL',32),'VPSRLVD':('SHR',32),'VPSRAVD':('SAR',32),
        'VPSLLVQ':('SHL',64),'VPSRLVQ':('SHR',64)}
    movmask=name=='VPMOVMSKB' and R.YMM0<=ins.op1_register<=R.YMM15
    if name not in ('VPERMD','VPERMPS') and name not in shifts and not movmask:return None
    if movmask and ins.op0_register in (R.RSP,R.ESP):return None
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement>=1<<63:return None
    used={xmm(ins.op_register(n)) for n in range(ins.op_count) if ins.op_kind(n)==O.REGISTER and R.XMM0<=ins.op_register(n)<=R.YMM15}
    scratch=next(R.XMM0+n for n in range(16) if R.XMM0+n not in used)
    size=192
    before=[I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(-size)),
        I.create_mem_reg(C.VEX_VMOVDQU_YMMM256_YMM,_stack_mem(96),ymm(scratch))]
    wide=not movmask and R.YMM0<=ins.op0_register<=R.YMM15
    if not movmask:
        store=C.VEX_VMOVDQU_YMMM256_YMM if wide else C.VEX_VMOVDQU_XMMM128_XMM
        load=C.VEX_VMOVDQU_YMM_YMMM256 if wide else C.VEX_VMOVDQU_XMM_XMMM128
        before.append(I.create_mem_reg(store,_stack_mem(0),ins.op1_register))
        if ins.op2_kind==O.REGISTER:
            before.append(I.create_mem_reg(store,_stack_mem(32),ins.op2_register))
        else:
            reg=ymm(scratch) if wide else scratch
            before += [I.create_reg_mem(load,reg,memory(ins,stack_adjust=size)),I.create_mem_reg(store,_stack_mem(32),reg)]
    for n,reg in enumerate([R.RAX,R.RCX,R.RDX]):
        before.append(I.create_mem_reg(C.MOV_RM64_R64,_stack_mem(128+n*8),reg))
    before += [I.create(C.PUSHFQ),I.create_reg(C.POP_R64,R.RAX),I.create_mem_reg(C.MOV_RM64_R64,_stack_mem(152),R.RAX)]
    body=[]
    if movmask:
        body += [I.create_reg_reg_i32(C.VEX_VEXTRACTF128_XMMM128_YMM_IMM8,scratch,ins.op1_register,1),
            I.create_reg_reg(C.VEX_VPMOVMSKB_R32_XMM,R.EAX,scratch),
            I.create_reg_i32(C.SHL_RM32_IMM8,R.EAX,16),
            I.create_reg_reg(C.VEX_VPMOVMSKB_R32_XMM,R.ECX,xmm(ins.op1_register)),
            I.create_reg_reg(C.OR_R32_RM32,R.EAX,R.ECX),
            I.create_mem_reg(C.MOV_RM32_R32,_stack_mem(64),R.EAX)]
    elif name in ('VPERMD','VPERMPS'):
        for n in range(8):
            body += [I.create_reg_mem(C.MOV_R32_RM32,R.ECX,_stack_mem(n*4)),
                I.create_reg_i32(C.AND_RM32_IMM8,R.ECX,7),
                I.create_reg_mem(C.MOV_R32_RM32,R.EAX,ix.MemoryOperand(R.RSP,R.RCX,4,32,8)),
                I.create_mem_reg(C.MOV_RM32_R32,_stack_mem(64+n*4),R.EAX)]
    else:
        operation,bits=shifts[name];bytesize=bits//8
        a=R.RAX if bits==64 else R.EAX;c=R.RCX if bits==64 else R.ECX;d=R.RDX if bits==64 else R.EDX
        mov=getattr(C,'MOV_R'+str(bits)+'_RM'+str(bits));store=getattr(C,'MOV_RM'+str(bits)+'_R'+str(bits))
        for n in range((32 if wide else 16)//bytesize):
            body += [I.create_reg_mem(mov,a,_stack_mem(n*bytesize)),
                I.create_reg_mem(mov,c,_stack_mem(32+n*bytesize)),
                I.create_reg_i32(C.MOV_R32_IMM32,R.EDX,bits-1 if operation=='SAR' else 0)]
            if operation=='SAR':
                body += [I.create_reg_i32(getattr(C,'CMP_RM'+str(bits)+'_IMM8'),c,bits),
                    I.create_reg_reg(getattr(C,'CMOVAE_R'+str(bits)+'_RM'+str(bits)),c,d)]
            body.append(I.create_reg_reg(getattr(C,operation+'_RM'+str(bits)+'_CL'),a,R.CL))
            if operation!='SAR':
                body += [I.create_reg_i32(getattr(C,'CMP_RM'+str(bits)+'_IMM8'),c,bits),
                    I.create_reg_reg(getattr(C,'CMOVAE_R'+str(bits)+'_RM'+str(bits)),a,d)]
            body.append(I.create_mem_reg(store,_stack_mem(64+n*bytesize),a))
    after=[I.create_reg_mem(C.MOV_R64_RM64,R.RAX,_stack_mem(152)),I.create_reg(C.PUSH_R64,R.RAX),I.create(C.POPFQ)]
    for n,reg in enumerate([R.RAX,R.RCX,R.RDX]):
        after.append(I.create_reg_mem(C.MOV_R64_RM64,reg,_stack_mem(128+n*8)))
    after.append(I.create_reg_mem(C.VEX_VMOVDQU_YMM_YMMM256,ymm(scratch),_stack_mem(96)))
    if movmask:
        dst=ins.op0_register
        if R.RAX<=dst<=R.R15:dst=R.EAX+dst-R.RAX
        after.append(I.create_reg_mem(C.MOV_R32_RM32,dst,_stack_mem(64)))
    else:
        after.append(I.create_reg_mem(C.VEX_VMOVDQU_YMM_YMMM256 if wide else C.VEX_VMOVDQU_XMM_XMMM128,ins.op0_register,_stack_mem(64)))
    after.append(I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(size)))
    return before+body+after

def _lower_gather(ins):
    """AVX2 gather normal-completion semantics with masked fault suppression.

    Like other native expansion stubs, an active memory fault occurs inside
    the stub. Original gather partial-completion exception context is not
    reconstructed; callers must not advertise exact fault-resume semantics.
    """
    name=MNEMONIC_NAMES.get(ins.mnemonic,'')
    kinds={
        'VPGATHERDD':(4,4),'VGATHERDPS':(4,4),
        'VPGATHERQD':(8,4),'VGATHERQPS':(8,4),
        'VPGATHERDQ':(4,8),'VGATHERDPD':(4,8),
        'VPGATHERQQ':(8,8),'VGATHERQPD':(8,8),
    }
    if name not in kinds:return None
    if ins.segment_prefix in (R.FS,R.GS):return None
    dst,index,mask=ins.op0_register,ins.memory_index,ins.op2_register
    if len({xmm(dst),xmm(index),xmm(mask)})!=3:return None
    if ins.memory_base in (R.RSP,R.ESP) and ins.memory_displacement>=1<<63:return None
    index_size,item_size=kinds[name]
    dest_width=32 if R.YMM0<=dst<=R.YMM15 else 16
    index_width=32 if R.YMM0<=index<=R.YMM15 else 16
    count=min(dest_width//item_size,index_width//index_size)
    used=ix.InstructionInfoFactory().info(ins).used_memory()
    if not used:return None
    addr32=used[0].address_size==ix.CodeSize.CODE32
    frame=192
    before=[I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(-frame))]
    for off,reg in [(0,dst),(32,mask),(64,index)]:
        before.append(I.create_mem_reg(C.VEX_VMOVDQU_YMMM256_YMM,_stack_mem(off),ymm(reg)))
    for n,reg in enumerate([R.RAX,R.RCX,R.RDX,R.R11]):
        before.append(I.create_mem_reg(C.MOV_RM64_R64,_stack_mem(128+n*8),reg))
    disp=ins.memory_displacement+(frame if ins.memory_base in (R.RSP,R.ESP) else 0)
    base_mem=ix.MemoryOperand.ctor_u64(ins.memory_base,R.NONE,1,disp&((1<<64)-1),8)
    if ins.memory_base==R.NONE:
        before.append(I.create_reg_u32(C.MOV_R32_IMM32,R.R11D,disp&0xffffffff) if addr32 else I.create_reg_u64(C.MOV_R64_IMM64,R.R11,disp&((1<<64)-1)))
    else:before.append(I.create_reg_mem(C.LEA_R32_M if addr32 else C.LEA_R64_M,R.R11D if addr32 else R.R11,base_mem))
    before += [I.create(C.PUSHFQ),I.create_reg(C.POP_R64,R.RAX),I.create_mem_reg(C.MOV_RM64_R64,_stack_mem(160),R.RAX)]
    # Architecturally unused destination elements are always cleared.
    for off in range(count*item_size,32,4):
        before.append(I.create_mem_i32(C.MOV_RM32_IMM32,_stack_mem(off),0))
    body=[]
    for n in range(count):
        body.append(I.create_reg_mem(C.MOVSXD_R64_RM32 if index_size==4 else C.MOV_R64_RM64,R.RCX,_stack_mem(64+n*index_size)))
        body.append(I.create_reg_mem(C.LEA_R32_M if addr32 else C.LEA_R64_M,R.EAX if addr32 else R.RAX,ix.MemoryOperand(R.R11,R.RCX,ins.memory_index_scale)))
        body += [I.create_reg_mem(C.LEA_R64_M,R.RDX,_stack_mem(n*item_size)),
            I.create_mem_i32(C.CMP_RM32_IMM8 if item_size==4 else C.CMP_RM64_IMM8,_stack_mem(32+n*item_size),0),
            I.create_reg_reg(C.CMOVNS_R64_RM64,R.RAX,R.RDX),
            I.create_reg_mem(C.MOV_R32_RM32 if item_size==4 else C.MOV_R64_RM64,R.EAX if item_size==4 else R.RAX,ix.MemoryOperand(R.RAX)),
            I.create_mem_reg(C.MOV_RM32_R32 if item_size==4 else C.MOV_RM64_R64,_stack_mem(n*item_size),R.EAX if item_size==4 else R.RAX)]
    after=[I.create_reg_mem(C.MOV_R64_RM64,R.RAX,_stack_mem(160)),I.create_reg(C.PUSH_R64,R.RAX),I.create(C.POPFQ)]
    for n,reg in enumerate([R.RAX,R.RCX,R.RDX,R.R11]):
        after.append(I.create_reg_mem(C.MOV_R64_RM64,reg,_stack_mem(128+n*8)))
    after += [I.create_reg_mem(C.VEX_VMOVDQU_YMM_YMMM256,ymm(dst),_stack_mem(0)),
        I.create_reg_reg_reg(C.VEX_VXORPS_XMM_XMM_XMMM128,xmm(mask),xmm(mask),xmm(mask)),
        I.create_reg_mem(C.LEA_R64_M,R.RSP,_stack_mem(frame))]
    return before+body+after

def _lower_instructions(ins):
    if ins.encoding != ix.EncodingKind.VEX:
        return None
    if ins.code in DIRECT:
        out = ins.copy()
        out.code = DIRECT[ins.code]
        return [out]
    if ins.mnemonic in (ix.Mnemonic.VBROADCASTSS, ix.Mnemonic.VPBROADCASTD):
        dst = ins.op0_register
        if not R.XMM0 <= dst <= R.YMM15:
            return None
        d = xmm(dst)
        if ins.op1_kind == O.REGISTER:
            src = xmm(ins.op1_register)
            out = [I.create_reg_reg_reg_i32(C.VEX_VSHUFPS_XMM_XMM_XMMM128_IMM8,
                d, src, src, 0)]
        elif ins.op1_kind == O.MEMORY:
            out = [I.create_reg_mem(C.VEX_VMOVSS_XMM_M32, d, memory(ins)),
                I.create_reg_reg_reg_i32(C.VEX_VSHUFPS_XMM_XMM_XMMM128_IMM8,
                d, d, d, 0)]
        else:
            return None
        if R.YMM0 <= dst <= R.YMM15:
            out.append(_upper_duplicate(dst))
        return out
    if ins.mnemonic in (ix.Mnemonic.VBROADCASTSD, ix.Mnemonic.VPBROADCASTQ):
        dst = ins.op0_register
        d = xmm(dst)
        if ins.op1_kind == O.REGISTER:
            out = [I.create_reg_reg(C.VEX_VMOVDDUP_XMM_XMMM64, d, xmm(ins.op1_register))]
        elif ins.op1_kind == O.MEMORY:
            out = [I.create_reg_mem(C.VEX_VMOVDDUP_XMM_XMMM64, d, memory(ins))]
        else:
            return None
        if R.YMM0 <= dst <= R.YMM15:
            out.append(_upper_duplicate(dst))
        return out
    return _lower_broadcast_small(ins) or _lower_widen(ins) or _lower_permq(ins) or _lower_lanes(ins) or _lower_scalar_vector(ins) or _lower_gather(ins)

def lower_instructions(ins, external_stack_adjust=0):
    if external_stack_adjust:
        if external_stack_adjust < 0:
            raise ValueError('external_stack_adjust must be nonnegative')
        ins=ins.copy()
        if ins.memory_base in (R.RSP,R.ESP):
            # A caller-supplied synthetic return address occupies below-RSP
            # memory; decline originals that read that unusual area.
            if ins.memory_displacement>=1<<63:return None
            ins.memory_displacement=(ins.memory_displacement+external_stack_adjust)&((1<<64)-1)
            ins.memory_displ_size=8
    lowered = _lower_instructions(ins)
    if lowered is not None:
        # Copied instruction IPs are not labels in a branch-free replacement.
        # BlockEncoder rejects duplicate nonzero IPs; RIP memory stores its
        # absolute target separately and remains intact when IP is reset.
        for instruction in lowered:
            instruction.ip = 0
    return lowered

def lower(ins, ip, external_stack_adjust=0):
    lowered = lower_instructions(ins, external_stack_adjust)
    if lowered is None:
        return None
    encoder = ix.BlockEncoder(64)
    encoder.add_many(lowered)
    return encoder.encode(ip)

def supported(ins):
    return lower_instructions(ins) is not None
