"""Build local, reversible PE compatibility copies; never overwrites installed files."""
import sys,json,struct,hashlib,collections,bisect,re,ctypes
from pathlib import Path
WORK=Path(__file__).parent
sys.path.insert(0,str(WORK/'pylibs'))
import pefile,iced_x86 as ix
import bmi2_lower,avx2_lower,unwind_builder
GAME=Path('.') # Input supplied explicitly by the review build driver.
STAGING=WORK/'staging'; STAGING.mkdir(exist_ok=True)
def align(n,a):return (n+a-1)&~(a-1)

def native_checksum(data):
    calculate=ctypes.WinDLL('imagehlp').CheckSumMappedFile
    calculate.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32)]
    calculate.restype=ctypes.c_void_p
    if len(data)>0xffffffff:raise ValueError('Image too large for PE checksum')
    buffer=(ctypes.c_ubyte*len(data)).from_buffer(data)
    header=ctypes.c_uint32();checksum=ctypes.c_uint32()
    if not calculate(buffer,len(data),ctypes.byref(header),ctypes.byref(checksum)):
        raise RuntimeError('Windows PE checksum calculation failed')
    return checksum.value

class Builder:
    def __init__(self,path,hits):
        self.path=Path(path); self.original=self.path.read_bytes(); self.data=bytearray(self.original)
        self.pe=pefile.PE(data=self.original,fast_load=True); self.pe.parse_data_directories(directories=[1,3,5])
        self.base=self.pe.OPTIONAL_HEADER.ImageBase; self.old_image=self.pe.OPTIONAL_HEADER.SizeOfImage
        self.iat_rva=align(self.old_image,self.pe.OPTIONAL_HEADER.SectionAlignment)
        self.iat_raw=align(len(self.original),self.pe.OPTIONAL_HEADER.FileAlignment)
        self.iat_payload=b''
        self.rva=self.iat_rva+self.pe.OPTIONAL_HEADER.SectionAlignment
        self.raw=self.iat_raw+self.pe.OPTIONAL_HEADER.FileAlignment
        self.payload=bytearray(32); self.hits=hits; self.records=[]; self.redirects=[]; self.new_relocs=[]; self.skipped=[]
        self.targets=None; self.caves=None
        self.unwind_entries=[]; self.unwind_blobs={}; self.unwind_refusals=[]
        self.fmt=ix.Formatter(ix.FormatterSyntax.INTEL)
    def append(self,data,a=1):
        pos=align(len(self.payload),a); self.payload.extend(b'\0'*(pos-len(self.payload))); self.payload.extend(data)
        return self.rva+pos
    def store(self,rva,data):
        if rva>=self.rva:self.payload[rva-self.rva:rva-self.rva+len(data)]=data
        else:
            off=self.pe.get_offset_from_rva(rva); self.data[off:off+len(data)]=data
    def imports(self):
        dllname=self.append(b'fxcompat.dll\0')
        names=[self.append(b'\0\0'+n+b'\0',2) for n in [b'FxCompatImportAnchor',b'FxCompatRegisterModule']]
        thunks=struct.pack('<QQQ',*names,0); ilt=self.append(thunks,8)
        # Loader-resolved addresses must be writable without making the native code writable.
        self.iat_payload=thunks; iat=self.iat_rva
        old=[]; imp=self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]
        for p in range(imp.VirtualAddress,imp.VirtualAddress+imp.Size,20):
            desc=self.pe.get_data(p,20)
            if desc==b'\0'*20:break
            old.append(desc)
        table=b''.join(old)+struct.pack('<IIIII',ilt,0,0,dllname,iat)+b'\0'*20
        table_rva=self.append(table,8)
        imp.VirtualAddress=table_rva; imp.Size=len(table)
        return iat
    def prepare_caves(self):
        if self.caves is not None:return
        cache_dir=WORK/'code_cache';cache_dir.mkdir(exist_ok=True)
        cache_file=cache_dir/(hashlib.sha256(self.original).hexdigest()+'.padding.json')
        if cache_file.exists():
            self.caves=json.loads(cache_file.read_text());self.used_caves=set();return
        print('Preparing safe padding inventory',self.path.name,flush=True)
        ranges=sorted((e.struct.BeginAddress,e.struct.EndAddress) for e in getattr(self.pe,'DIRECTORY_ENTRY_EXCEPTION',[]))
        starts=[s for s,e in ranges]
        targets=set(starts)
        candidates=[]
        for sec in self.pe.sections:
            if not sec.Characteristics&0x20000000:continue
            raw=sec.get_data()[:sec.Misc_VirtualSize]
            for ins in ix.Decoder(64,raw,ip=sec.VirtualAddress):
                if ins.op0_kind in (ix.OpKind.NEAR_BRANCH16,ix.OpKind.NEAR_BRANCH32,ix.OpKind.NEAR_BRANCH64):targets.add(ins.near_branch_target)
            for match in re.finditer(b'\xcc{5,}',raw):
                for pos in range(sec.VirtualAddress+match.start(),sec.VirtualAddress+match.end()-4):
                    idx=bisect.bisect_right(starts,pos)-1
                    if idx>=0 and pos<ranges[idx][1]:continue
                    if idx+1<len(ranges) and pos+5>ranges[idx+1][0]:continue
                    candidates.append(pos)
        for block in getattr(self.pe,'DIRECTORY_ENTRY_BASERELOC',[]):
            for entry in block.entries:
                if entry.type==10:
                    target=int.from_bytes(self.pe.get_data(entry.rva,8),'little')-self.base
                    if 0<=target<self.old_image:targets.add(target)
        self.targets=targets
        self.caves=sorted(p for p in candidates if not any(p+i in targets for i in range(5)))
        self.used_caves=set()
        cache_file.write_text(json.dumps(self.caves))
    def cave(self,rva):
        self.prepare_caves()
        idx=bisect.bisect_left(self.caves,rva-126)
        while idx<len(self.caves) and self.caves[idx]<=rva+129:
            p=self.caves[idx];idx+=1
            if any(p+i in self.used_caves for i in range(5)):continue
            off=self.pe.get_offset_from_rva(p)
            if self.data[off:off+5]!=b'\xcc'*5:continue
            self.used_caves.update(range(p,p+5));return p
        return None
    def lower(self,ins,ip,adjust=0):
        fs=ins.cpuid_features()
        if ix.CpuidFeature.BMI2 in fs:return bmi2_lower.lower(ins,ip,external_stack_adjust=adjust)
        if ix.CpuidFeature.AVX2 in fs:return avx2_lower.lower(ins,ip,external_stack_adjust=adjust)
        return None
    def make_stub(self,ins):
        start=self.rva+align(len(self.payload),16)
        body=self.lower(ins,self.base+start+6,8)
        if body is None:return None
        # PUSH [RIP+literal] supplies a genuine return address without clobbering state.
        literal=start+6+len(body)+1
        prefix=b'\xff\x35'+struct.pack('<i',literal-(start+6))
        code=prefix+body+b'\xc3'+struct.pack('<Q',ins.next_ip)
        actual=self.append(code,16); assert actual==start
        self.new_relocs.append((literal,10))
        decoder=ix.Decoder(64,body,ip=self.base+start+6)
        for item in decoder:
            if item.is_invalid:raise RuntimeError('Invalid instruction in generated body')
            if any(f in (ix.CpuidFeature.AVX2,ix.CpuidFeature.BMI2,ix.CpuidFeature.AVX512F) for f in item.cpuid_features()):raise RuntimeError('Unsupported instruction remains in generated body')
            if item.code==ix.Code.MOV_R64_IMM64 and self.base<=item.immediate64<self.base+self.old_image:
                const=decoder.get_constant_offsets(item)
                self.new_relocs.append((item.ip-self.base+const.immediate_offset,10))
        description=unwind_builder.inspect_unwind_intervals(body,self.base+start+6)
        if description['intervals'] is None:
            self.unwind_refusals.append({'stub_rva':hex(start),'reason':description['reason']})
        else:
            for interval in description['intervals']:
                blob=interval['unwind']
                if blob not in self.unwind_blobs:self.unwind_blobs[blob]=self.append(blob,4)
                self.unwind_entries.append((start+6+interval['begin_offset'],start+6+interval['end_offset'],self.unwind_blobs[blob]))
        return start
    def stack_neutral(self,body,ip):
        for ins in ix.Decoder(64,body,ip=ip):
            if ins.stack_pointer_increment!=0:return False
            if ins.op0_kind==ix.OpKind.REGISTER and ins.op0_register in (ix.Register.RSP,ix.Register.ESP):return False
        return True
    def instructions(self):
        seen=set()
        for hit in sorted(self.hits,key=lambda h:int(h['rva'],16)):
            rva=int(hit['rva'],16)
            if rva in seen:continue
            seen.add(rva)
            raw=self.pe.get_data(rva,15);ins=ix.Decoder(64,raw,ip=self.base+rva).decode()
            if ins.is_invalid:raise RuntimeError('Invalid original instruction')
            if not any(f in (ix.CpuidFeature.AVX2,ix.CpuidFeature.BMI2) for f in ins.cpuid_features()):continue
            if 'bytes' in hit and raw[:ins.len].hex()!=hit['bytes']:raise RuntimeError('Input inventory bytes differ')
            try:body=self.lower(ins,ins.ip)
            except Exception as err:self.skipped.append({'rva':hex(rva),'asm':str(ins),'error':str(err)});continue
            if body is None:self.skipped.append({'rva':hex(rva),'asm':str(ins),'error':'unsupported'});continue
            cave=None;stub=None
            if len(body)<=ins.len and self.stack_neutral(body,ins.ip):
                patch=body+b'\x90'*(ins.len-len(body));method='in_place'
            else:
                try:stub=self.make_stub(ins)
                except Exception as err:self.skipped.append({'rva':hex(rva),'asm':str(ins),'error':str(err)});continue
                if stub is None:continue
                if ins.len>=5:
                    patch=b'\xe9'+struct.pack('<i',stub-rva-5)+b'\x90'*(ins.len-5);method='native_jump'
                elif (cave:=self.cave(rva)) is not None:
                    self.store(cave,b'\xe9'+struct.pack('<i',stub-cave-5))
                    patch=b'\xeb'+struct.pack('<b',cave-rva-2)+b'\x90'*(ins.len-2);method='padding_jump'
                else:
                    patch=raw[:ins.len];self.redirects.append((rva,stub));method='native_exception_redirect'
            self.store(rva,patch)
            self.records.append({'rva':hex(rva),'asm':self.fmt.format(ins),'original':raw[:ins.len].hex(),'patch':patch.hex(),'stub_rva':hex(stub) if stub else None,'cave_rva':hex(cave) if cave else None,'method':method})
        print('Translated',len(self.records),'skipped',len(self.skipped),dict(collections.Counter(r['method'] for r in self.records)),flush=True)
    def aux_entry(self,iat):
        # Windows DLL entrypoint receives module in RCX, reason in EDX, reserved in R8.
        old=self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        start=self.rva+align(len(self.payload),16)
        # For non-attach calls, jump straight to original entrypoint.
        code=bytearray(bytes.fromhex('83fa01 7500'))
        code+=bytes.fromhex('50 51 52 4150 4151 4152 4153 9c 4883ec28')
        callpos=start+len(code);code+=b'\xff\x15'+struct.pack('<i',iat+8-callpos-6)
        code+=bytes.fromhex('85c0 7500');failure_branch=len(code)-1
        restore=bytes.fromhex('4883c428 9d 415b 415a 4159 4158 5a 59 58')
        code+=restore
        original_jmp=len(code);code+=b'\xe9'+struct.pack('<i',old-(start+len(code)+5))
        fail=len(code);code+=restore+bytes.fromhex('31c0 c3')
        code[4]=original_jmp-5
        code[failure_branch]=fail-(failure_branch+1)
        self.append(code,16);self.pe.OPTIONAL_HEADER.AddressOfEntryPoint=start
    def finish(self):
        iat=self.imports(); self.instructions()
        if self.path.name.lower()=='ff7rebirth_.exe':
            # Located by pattern (see cpu_gate.py) so game updates that move it still work.
            import cpu_gate
            rva=cpu_gate.find(self.pe,self.original)
            self.cpu_gate_rva=rva
            self.store(rva,b'\xeb'+self.pe.get_data(rva+1,1))
        elif self.pe.FILE_HEADER.Characteristics&0x2000:self.aux_entry(iat)
        entries=self.append(b''.join(struct.pack('<II',*x) for x in self.redirects),8)
        self.payload[:32]=struct.pack('<8sIIIIII',b'FXCPT001',1,len(self.redirects),entries,0,self.old_image,0)
        if self.unwind_entries:
            directory=self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            old_table=self.pe.get_data(directory.VirtualAddress,directory.Size)
            new_table=old_table+b''.join(struct.pack('<III',*row) for row in sorted(self.unwind_entries))
            directory.VirtualAddress=self.append(new_table,4);directory.Size=len(new_table)
        relocations=collections.defaultdict(set)
        for block in getattr(self.pe,'DIRECTORY_ENTRY_BASERELOC',[]):
            for e in block.entries:
                if e.type:relocations[e.rva&~4095].add((e.type<<12)|(e.rva&4095))
        for rva,kind in self.new_relocs:relocations[rva&~4095].add((kind<<12)|(rva&4095))
        reloc=bytearray()
        for page,items in sorted(relocations.items()):
            rows=sorted(items)
            if len(rows)&1:rows.append(0)
            reloc+=struct.pack('<II',page,8+len(rows)*2)+struct.pack('<'+'H'*len(rows),*rows)
        reloc_rva=self.append(reloc,4)
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress=reloc_rva
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size=len(reloc)
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress=0;self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size=0
        self.pe.OPTIONAL_HEADER.SizeOfImage=align(self.rva+len(self.payload),self.pe.OPTIONAL_HEADER.SectionAlignment)
        self.pe.OPTIONAL_HEADER.SizeOfCode+=align(len(self.payload),self.pe.OPTIONAL_HEADER.FileAlignment)
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData+=self.pe.OPTIONAL_HEADER.FileAlignment
        self.pe.OPTIONAL_HEADER.CheckSum=0
        header=self.pe.sections[-1].get_file_offset()+40
        if header+80>self.pe.OPTIONAL_HEADER.SizeOfHeaders:raise RuntimeError('No room for added section headers')
        self.pe.FILE_HEADER.NumberOfSections+=2
        # pefile updates known headers; copy only those fields back over patched contents.
        headers=self.pe.write()[:self.pe.OPTIONAL_HEADER.SizeOfHeaders]
        self.data[:len(headers)]=headers
        rawsize=align(len(self.payload),self.pe.OPTIONAL_HEADER.FileAlignment)
        iat_section=struct.pack('<8sIIIIIIHHI',b'.fxiat\0\0',len(self.iat_payload),self.iat_rva,self.pe.OPTIONAL_HEADER.FileAlignment,self.iat_raw,0,0,0,0,0xc0000040)
        section=struct.pack('<8sIIIIIIHHI',b'.fxcpt\0\0',len(self.payload),self.rva,rawsize,self.raw,0,0,0,0,0x60000020)
        self.data[header:header+80]=iat_section+section
        self.data.extend(b'\0'*(self.iat_raw-len(self.data)));self.data.extend(self.iat_payload)
        self.data.extend(b'\0'*(self.raw-len(self.data)));self.data.extend(self.payload);self.data.extend(b'\0'*(rawsize-len(self.payload)))
        checksum=native_checksum(self.data);struct.pack_into('<I',self.data,self.pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'),checksum)
        output=STAGING/self.path.name
        temporary=STAGING/(self.path.name+'.building')
        temporary.write_bytes(self.data);temporary.replace(output)
        report={'source':str(self.path),'source_sha256':hashlib.sha256(self.original).hexdigest(),'output':str(output),'sha256':hashlib.sha256(self.data).hexdigest(),'section_rva':hex(self.rva),'section_size':len(self.payload),'redirects':len(self.redirects),'methods':dict(collections.Counter(r['method'] for r in self.records)),'translated':len(self.records),'skipped':self.skipped,'records':self.records,'unwind_intervals':len(self.unwind_entries),'unwind_refusals':self.unwind_refusals,'limitations':['Synthetic return PUSH prefix lacks original-function unwind mapping','Fault-address translation and partial-instruction fault recovery are not implemented','Further runtime coverage and gameplay testing required']}
        (STAGING/(self.path.name+'.manifest.json')).write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k not in ('records','skipped')},indent=2),flush=True)

