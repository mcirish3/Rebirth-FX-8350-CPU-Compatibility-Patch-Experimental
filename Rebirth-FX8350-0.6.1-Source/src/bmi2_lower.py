"""Conservative Windows x64 BMI2 instruction lowering using iced-x86.

lower(ins, ip=0) returns a native body without a return/jump to the game.
The decoded input instruction must have its ORIGINAL IP, so RIP-relative
operands can be resolved. The returned body may be relocated unchanged: it
uses absolute addresses for original RIP-relative operands and only local
branches. ``ip`` is the intended output address used by the encoder.

Contract/limits: normal accessible Windows x64 stack; borrows up to 40 bytes below
RSP and has no unwind metadata. It preserves all registers other than the
documented destination, and preserves flags except BZHI's defined changes.
Memory-source aliases with the borrowed stack are not supported. Obvious
RSP-relative aliases are rejected. An access fault within this body is not
transparent to the original game's exception handler. No game is modified.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "pylibs"))
import iced_x86 as ix

R, C, I, M = ix.Register, ix.Code, ix.Instruction, ix.MemoryOperand
GPRS64 = [R.RAX, R.RCX, R.RDX, R.RBX, R.RSP, R.RBP, R.RSI, R.RDI,
          R.R8, R.R9, R.R10, R.R11, R.R12, R.R13, R.R14, R.R15]
GPRS32 = [R.EAX, R.ECX, R.EDX, R.EBX, R.ESP, R.EBP, R.ESI, R.EDI,
          R.R8D, R.R9D, R.R10D, R.R11D, R.R12D, R.R13D, R.R14D, R.R15D]
FULL = dict(zip(GPRS32, GPRS64)) | dict(zip(GPRS64, GPRS64))
LOW32 = dict(zip(GPRS64, GPRS32))
SUPPORTED = {
    C.VEX_SHLX_R32_RM32_R32: ("SHL", 32),
    C.VEX_SHLX_R64_RM64_R64: ("SHL", 64),
    C.VEX_SHRX_R32_RM32_R32: ("SHR", 32),
    C.VEX_SHRX_R64_RM64_R64: ("SHR", 64),
    C.VEX_SARX_R32_RM32_R32: ("SAR", 32),
    C.VEX_SARX_R64_RM64_R64: ("SAR", 64),
    C.VEX_BZHI_R32_RM32_R32: ("BZHI", 32),
    C.VEX_BZHI_R64_RM64_R64: ("BZHI", 64),
}


class LoweringError(ValueError):
    """The requested operand form cannot be safely lowered by this module."""


def _signed64(n):
    n &= (1 << 64) - 1
    return n - (1 << 64) if n & (1 << 63) else n


def _register_shift_fast(ins, ip, operation, bits, external_stack_adjust=0):
    """Direct shifts with just flags and one scratch register saved at most.

The source is a register and the destination is not RSP. Order of operand
copies matters: for dst!=RCX, capture count first; for dst=RCX, capture value
first in RAX. Saved operands are used if the first copy clobbers the second.
"""
    b = _Builder()
    emit = b.emit
    dst = ins.op0_register
    src64, count64, dst64 = (FULL[ins.op1_register], FULL[ins.op2_register], FULL[dst])
    mov = C.MOV_R64_RM64 if bits == 64 else C.MOV_R32_RM32
    lea = C.LEA_R64_M if bits == 64 else C.LEA_R32_M
    narrow = lambda r: r if bits == 64 else LOW32[r]
    shift = getattr(C, f"{operation}_RM{bits}_CL")
    emit(I.create(C.PUSHFQ))

    if dst64 == R.RCX:
        emit(I.create_reg(C.PUSH_R64, R.RAX))
        # Preserve the value before RCX becomes the shift count.
        if src64 == R.RSP:
            emit(I.create_reg_mem(lea, narrow(R.RAX), M(R.RSP, displ=16 + external_stack_adjust, displ_size=1)))
        elif src64 != R.RAX:
            emit(I.create_reg_reg(mov, narrow(R.RAX), narrow(src64)))
        if count64 == R.RSP:
            emit(I.create_reg_mem(lea, narrow(R.RCX), M(R.RSP, displ=16 + external_stack_adjust, displ_size=1)))
        elif count64 == R.RAX:
            emit(I.create_reg_mem(mov, narrow(R.RCX), M(R.RSP)))
        elif count64 != R.RCX:
            emit(I.create_reg_reg(mov, narrow(R.RCX), narrow(count64)))
        emit(I.create_reg_reg(shift, narrow(R.RAX), R.CL))
        emit(I.create_reg_reg(mov, dst, narrow(R.RAX)))
        emit(I.create_reg(C.POP_R64, R.RAX))
    else:
        save_rcx = count64 != R.RCX
        frame = 16 if save_rcx else 8
        if save_rcx:
            emit(I.create_reg(C.PUSH_R64, R.RCX))
            if count64 == R.RSP:
                emit(I.create_reg_mem(lea, narrow(R.RCX), M(R.RSP, displ=frame + external_stack_adjust, displ_size=1)))
            else:
                emit(I.create_reg_reg(mov, narrow(R.RCX), narrow(count64)))
        if src64 == R.RSP:
            emit(I.create_reg_mem(lea, dst, M(R.RSP, displ=frame + external_stack_adjust, displ_size=1)))
        elif src64 == R.RCX and save_rcx:
            emit(I.create_reg_mem(mov, dst, M(R.RSP)))
        elif src64 != dst64:
            emit(I.create_reg_reg(mov, dst, narrow(src64)))
        emit(I.create_reg_reg(shift, dst, R.CL))
        if save_rcx:
            emit(I.create_reg(C.POP_R64, R.RCX))
    emit(I.create(C.POPFQ))
    return b.encode(ip)


class _Builder:
    def __init__(self):
        self.instructions = []
        self.labels = {}
        self.branches = []

    def emit(self, ins):
        self.instructions.append(ins)

    def label(self, name):
        self.labels[name] = len(self.instructions)

    def branch(self, code, label):
        self.branches.append((len(self.instructions), code, label))
        self.emit(I.create_branch(code, 0))

    def encode(self, ip):
        # Fake unique input addresses let BlockEncoder resolve local labels.
        base = 0x123400000000
        for n, ins in enumerate(self.instructions):
            ins.ip = base + n * 16
        for n, code, label in self.branches:
            target = base + self.labels[label] * 16
            self.instructions[n].near_branch64 = target
        enc = ix.BlockEncoder(64)
        enc.add_many(self.instructions)
        return enc.encode(ip)


def _lower(ins: ix.Instruction, ip: int = 0, use_fast: bool = True,
           external_stack_adjust: int = 0) -> bytes:
    if ins.code not in SUPPORTED:
        raise LoweringError(f"Unsupported instruction: {ins}")
    if ins.op0_kind != ix.OpKind.REGISTER or ins.op2_kind != ix.OpKind.REGISTER:
        raise LoweringError("Destination and count must be GPR registers")
    operation, bits = SUPPORTED[ins.code]
    regs = GPRS64 if bits == 64 else GPRS32
    if ins.op0_register not in regs or ins.op2_register not in regs:
        raise LoweringError("Unexpected register width")
    if ins.op1_kind not in (ix.OpKind.REGISTER, ix.OpKind.MEMORY):
        raise LoweringError("Source must be a GPR or ordinary memory")
    if ins.op1_kind == ix.OpKind.REGISTER and ins.op1_register not in regs:
        raise LoweringError("Unexpected source register width")
    if external_stack_adjust not in (0, 8):
        raise LoweringError("external_stack_adjust must be 0 or 8")
    if external_stack_adjust and FULL[ins.op0_register] == R.RSP:
        raise LoweringError("A return-address trampoline cannot change RSP/ESP")

    if (use_fast and operation != "BZHI" and ins.op1_kind == ix.OpKind.REGISTER
            and FULL[ins.op0_register] != R.RSP):
        return _register_shift_fast(ins, ip, operation, bits, external_stack_adjust)

    b = _Builder()
    emit = b.emit
    dst64 = FULL[ins.op0_register]
    save_flags = operation != "BZHI"
    frame_size = 40 if save_flags else 32
    result_offset = frame_size - 8
    # Layout: RDX0, RCX8, RAX16, optional RFLAGS24, then result slot.
    # POP destination last handles overlaps, 32-bit zero extension and RSP.
    emit(I.create_reg(C.PUSH_R64, dst64))
    if save_flags:
        emit(I.create(C.PUSHFQ))
    for reg in (R.RAX, R.RCX, R.RDX):
        emit(I.create_reg(C.PUSH_R64, reg))

    def original_reg(target64, source, width):
        source64 = FULL[source]
        target = target64 if width == 64 else LOW32[target64]
        code = C.MOV_R64_RM64 if width == 64 else C.MOV_R32_RM32
        slots = {R.RAX: 16, R.RCX: 8, R.RDX: 0}
        if source64 in slots:
            emit(I.create_reg_mem(code, target, M(R.RSP, displ=slots[source64], displ_size=1)))
        elif source64 == R.RSP:
            emit(I.create_reg_mem(C.LEA_R64_M if width == 64 else C.LEA_R32_M,
                                  target, M(R.RSP, displ=frame_size + external_stack_adjust, displ_size=1)))
        else:
            emit(I.create_reg_reg(code, target, source64 if width == 64 else LOW32[source64]))

    # Read memory BEFORE clobbering any saved scratch-register address input.
    if ins.op1_kind == ix.OpKind.MEMORY:
        target = R.RAX if bits == 64 else R.EAX
        mov = C.MOV_R64_RM64 if bits == 64 else C.MOV_R32_RM32
        if ins.is_ip_rel_memory_operand:
            emit(I.create_reg_u64(C.MOV_R64_IMM64, R.RAX, ins.ip_rel_memory_address))
            mem = M(R.RAX, seg=ins.segment_prefix)
        else:
            base, index = ins.memory_base, ins.memory_index
            disp = _signed64(ins.memory_displacement)
            if base in (R.RSP, R.ESP):
                if index == R.NONE and disp < 0 and disp + bits // 8 > -(frame_size + external_stack_adjust):
                    raise LoweringError("Memory source overlaps the borrowed stack frame/return slot")
                disp = _signed64(disp + frame_size + external_stack_adjust)
            if index in (R.RSP, R.ESP):
                raise LoweringError("RSP cannot be an x86 SIB index")
            address32 = base in GPRS32 or index in GPRS32
            displ_size = (1 if -128 <= disp <= 127 else (4 if address32 else 8))
            if base == R.NONE and index == R.NONE:
                displ_size = ins.memory_displ_size
            mem = M(base, index, ins.memory_index_scale, disp,
                    displ_size, seg=ins.segment_prefix)
        emit(I.create_reg_mem(mov, target, mem))
    else:
        original_reg(R.RAX, ins.op1_register, bits)

    original_reg(R.RCX, ins.op2_register, bits)
    accum = R.RAX if bits == 64 else R.EAX

    if operation != "BZHI":
        emit(I.create_reg_reg(getattr(C, f"{operation}_RM{bits}_CL"), accum, R.CL))
    else:
        # BZHI consumes the low EIGHT count bits, unlike SHLX's low 5/6.
        emit(I.create_reg_i32(C.AND_RM32_IMM32, R.ECX, 255))
        emit(I.create_reg_i32(C.CMP_RM32_IMM8, R.ECX, bits))
        b.branch(C.JAE_REL8_64, "whole")
        scratch = R.RDX if bits == 64 else R.EDX
        emit(I.create_reg_i32(C.MOV_RM64_IMM32 if bits == 64 else C.MOV_R32_IMM32,
                              scratch, -1))
        emit(I.create_reg_reg(C.SHL_RM64_CL if bits == 64 else C.SHL_RM32_CL, scratch, R.CL))
        emit(I.create_reg(C.NOT_RM64 if bits == 64 else C.NOT_RM32, scratch))
        emit(I.create_reg_reg(C.AND_R64_RM64 if bits == 64 else C.AND_R32_RM32,
                              accum, scratch))
        b.branch(C.JMP_REL8_64, "flags")
        b.label("whole")
        emit(I.create_reg_reg(C.TEST_RM64_R64 if bits == 64 else C.TEST_RM32_R32,
                              accum, accum))
        emit(I.create(C.STC))
        b.label("flags")
        # TEST/AND set OF=0 and correct ZF/SF. CF is 1 only for index>=width.
        # AF/PF are undefined for BZHI. Following MOV/POP preserve these flags.

    emit(I.create_mem_reg(C.MOV_RM64_R64, M(R.RSP, displ=result_offset, displ_size=1), R.RAX))
    for reg in (R.RDX, R.RCX, R.RAX):
        emit(I.create_reg(C.POP_R64, reg))
    if save_flags:
        emit(I.create(C.POPFQ))
    emit(I.create_reg(C.POP_R64, dst64))
    return b.encode(ip)


def lower(ins: ix.Instruction, ip: int = 0, external_stack_adjust: int = 0) -> bytes:
    """Lower a supported instruction; optionally account for a pushed return IP.

    external_stack_adjust=8 means the caller pushed a return address BEFORE
    the body. Original RSP operands are entry RSP+8. The body leaves entry
    RSP unchanged so the caller's appended RET can consume that address.
    RSP/ESP destinations are rejected in this mode. Default0 is unchanged.
    """
    return _lower(ins, ip, use_fast=True, external_stack_adjust=external_stack_adjust)


def lower_conservative(ins: ix.Instruction, ip: int = 0, external_stack_adjust: int = 0) -> bytes:
    """Unoptimized implementation retained for regression/benchmark comparison."""
    return _lower(ins, ip, use_fast=False, external_stack_adjust=external_stack_adjust)


def lower_simd_candidate(ins: ix.Instruction, ip: int = 0, external_stack_adjust: int = 0) -> bytes:
    """Experimental SHLX/SHRX path with no flag-writing instructions.

    Legacy SSE2 preserves upper YMM halves. XMM0/1 low halves are spilled;
    logical shifts mask count in XMM1 with immediate shifts, without flags.
    Other forms use the validated ordinary lowerer.
    """
    if ins.code not in SUPPORTED:
        return lower(ins, ip, external_stack_adjust)
    if external_stack_adjust not in (0, 8):
        raise LoweringError("external_stack_adjust must be 0 or 8")
    operation, bits = SUPPORTED[ins.code]
    if (operation not in ("SHL", "SHR") or ins.op1_kind != ix.OpKind.REGISTER
            or any(FULL.get(ins.op_register(n)) == R.RSP for n in range(3))):
        return lower(ins, ip, external_stack_adjust)
    b = _Builder()
    emit = b.emit
    emit(I.create_reg_mem(C.LEA_R64_M, R.RSP, M(R.RSP, displ=-32, displ_size=1)))
    emit(I.create_mem_reg(C.MOVDQU_XMMM128_XMM, M(R.RSP), R.XMM0))
    emit(I.create_mem_reg(C.MOVDQU_XMMM128_XMM, M(R.RSP, displ=16, displ_size=1), R.XMM1))
    to_xmm = C.MOVQ_XMM_RM64 if bits == 64 else C.MOVD_XMM_RM32
    from_xmm = C.MOVQ_RM64_XMM if bits == 64 else C.MOVD_RM32_XMM
    emit(I.create_reg_reg(to_xmm, R.XMM0, ins.op1_register))
    emit(I.create_reg_reg(to_xmm, R.XMM1, ins.op2_register))
    count_shift = 58 if bits == 64 else 59
    emit(I.create_reg_i32(C.PSLLQ_XMM_IMM8, R.XMM1, count_shift))
    emit(I.create_reg_i32(C.PSRLQ_XMM_IMM8, R.XMM1, count_shift))
    shift = getattr(C, f"PS{'LL' if operation == 'SHL' else 'RL'}{'Q' if bits == 64 else 'D'}_XMM_XMMM128")
    emit(I.create_reg_reg(shift, R.XMM0, R.XMM1))
    emit(I.create_reg_reg(from_xmm, ins.op0_register, R.XMM0))
    emit(I.create_reg_mem(C.MOVDQU_XMM_XMMM128, R.XMM0, M(R.RSP)))
    emit(I.create_reg_mem(C.MOVDQU_XMM_XMMM128, R.XMM1, M(R.RSP, displ=16, displ_size=1)))
    emit(I.create_reg_mem(C.LEA_R64_M, R.RSP, M(R.RSP, displ=32, displ_size=1)))
    return b.encode(ip)


def lower_info(ins: ix.Instruction, ip: int = 0, external_stack_adjust: int = 0) -> dict:
    """Return body and descriptive stack metadata, NOT Windows unwind info.

    The stack depth changes within the body. Metadata describes the strategy
    and peak use; callers must not use peak depth as a fixed unwind rule.
    """
    body = lower(ins, ip, external_stack_adjust)
    operation, bits = SUPPORTED[ins.code]
    fast = (operation != "BZHI" and ins.op1_kind == ix.OpKind.REGISTER
            and FULL[ins.op0_register] != R.RSP)
    if fast:
        scratch = (R.RAX if FULL[ins.op0_register] == R.RCX else
                   R.RCX if FULL[ins.op2_register] != R.RCX else None)
        strategy = "register_shift_direct"
        peak = 16 if scratch is not None else 8
        saved = ["RFLAGS"] + (["RAX" if scratch == R.RAX else "RCX"] if scratch is not None else [])
    else:
        strategy = "conservative_stack_frame"
        peak = 32 if operation == "BZHI" else 40
        saved = (["destination/result slot"] + ([] if operation == "BZHI" else ["RFLAGS"])
                 + ["RAX", "RCX", "RDX"])
    return {"body": body, "strategy": strategy, "peak_stack_bytes": peak,
            "external_stack_adjust": external_stack_adjust,
            "peak_stack_bytes_from_original": peak + external_stack_adjust,
            "saved_in_push_order": saved, "has_unwind_metadata": False,
            "position_independent_body": True}


if __name__ == "__main__":
    for raw in ("c4e2f9f7c1", "c4e2f8f5c1"):
        original = ix.Decoder(64, bytes.fromhex(raw), ip=0x140000000).decode()
        print(original)
        for item in ix.Decoder(64, lower(original, 0x180000000), ip=0x180000000):
            print(" ", item)
