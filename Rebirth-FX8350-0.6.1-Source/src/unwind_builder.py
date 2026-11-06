"""Conservative Windows x64 UNWIND_INFO builder for generated helper bodies.

Pass bytes beginning AFTER the synthetic return-address push. A final RET
may be included; otherwise one is assumed appended by the caller. ip is that
body's address. build_unwind returns bytes or None. inspect_unwind provides
the refusal reason. No exception handler or instruction-fault translation is
installed: this describes stack/register recovery for supported shapes only.

Source: Microsoft's x64 exception handling and prolog/epilog documentation.
POPFQ is not a register-pop epilogue opcode. build_unwind refuses bodies whose
intermediate stack depths make ordinary metadata misleading. For those bodies,
build_unwind_intervals supplies separately described constant-state ranges.
"""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).parent / "pylibs"))
import iced_x86 as ix

C, R, M, O = ix.Code, ix.Register, ix.Mnemonic, ix.OpKind
GPRS = [R.RAX, R.RCX, R.RDX, R.RBX, R.RSP, R.RBP, R.RSI, R.RDI,
        R.R8, R.R9, R.R10, R.R11, R.R12, R.R13, R.R14, R.R15]
NONVOL = {R.RBX, R.RBP, R.RSI, R.RDI, R.R12, R.R13, R.R14, R.R15}
XMM_STORES = {C.MOVDQU_XMMM128_XMM, C.MOVDQA_XMMM128_XMM,
              C.VEX_VMOVDQU_XMMM128_XMM, C.VEX_VMOVDQA_XMMM128_XMM,
              C.VEX_VMOVDQU_YMMM256_YMM, C.VEX_VMOVDQA_YMMM256_YMM}
GPR_STORES = {C.MOV_RM64_R64}


def signed(n):
    n &= (1 << 64) - 1
    return n - (1 << 64) if n >> 63 else n


def stack_delta(ins):
    """Positive means bytes allocated, negative means released; None unknown."""
    if ins.mnemonic in (M.PUSH, M.PUSHFQ):
        return 8
    if ins.mnemonic in (M.POP, M.POPFQ):
        if ins.op0_kind == O.REGISTER and ins.op0_register == R.RSP:
            return None
        return -8
    if ins.mnemonic == M.LEA and ins.op0_register == R.RSP:
        if ins.memory_base != R.RSP or ins.memory_index != R.NONE:
            return None
        return -signed(ins.memory_displacement)
    if ins.op0_kind == O.REGISTER and ins.op0_register == R.RSP and ins.mnemonic in (M.ADD, M.SUB):
        try:
            value = signed(ins.immediate(1))
        except ValueError:
            return None
        return value if ins.mnemonic == M.SUB else -value
    if ins.op0_kind == O.REGISTER and ins.op0_register == R.RSP and ins.mnemonic not in (M.CMP, M.TEST):
        return None
    return 0


def _allocation(offset, size):
    if size <= 0 or size % 8:
        raise ValueError("Stack allocation is not a positive multiple of eight")
    if size <= 128:
        return bytes([offset, 2 | (((size - 8) // 8) << 4)])
    if size <= 0x7FFF8:
        return bytes([offset, 1]) + struct.pack("<H", size // 8)
    if size <= 0xFFFFFFFF:
        return bytes([offset, 0x11]) + struct.pack("<I", size)
    raise ValueError("Stack allocation is too large")


def _stack_mem(ins):
    return ins.memory_base == R.RSP and ins.memory_index == R.NONE and ins.segment_prefix == R.NONE


def _nonvolatile_writes(insns):
    """Identify registers whose low ABI-preserved value can actually change.

    Stack copies of untouched source vectors are not scratch-register saves.
    iced reports VEX writes as ZMM writes because the upper bits are cleared.
    """
    found = set()
    factory = ix.InstructionInfoFactory()
    for ins in insns:
        for used in factory.info(ins).used_registers():
            if used.access not in (ix.OpAccess.WRITE, ix.OpAccess.READ_WRITE,
                                   ix.OpAccess.COND_WRITE, ix.OpAccess.READ_COND_WRITE):
                continue
            raw = used.register
            if R.XMM0 <= raw <= R.XMM31:
                reg = raw
            elif R.YMM0 <= raw <= R.YMM31:
                reg = R.XMM0 + raw - R.YMM0
            elif R.ZMM0 <= raw <= R.ZMM31:
                reg = R.XMM0 + raw - R.ZMM0
            else:
                reg = ix.RegisterExt.full_register(raw)
            if reg in NONVOL or R.XMM6 <= reg <= R.XMM15:
                found.add(reg)
    return found


def _candidate(body, ip):
    """Internal: may retain candidate bytes with an error for negative tests."""
    insns = list(ix.Decoder(64, body, ip=ip))
    if not insns or any(i.is_invalid for i in insns):
        return {"unwind": None, "reason": "Empty/invalid instruction stream"}
    if insns[-1].code != C.RETNQ:
        body += b"\xc3"
        insns = list(ix.Decoder(64, body, ip=ip))
    operations = []
    saves = []
    depth = 0
    prologue_end = 0
    p = 0
    seen_allocation = False
    reason = None
    for p, ins in enumerate(insns):
        end = ins.next_ip - ip
        if end > 255:
            reason = "Prologue exceeds the one-byte UNWIND_INFO limit"
            break
        if ins.mnemonic in (M.PUSH, M.PUSHFQ):
            if ins.mnemonic == M.PUSH and ins.op0_kind == O.REGISTER and ins.op0_register in NONVOL:
                if seen_allocation:
                    reason = "Nonvolatile push follows stack allocation; unsupported prologue order"
                    break
                operations.append(bytes([end, GPRS.index(ins.op0_register) << 4]))
                depth += 8
                saves.append({"kind": "gpr", "register": ins.op0_register, "entry_offset": -depth, "size": 8})
            elif ins.mnemonic == M.PUSHFQ or (ins.op0_kind == O.REGISTER and ins.op0_register in GPRS and ins.op0_register != R.RSP):
                operations.append(_allocation(end, 8))
                depth += 8
                seen_allocation = True
            else:
                reason = "Unsupported push in prologue"
                break
            prologue_end = end
            continue
        delta = stack_delta(ins)
        if delta is not None and delta > 0 and ins.mnemonic in (M.LEA, M.SUB):
            operations.append(_allocation(end, delta))
            depth += delta
            seen_allocation = True
            prologue_end = end
            continue
        if ins.code in XMM_STORES and _stack_mem(ins):
            reg = ins.op1_register
            n = reg - (R.YMM0 if R.YMM0 <= reg <= R.YMM15 else R.XMM0)
            offset = signed(ins.memory_displacement)
            if 6 <= n <= 15:
                if offset < 0 or offset % 16 or offset + 16 > depth:
                    reason = "Nonvolatile XMM save is not inside aligned local storage"
                    break
                if offset < 0x100000:
                    op = bytes([end, 8 | (n << 4)]) + struct.pack("<H", offset // 16)
                else:
                    op = bytes([end, 9 | (n << 4)]) + struct.pack("<I", offset)
                operations.append(op)
                saves.append({"kind": "xmm", "register": R.XMM0 + n, "entry_offset": offset - depth, "size": 16})
            prologue_end = end
            continue
        if ins.code in GPR_STORES and _stack_mem(ins):
            reg = ins.op1_register
            offset = signed(ins.memory_displacement)
            if reg in NONVOL:
                if offset < 0 or offset % 8 or offset + 8 > depth:
                    reason = "Nonvolatile GPR save lies outside aligned local storage"
                    break
                operations.append(bytes([end, 4 | (GPRS.index(reg) << 4)]) + struct.pack("<H", offset // 8))
                saves.append({"kind": "gpr", "register": reg, "entry_offset": offset - depth, "size": 8})
            prologue_end = end
            continue
        break
    codes = b"".join(reversed(operations))
    slots = len(codes) // 2
    if slots > 255:
        reason = reason or "More than 255 unwind-code slots"
    unwind = bytes([1, prologue_end, slots & 255, 0]) + codes
    unwind += bytes((-len(unwind)) % 4)
    result = {"unwind": unwind, "reason": reason, "prologue_size": prologue_end,
              "frame_bytes": depth, "saves": saves, "function_bytes": len(body),
              "code": body, "ip": ip}
    if reason:
        return result

    remaining = [i for i in insns if i.ip - ip >= prologue_end]
    # Deallocations must be a contiguous terminal suffix. POPFQ can appear only
    # first: before any deallocation full-prologue fallback is still correct;
    # subsequent ordinary POPs/RET are recognized by Windows' epilogue scanner.
    suffix = []
    for ins in reversed(remaining[:-1]):
        d = stack_delta(ins)
        if d is not None and d < 0 and ins.mnemonic in (M.POP, M.POPFQ, M.LEA, M.ADD):
            suffix.append(ins)
        else:
            break
    suffix.reverse()
    suffix_start = suffix[0].ip if suffix else insns[-1].ip
    for ins in remaining:
        if ins.code == C.RETNQ:
            continue
        d = stack_delta(ins)
        if d is None:
            result["reason"] = "Dynamic/unknown RSP write"
            return result
        if d and ins.ip < suffix_start:
            result["reason"] = f"Stack depth changes inside body at +0x{ins.ip-ip:x}: {ins}"
            return result
        # Saved nonvolatile slots must remain intact. In particular BMI2's
        # pushed destination slot can become the result, not a valid save.
        info = ix.InstructionInfoFactory().info(ins)
        for memory in info.used_memory():
            if memory.access not in (ix.OpAccess.WRITE, ix.OpAccess.READ_WRITE, ix.OpAccess.COND_WRITE, ix.OpAccess.READ_COND_WRITE):
                continue
            if memory.base != R.RSP or memory.index != R.NONE:
                continue
            offset = signed(memory.displacement) - depth
            size = ix.MemorySizeExt.info(memory.memory_size).size
            for save in saves:
                if offset < save["entry_offset"] + save["size"] and offset + size > save["entry_offset"]:
                    result["reason"] = "Saved nonvolatile slot overwritten after prologue"
                    return result
    if sum(-stack_delta(i) for i in suffix) != depth:
        result["reason"] = "Terminal epilogue does not release exactly the fixed frame"
        return result
    for n, ins in enumerate(suffix):
        if ins.mnemonic == M.POPFQ and n:
            result["reason"] = "POPFQ after earlier stack release is not a Windows x64 epilogue; intermediate PCs unwind incorrectly"
            return result
        if ins.mnemonic in (M.LEA, M.ADD) and n:
            result["reason"] = "Stack adjustment follows an earlier epilogue pop"
            return result
    result["epilogue_offset"] = suffix_start - ip
    return result


def inspect_unwind(body: bytes, ip: int = 0) -> dict:
    """Explain eligibility and return bytes only for supported recovery shapes."""
    try:
        result = _candidate(body, ip)
    except (ValueError, OverflowError, IndexError) as ex:
        return {"unwind": None, "reason": str(ex)}
    result.pop("code", None)
    if result.get("reason"):
        result["unwind"] = None
    return result


def build_unwind(body: bytes, ip: int = 0) -> bytes | None:
    """Return an aligned version-1 UNWIND_INFO blob, or None if unsupported."""
    return inspect_unwind(body, ip).get("unwind")


def _state_unwind(depth, saves):
    """Constant-PC-state record: restore saved values, then remove locals."""
    ops = []
    for kind, reg, entry_offset, size in saves:
        offset = entry_offset + depth
        if offset < 0 or offset + size > depth:
            raise ValueError("Active nonvolatile save is outside the current frame")
        if kind == "gpr":
            if offset % 8 or offset // 8 > 0xFFFF:
                raise ValueError("Unrepresentable GPR save offset")
            ops.append(bytes([0, 4 | (GPRS.index(reg) << 4)]) + struct.pack("<H", offset // 8))
        else:
            if offset % 16 or offset // 16 > 0xFFFF:
                raise ValueError("Unrepresentable XMM save offset at this stack depth")
            ops.append(bytes([0, 8 | ((reg - R.XMM0) << 4)]) + struct.pack("<H", offset // 16))
    if depth:
        ops.append(_allocation(0, depth))
    codes = b"".join(ops)
    result = bytes([1, 0, len(codes) // 2, 0]) + codes
    return result + bytes((-len(result)) % 4)


def inspect_unwind_intervals(body: bytes, ip: int = 0) -> dict:
    """Build disjoint RUNTIME_FUNCTION ranges with constant stack state.

    Each returned begin/end is relative to body start (after synthetic PUSH).
    Each range's UNWIND_INFO has prologue_size=0 and describes the state at
    instruction boundaries within that range. Branches must stay inside the
    corresponding range, avoiding accidental tail-call recognition by Windows.
    The caller must emit ALL ranges, sorted, and each associated xdata blob.
    """
    try:
        insns = list(ix.Decoder(64, body, ip=ip))
        if not insns or any(i.is_invalid for i in insns):
            raise ValueError("Empty/invalid instruction stream")
        if insns[-1].code != C.RETNQ:
            body += b"\xc3"
            insns = list(ix.Decoder(64, body, ip=ip))
        written_nonvolatile = _nonvolatile_writes(insns)
        depth = 0
        saves = {}
        changed_vectors = set()
        states = []
        after_states = []
        info_factory = ix.InstructionInfoFactory()
        for n, ins in enumerate(insns):
            # Map values are immutable tuples: kind, register, entry offset,size.
            # A copied vector remains recoverable directly from its context
            # until its first write. Input/output aliases must not prematurely
            # require a save at the +8 stack depth of PUSHFQ/POP sequences.
            signature = (depth, tuple(sorted(s for r,s in saves.items()
                if s[0] != 'xmm' or r in changed_vectors)))
            states.append(signature)
            if ins.code == C.RETNQ:
                if n != len(insns) - 1 or depth:
                    raise ValueError("RET before final instruction or with unreleased stack")
                after_states.append(signature)
                continue
            if ins.flow_control in (ix.FlowControl.CALL, ix.FlowControl.INDIRECT_CALL,
                                     ix.FlowControl.INDIRECT_BRANCH, ix.FlowControl.INTERRUPT):
                raise ValueError("Calls/indirect transfers are outside this helper model")
            d = stack_delta(ins)
            if d is None:
                raise ValueError(f"Unknown RSP write at +0x{ins.ip-ip:x}")
            changed_vectors.update(r for r in _nonvolatile_writes([ins])
                                   if R.XMM6 <= r <= R.XMM15)
            if ins.mnemonic in (M.PUSH, M.PUSHFQ):
                depth += d
                if ins.mnemonic == M.PUSH and ins.op0_kind == O.REGISTER and ins.op0_register in NONVOL:
                    reg = ins.op0_register
                    if reg not in saves:
                        saves[reg] = ("gpr", reg, -depth, 8)
            elif ins.mnemonic in (M.POP, M.POPFQ):
                if ins.op0_kind == O.REGISTER:
                    saves.pop(ins.op0_register, None)
                depth += d
            elif d:
                depth += d
            else:
                # Invalidate an overwritten save before recognizing a new save.
                for mem in info_factory.info(ins).used_memory():
                    if mem.access not in (ix.OpAccess.WRITE, ix.OpAccess.READ_WRITE,
                                          ix.OpAccess.COND_WRITE, ix.OpAccess.READ_COND_WRITE):
                        continue
                    if mem.base != R.RSP or mem.index != R.NONE:
                        continue
                    lo = signed(mem.displacement) - depth
                    size = ix.MemorySizeExt.info(mem.memory_size).size
                    for reg, (_, _, offset, length) in list(saves.items()):
                        if lo < offset + length and lo + size > offset:
                            del saves[reg]
                if ins.code in XMM_STORES and _stack_mem(ins):
                    raw = ins.op1_register
                    num = raw - (R.YMM0 if R.YMM0 <= raw <= R.YMM15 else R.XMM0)
                    if 6 <= num <= 15 and R.XMM0 + num in written_nonvolatile and R.XMM0 + num not in saves:
                        reg = R.XMM0 + num
                        saves[reg] = ("xmm", reg, signed(ins.memory_displacement) - depth, 16)
                elif ins.code in GPR_STORES and _stack_mem(ins) and ins.op1_register in NONVOL:
                    reg = ins.op1_register
                    if reg not in saves:
                        saves[reg] = ("gpr", reg, signed(ins.memory_displacement) - depth, 8)
                # Once a saved register is restored, metadata can use its context
                # value. This avoids invalid negative offsets after deallocation.
                if ins.op0_kind == O.REGISTER and ins.op1_kind == O.MEMORY and _stack_mem(ins):
                    raw = ins.op0_register
                    reg = (R.XMM0 + raw - R.YMM0) if R.YMM0 <= raw <= R.YMM15 else raw
                    if reg in saves and saves[reg][2] == signed(ins.memory_displacement) - depth:
                        if ins.mnemonic in (M.MOV, M.MOVDQU, M.MOVDQA, M.VMOVDQU, M.VMOVDQA):
                            del saves[reg]
                            changed_vectors.discard(reg)
            if depth < 0 or depth > 4096:
                raise ValueError("Unexpected helper stack depth")
            # Freed local storage no longer describes an active scratch save.
            saves = {r:s for r,s in saves.items() if 0 <= s[2] + depth and s[2] + depth + s[3] <= depth}
            after_states.append((depth, tuple(sorted(s for r,s in saves.items()
                if s[0] != 'xmm' or r in changed_vectors))))
        indices = {ins.ip:n for n,ins in enumerate(insns)}
        ranges = []
        membership = {}
        for n, ins in enumerate(insns):
            signature = states[n]
            if not ranges or ranges[-1]["state"] != signature:
                ranges.append({"begin_offset": ins.ip-ip, "end_offset": ins.next_ip-ip,
                               "state": signature, "unwind": _state_unwind(*signature),
                               "stack_depth": signature[0]})
            else:
                ranges[-1]["end_offset"] = ins.next_ip-ip
            membership[ins.ip] = len(ranges)-1
        for n, ins in enumerate(insns):
            if ins.flow_control in (ix.FlowControl.UNCONDITIONAL_BRANCH, ix.FlowControl.CONDITIONAL_BRANCH):
                target = ins.near_branch_target
                if target not in indices or states[indices[target]] != after_states[n]:
                    raise ValueError("Branch joins inconsistent stack/save states")
                if membership[target] != membership[ins.ip]:
                    raise ValueError("Branch crosses a metadata interval; could be misidentified as a tail call")
        for entry in ranges:
            entry.pop("state")
        return {"intervals": ranges, "reason": None, "function_bytes": len(body),
                "instruction_count": len(insns), "max_stack_depth": max(s[0] for s in states)}
    except (ValueError, OverflowError, IndexError) as ex:
        return {"intervals": None, "reason": str(ex)}


def build_unwind_intervals(body: bytes, ip: int = 0) -> list | None:
    """Return constant-state intervals, or None; see inspect_unwind_intervals."""
    return inspect_unwind_intervals(body, ip).get("intervals")
