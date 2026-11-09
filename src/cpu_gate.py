"""Find the game's startup "CPU lacks AVX2" check by its pattern, not a fixed address.

The game shows "This CPU does not support a required feature (AVX2)." and quits
when CPUID reports no AVX2. Compiled, the check is:

    call  <feature query>
    bt    eax, 8              ; feature bit 8 = AVX2
    jb    short <continue>    ; supported -> skip the error
    lea   r9/r8/rdx, ...      ; error-message setup, including the AVX2 string
    ...

Patching that JB (72 xx) into JMP (EB xx) skips the error. This module locates
the JB in whatever build it is given, by following references to the message
string, so a game update that moves the code does not break the mod.
"""
from __future__ import annotations

import bisect

import iced_x86 as ix

MESSAGE_FRAGMENT = "does not support a required feature (AVX2)"


class CpuGateNotFound(RuntimeError):
    pass


def _utf16_hits(data: bytes, text: str) -> list[int]:
    needle = text.encode("utf-16-le")
    out, pos = [], data.find(needle)
    while pos >= 0:
        out.append(pos)
        pos = data.find(needle, pos + 2)
    return out


def _string_start(data: bytes, offset: int) -> int:
    """Walk back to the start of the UTF-16 string that contains offset."""
    while offset >= 2 and data[offset - 2:offset] != b"\0\0" and data[offset - 1] < 0x80:
        offset -= 2
    return offset


def find(pe, data: bytes) -> int:
    """Return the RVA of the JB to patch. Raises CpuGateNotFound if not exactly one."""
    base = pe.OPTIONAL_HEADER.ImageBase
    targets = set()
    for off in _utf16_hits(data, MESSAGE_FRAGMENT):
        try:
            targets.add(base + pe.get_rva_from_offset(_string_start(data, off)))
        except Exception:
            continue
    if not targets:
        raise CpuGateNotFound("AVX2 error message not found in the executable")

    funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                   for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []))
    starts = [f[0] for f in funcs]
    candidates = set()
    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000:
            continue
        code = sec.get_data()[:sec.Misc_VirtualSize]
        for ins in ix.Decoder(64, code, ip=base + sec.VirtualAddress):
            if not (ins.is_ip_rel_memory_operand and ins.ip_rel_memory_address in targets):
                continue
            xref = ins.ip - base
            i = bisect.bisect_right(starts, xref) - 1
            if i < 0 or xref >= funcs[i][1]:
                continue
            begin, end = funcs[i]
            prev = None
            for sub in ix.Decoder(64, pe.get_data(begin, end - begin), ip=base + begin):
                if sub.ip - base > xref:
                    break
                # bt eax,8 ; jb short forward-past-the-error-message
                if (prev is not None and prev.mnemonic == ix.Mnemonic.BT
                        and prev.op0_kind == ix.OpKind.REGISTER and prev.op1_kind == ix.OpKind.IMMEDIATE8
                        and prev.immediate8 == 8 and sub.code == ix.Code.JB_REL8_64
                        and sub.near_branch_target - base > xref):
                    candidates.add(sub.ip - base)
                prev = sub
    if len(candidates) != 1:
        raise CpuGateNotFound(f"expected one AVX2 check, found {len(candidates)}")
    rva = candidates.pop()
    if pe.get_data(rva, 1) != b"\x72":
        raise CpuGateNotFound("AVX2 check has unexpected bytes")
    return rva
