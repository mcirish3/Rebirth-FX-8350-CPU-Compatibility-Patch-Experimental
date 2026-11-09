"""Build the list of AVX2/BMI2 instructions to translate, for any game build.

v6 shipped a frozen list of 23,171 addresses for Steam build 23447986. That list
is exactly:
  * every "control_flow" hit from discover_code_sites.py (reached from the entry
    point, exports, or unwind-table functions through direct branches), plus
  * every "address_reference" hit (code reached only through a pointer or a
    RIP-relative LEA) that passed a review.

This module automates that review so the same list can be rebuilt after a game
update. A pointer-reached root is accepted only if:
  1. the reference really points at it (the LEA target or relocated pointer
     equals the root address),
  2. walking its code from the root (following branches and tail jumps, up to
     5000 instructions) never hits an invalid decode, and every hit is on it,
  3. no hit sits in something shaped like a jump table: a run of 32-bit values
     that are all near-by code addresses, directly after RET/NOP/INT3.

"linear_candidate" hits (found only by sweeping bytes) are never patched; they
can be data. Anything missed is logged by fxcompat.dll at runtime and picked up
the next time the patcher runs (see fxreborn.py, "learned sites").
"""
from __future__ import annotations

import collections
import struct

import iced_x86 as ix

STOP = (ix.FlowControl.RETURN, ix.FlowControl.INDIRECT_BRANCH,
        ix.FlowControl.INTERRUPT, ix.FlowControl.EXCEPTION)


def _looks_like_jump_table(pe, rva: int) -> bool:
    before = pe.get_data(rva - 1, 1)
    if before not in (b"\xc3", b"\x90", b"\xcc"):
        return False
    words = struct.unpack("<4I", pe.get_data(rva, 16))
    return all(abs(w - rva) < 0x10000 for w in words)


def _review_root(pe, base: int, root: int, hits: list[dict], root_source: int | None) -> tuple[bool, str]:
    kind = hits[0]["provenance"]["root_kind"]
    sources = {int(h["provenance"]["via_rva"], 16) for h in hits if h["provenance"]["via_rva"]}
    if root_source is not None:
        sources.add(root_source)
    if not sources:
        return False, "no reference"
    # via_rva is the reference for the root block, but a branch source for blocks
    # reached later in the walk, so at least one (not every) source must match.
    def points_at_root(source: int) -> bool:
        if kind == "base_relocation":
            return int.from_bytes(pe.get_data(source, 8), "little") == base + root
        ins = ix.Decoder(64, pe.get_data(source, 15), ip=base + source).decode()
        return (ins.mnemonic == ix.Mnemonic.LEA and ins.is_ip_rel_memory_operand
                and ins.ip_rel_memory_address == base + root)
    if not any(points_at_root(s) for s in sources):
        return False, "reference does not point at root"
    visited, pending = set(), [root]
    while pending and len(visited) < 5000:
        rva = pending.pop()
        while rva not in visited:
            ins = ix.Decoder(64, pe.get_data(rva, 15), ip=base + rva).decode()
            if ins.is_invalid:
                return False, f"invalid decode at {rva:#x}"
            visited.add(rva)
            flow = ins.flow_control
            if flow in STOP:
                break
            if flow in (ix.FlowControl.CONDITIONAL_BRANCH, ix.FlowControl.UNCONDITIONAL_BRANCH):
                if ins.op0_kind in (ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32, ix.OpKind.NEAR_BRANCH64):
                    pending.append(ins.near_branch_target - base)
                if flow == ix.FlowControl.UNCONDITIONAL_BRANCH:
                    break
            rva += ins.len
    for h in hits:
        r = int(h["rva"], 16)
        if r not in visited:
            return False, f"hit {r:#x} not on the walk from root"
        if pe.get_data(r, len(bytes.fromhex(h["bytes"]))).hex() != h["bytes"]:
            return False, f"bytes changed at {r:#x}"
        if _looks_like_jump_table(pe, r):
            return False, f"hit {r:#x} looks like a jump table"
    return True, "ok"


def select(pe, discovery: dict) -> tuple[list[int], dict]:
    """Return (sorted site RVAs, report) from discover_code_sites.Discovery.result()."""
    base = pe.OPTIONAL_HEADER.ImageBase
    sites = {int(h["rva"], 16) for h in discovery["hits"]
             if h["provenance"]["confidence"] == "control_flow"}
    groups = collections.defaultdict(list)
    for h in discovery["hits"]:
        if h["provenance"]["confidence"] == "address_reference":
            groups[int(h["provenance"]["root_rva"], 16)].append(h)
    roots = {int(k, 16): int(v, 16) for k, v in discovery.get("address_root_sources", {}).items()}
    accepted, rejected = 0, []
    for root, hits in groups.items():
        ok, why = _review_root(pe, base, root, hits, roots.get(root))
        if ok:
            sites.update(int(h["rva"], 16) for h in hits)
            accepted += len(hits)
        else:
            rejected.append({"root": hex(root), "hits": len(hits), "reason": why})
    report = {"control_flow": sum(h["provenance"]["confidence"] == "control_flow" for h in discovery["hits"]),
              "address_reference_accepted": accepted, "address_reference_rejected": rejected,
              "linear_candidates_ignored": sum(h["provenance"]["confidence"] == "linear_candidate"
                                               for h in discovery["hits"])}
    return sorted(sites), report


def discover(path) -> dict:
    import discover_code_sites as dcs
    d = dcs.Discovery(path)
    d.strong_roots(); d.walk()
    d.reloc_roots(); d.address_walk()
    # The linear sweep only adds low-confidence hits, which select() ignores.
    result = d.result()
    result["address_root_sources"] = {hex(r): hex(src) for r, (_, src) in d.address_roots.items()}
    return result
