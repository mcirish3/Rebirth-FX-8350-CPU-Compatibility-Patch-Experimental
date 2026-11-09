"""Read-only PE code discovery with evidence classes, bounded instruction storage.

No code is executed and no game file is modified.  Control-flow roots are walked
before address references and whole-section linear-sweep candidates.  The latter
remain explicitly lower-confidence evidence, never silently promoted to code.
"""
import argparse
import bisect
import collections
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

WORK = Path(__file__).parent
sys.path.insert(0, str(WORK / 'pylibs'))
import pefile
import iced_x86 as ix

DEFAULT = None  # pass --path
FEATURES = {v: k for k, v in vars(ix.CpuidFeature).items() if isinstance(v, int)}
CLASSES = {1: 'control_flow', 2: 'address_reference', 3: 'linear_candidate'}
DIRECT = (ix.FlowControl.CALL, ix.FlowControl.UNCONDITIONAL_BRANCH,
          ix.FlowControl.CONDITIONAL_BRANCH)
NEAR = (ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32, ix.OpKind.NEAR_BRANCH64)
STOP = (ix.FlowControl.RETURN, ix.FlowControl.INDIRECT_BRANCH,
        ix.FlowControl.INTERRUPT, ix.FlowControl.EXCEPTION)


class Discovery:
    def __init__(self, path):
        self.path = path
        self.raw = path.read_bytes()
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = []
        for sec in self.pe.sections:
            if not sec.Characteristics & 0x20000000:
                continue
            size = min(sec.SizeOfRawData, sec.Misc_VirtualSize)
            data = self.raw[sec.PointerToRawData:sec.PointerToRawData + size]
            self.secs.append((sec.VirtualAddress, sec.VirtualAddress + size, data,
                              bytearray(size), ix.Decoder(64, data)))
        self.secs.sort(key=lambda s: s[0])
        self.sec_starts = [s[0] for s in self.secs]
        dd = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        pdata = self.pe.get_data(dd.VirtualAddress, dd.Size)
        self.ranges = sorted((a, b) for a, b, _ in struct.iter_unpack('<III', pdata)
                             if a < b and self.section(a) is not None)
        self.function_starts = [a for a, _ in self.ranges]
        self.merged = []
        for a, b in self.ranges:
            if self.merged and a <= self.merged[-1][1]:
                self.merged[-1][1] = max(b, self.merged[-1][1])
            else:
                self.merged.append([a, b])
        self.range_starts = [a for a, _ in self.merged]
        self.pending = {}
        self.queue = collections.deque()
        self.hits = {}
        self.counts = collections.Counter()
        self.conflicts = []
        self.conflict_count = 0
        self.indirect = []
        self.invalid_roots = collections.Counter()
        self.address_roots = {}
        self.linear_roots = {}
        self.fmt = ix.Formatter(ix.FormatterSyntax.INTEL)
        self.started = time.monotonic()

    def section(self, rva):
        i = bisect.bisect_right(self.sec_starts, rva) - 1
        if i >= 0 and rva < self.secs[i][1]:
            return self.secs[i]
        return None

    def in_unwind(self, rva):
        i = bisect.bisect_right(self.range_starts, rva) - 1
        return i >= 0 and rva < self.merged[i][1]

    def fallthrough_limit(self, rva, section_end):
        # A .pdata region is not permitted to fall through its declared end.
        # For unlisted leaf code, stop at the next known function boundary.
        i = bisect.bisect_right(self.function_starts, rva) - 1
        if i >= 0 and rva < self.ranges[i][1]:
            return min(section_end, self.ranges[i][1])
        if i + 1 < len(self.ranges):
            return min(section_end, self.ranges[i + 1][0])
        return section_end

    def enqueue(self, rva, evidence, kind, root=None, source=None):
        sec = self.section(rva)
        if sec is None:
            return
        mark = sec[3][rva - sec[0]]
        if mark:
            if mark & 0x80:
                self.conflict_count += 1
                if len(self.conflicts) < 5000:
                    self.conflicts.append({'target': hex(rva), 'source': hex(source) if source is not None else None,
                                           'kind': kind, 'confidence': CLASSES[evidence]})
            else:
                sec[3][rva - sec[0]] |= 0x40
            return
        if rva not in self.pending:
            self.pending[rva] = (evidence, kind, rva if root is None else root, source)
            self.queue.append(rva)
            self.counts['roots_' + kind] += 1

    def walk(self):
        last = time.monotonic()
        while self.queue:
            block = self.queue.popleft()
            evidence, kind, root, source = self.pending.pop(block)
            sec = self.section(block)
            start, end, data, visited, decoder = sec
            offset = block - start
            if visited[offset]:
                continue
            decoder.position = offset
            decoder.ip = self.base + block
            limit = self.fallthrough_limit(block, end)
            while decoder.can_decode:
                offset = decoder.position
                rva = start + offset
                if rva >= limit:
                    self.counts['stops_function_boundary_' + CLASSES[evidence]] += 1
                    break
                if visited[offset]:
                    if visited[offset] & 0x80:
                        self.conflict_count += 1
                    break
                ins = decoder.decode()
                if ins.next_ip - self.base > limit:
                    self.counts['stops_crossed_function_boundary_' + CLASSES[evidence]] += 1
                    break
                if ins.is_invalid or ins.code in (ix.Code.INT3, ix.Code.HLT, ix.Code.UD2):
                    self.counts['stops_invalid_or_trap_' + CLASSES[evidence]] += 1
                    if ins.is_invalid:
                        self.invalid_roots[(root, evidence)] += 1
                    break
                if decoder.position > len(visited) or any(visited[offset:decoder.position]):
                    self.conflict_count += 1
                    if len(self.conflicts) < 5000:
                        self.conflicts.append({'target': hex(rva), 'source': hex(source) if source is not None else None,
                                               'kind': 'overlapping_decode', 'confidence': CLASSES[evidence]})
                    break
                visited[offset] = (evidence << 4) | ins.len | (0x40 if rva == block else 0)
                visited[offset + 1:decoder.position] = b'\x80' * (ins.len - 1)
                self.counts['instructions_' + CLASSES[evidence]] += 1
                self.counts['bytes_' + CLASSES[evidence]] += ins.len
                if ins.encoding != ix.EncodingKind.LEGACY:
                    fs = ins.cpuid_features()
                    if ix.CpuidFeature.AVX2 in fs or ix.CpuidFeature.BMI2 in fs:
                        self.hits[rva] = {
                            'rva': hex(rva), 'bytes': data[offset:decoder.position].hex(),
                            'features': [FEATURES.get(f, str(f)) for f in fs],
                            'asm': self.fmt.format(ins), 'within_unwind': self.in_unwind(rva),
                            'provenance': {'confidence': CLASSES[evidence], 'root_kind': kind,
                                           'root_rva': hex(root), 'block_rva': hex(block),
                                           'via_rva': hex(source) if source is not None else None}}
                flow = ins.flow_control
                if flow in DIRECT and ins.op0_kind in NEAR:
                    target = ins.near_branch_target - self.base
                    self.enqueue(target, evidence, kind, root, rva)
                    if flow == ix.FlowControl.UNCONDITIONAL_BRANCH:
                        break
                    if flow == ix.FlowControl.CONDITIONAL_BRANCH:
                        block = rva + ins.len
                if ins.mnemonic == ix.Mnemonic.LEA and ins.is_ip_rel_memory_operand:
                    target = ins.ip_rel_memory_address - self.base
                    if self.section(target) is not None and target not in self.address_roots:
                        self.address_roots[target] = ('rip_lea_' + CLASSES[evidence], rva)
                if flow == ix.FlowControl.INDIRECT_BRANCH:
                    self.indirect.append({'rva': hex(rva), 'asm': self.fmt.format(ins),
                                          'confidence': CLASSES[evidence], 'root_rva': hex(root)})
                if flow in STOP:
                    break
            if time.monotonic() - last > 15:
                print(json.dumps({'elapsed_s': round(time.monotonic() - self.started, 1),
                                  'pending': len(self.queue), 'hits': len(self.hits),
                                  'instructions': sum(v for k, v in self.counts.items() if k.startswith('instructions_'))}), flush=True)
                last = time.monotonic()

    def strong_roots(self):
        self.enqueue(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint, 1, 'entrypoint')
        self.pe.parse_data_directories(directories=[0])
        for e in getattr(getattr(self.pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
            if not e.forwarder:
                self.enqueue(e.address, 1, 'export')
        for start, _ in self.ranges:
            self.enqueue(start, 1, 'pdata')

    def reloc_roots(self):
        dd = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
        data = self.pe.get_data(dd.VirtualAddress, dd.Size)
        offset = 0
        while offset + 8 <= len(data):
            page, size = struct.unpack_from('<II', data, offset)
            if size < 8 or offset + size > len(data):
                break
            for (value,) in struct.iter_unpack('<H', data[offset + 8:offset + size]):
                if value >> 12 != 10:
                    continue
                source = page + (value & 4095)
                pointer = self.pe.get_data(source, 8)
                if len(pointer) != 8:
                    continue
                target = struct.unpack('<Q', pointer)[0] - self.base
                if self.section(target) is not None:
                    self.address_roots.setdefault(target, ('base_relocation', source))
            offset += size

    def address_walk(self):
        processed = set()
        while True:
            batch = [(rva, meta) for rva, meta in self.address_roots.items()
                     if rva not in processed and 'linear_candidate' not in meta[0]]
            if not batch:
                break
            for rva, (kind, source) in batch:
                processed.add(rva)
                self.enqueue(rva, 2, kind, source=source)
            self.walk()

    def linear_scan(self):
        for start, _, data, visited, _ in self.secs:
            decoder = ix.Decoder(64, data, ip=self.base + start)
            for ins in decoder:
                if ins.is_invalid:
                    continue
                rva = ins.ip - self.base
                if ins.flow_control in DIRECT and ins.op0_kind in NEAR:
                    target = ins.near_branch_target - self.base
                    sec = self.section(target)
                    if sec is not None and not sec[3][target - sec[0]]:
                        self.linear_roots.setdefault(target, ('linear_direct_target', rva))
                elif ins.mnemonic == ix.Mnemonic.LEA and ins.is_ip_rel_memory_operand:
                    target = ins.ip_rel_memory_address - self.base
                    sec = self.section(target)
                    if sec is not None and not sec[3][target - sec[0]]:
                        self.linear_roots.setdefault(target, ('linear_rip_lea', rva))
        for rva, (kind, source) in self.linear_roots.items():
            self.enqueue(rva, 3, kind, source=source)
        self.walk()

    def result(self):
        hits = sorted(self.hits.values(), key=lambda h: int(h['rva'], 16))
        by_class = collections.Counter(h['provenance']['confidence'] for h in hits)
        leaf_by_class = collections.Counter(h['provenance']['confidence'] for h in hits if not h['within_unwind'])
        by_feature = collections.Counter(f for h in hits for f in h['features'] if f in ('AVX2', 'BMI2'))
        # Contiguous runs are compact; individual instruction objects are never retained.
        coverage = []
        blocks = {name: [] for name in CLASSES.values()}
        for start, _, _, visited, _ in self.secs:
            pos = 0
            while pos < len(visited):
                if not visited[pos]:
                    pos += 1
                    continue
                begin = pos
                while pos < len(visited) and visited[pos]:
                    if visited[pos] & 0x40 and not visited[pos] & 0x80:
                        blocks[CLASSES[(visited[pos] >> 4) & 3]].append(hex(start + pos))
                    pos += 1
                coverage.append([hex(start + begin), hex(start + pos)])
        return {'source': str(self.path), 'source_sha256': hashlib.sha256(self.raw).hexdigest(),
                'image_base': hex(self.base), 'elapsed_seconds': round(time.monotonic() - self.started, 2),
                'unwind_entries': len(self.ranges), 'counts': dict(self.counts),
                'hits_by_confidence': dict(by_class), 'leaf_hits_by_confidence': dict(leaf_by_class),
                'features': dict(by_feature), 'hits': hits,
                'strong_hits': [h for h in hits if h['provenance']['confidence'] == 'control_flow'],
                'known_fault_fc0977': self.hits.get(0xfc0977),
                'unresolved_indirect_branches': self.indirect,
                'decode_conflict_count': self.conflict_count, 'decode_conflict_samples': self.conflicts,
                'roots_reaching_invalid_decode': [
                    {'rva': hex(rva), 'confidence': CLASSES[evidence], 'count': count}
                    for (rva, evidence), count in self.invalid_roots.items()],
                'decoded_ranges': coverage,
                'basic_block_starts': blocks,
                'basic_block_count': sum(len(values) for values in blocks.values()),
                'limitations': [
                    'Static discovery does not prove runtime reachability or complete coverage.',
                    'Only control_flow hits derive from executable entry/export/unwind roots and direct CFG edges.',
                    'address_reference roots can refer to tables or embedded data and need independent review before patching.',
                    'linear_candidate roots may originate in embedded data; they are not an automatic patch list.',
                    'Indirect jump targets and relative jump tables are unresolved; branch list identifies these gaps.',
                    'Overlapping decode conflicts are stopped and reported; no existing instruction boundaries are overwritten.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', type=Path, default=DEFAULT)
    parser.add_argument('--output', type=Path, default=WORK / 'discovered_sites.json')
    args = parser.parse_args()
    d = Discovery(args.path)
    print('Walking entry/export/unwind CFG', flush=True)
    d.strong_roots()
    d.walk()
    print('Walking relocated/RIP-relative address references', flush=True)
    d.reloc_roots()
    d.address_walk()
    print('Collecting lower-confidence linear branch-target seeds', flush=True)
    d.linear_scan()
    result = d.result()
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in (
        'hits', 'strong_hits', 'unresolved_indirect_branches', 'decode_conflict_samples', 'decoded_ranges', 'basic_block_starts', 'roots_reaching_invalid_decode')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
