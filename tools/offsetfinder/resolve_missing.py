#!/usr/bin/env python3
"""
Resolve missing offsets by cross-referencing found offsets in a new PE binary.

After a SigScan run, some offsets may not be found by pattern matching. This tool
uses the successfully found offsets to locate the missing ones through:

1. Computing separate deltas for code (.text) and data (.data/.rdata) sections
2. For missing globals: predicting address via data delta, verifying by scanning
   for RIP-relative instructions that reference the predicted address
3. For missing functions: predicting address via code delta, verifying by checking
   for valid function prologues and string cross-references nearby

Usage:
    python resolve_missing.py <scan_results.json> <executable> [--signatures <sig.json>]
                              [--output <resolved.json>] [--tolerance <bytes>]
"""

import json
import struct
import sys
import os
import argparse
import re
import array
from collections import defaultdict
from statistics import median

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


# Common x86-64 function prologue patterns (first bytes)
FUNCTION_PROLOGUES = [
    bytes([0x48, 0x89, 0x5C, 0x24]),       # mov [rsp+xx], rbx
    bytes([0x48, 0x89, 0x6C, 0x24]),       # mov [rsp+xx], rbp
    bytes([0x48, 0x89, 0x74, 0x24]),       # mov [rsp+xx], rsi
    bytes([0x48, 0x89, 0x7C, 0x24]),       # mov [rsp+xx], rdi
    bytes([0x48, 0x89, 0x4C, 0x24]),       # mov [rsp+xx], rcx
    bytes([0x48, 0x83, 0xEC]),             # sub rsp, imm8
    bytes([0x48, 0x81, 0xEC]),             # sub rsp, imm32
    bytes([0x40, 0x53]),                   # push rbx
    bytes([0x40, 0x55]),                   # push rbp
    bytes([0x40, 0x56]),                   # push rsi
    bytes([0x40, 0x57]),                   # push rdi
    bytes([0x41, 0x54]),                   # push r12
    bytes([0x41, 0x55]),                   # push r13
    bytes([0x41, 0x56]),                   # push r14
    bytes([0x41, 0x57]),                   # push r15
    bytes([0x55]),                         # push rbp
    bytes([0x53]),                         # push rbx
    bytes([0x56]),                         # push rsi
    bytes([0x57]),                         # push rdi
    bytes([0xCC, 0x48]),                   # int3 padding then mov-based prologue
    bytes([0xCC, 0x40]),                   # int3 padding then REX prologue
]

# Names that indicate global variables (data addresses, not code)
GLOBAL_PREFIXES = ('pinst', 'inst', 'DI8__', '__g', 'EQObject_Top',
                   'Teleport_Table', 'g_')
GLOBAL_PATTERNS = re.compile(
    r'^(pinst|inst[A-Z]|DI8__|__[a-z]|__[A-Z][a-z]|EQObject_|Teleport_|g_|'
    r'__MemCheck|__Encrypt|__Screen|__Mouse|__Login|__Current|__Bind|'
    r'__Command|__Server|__Guild|__Label|__Help|__HWnd|__heq)')


def is_global_name(name):
    """Heuristic: does this offset name look like a global variable?"""
    if GLOBAL_PATTERNS.match(name):
        return True
    # If it contains __ with a class-like pattern, it's likely a function
    if '__' in name and not name.startswith('__'):
        return False
    return False


class PEFile:
    """Minimal PE parser for reading x86-64 executables."""

    def __init__(self, filepath):
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self._parse()

    def _parse(self):
        # DOS header
        if self.data[:2] != b'MZ':
            raise ValueError("Not a valid PE file")

        pe_offset = struct.unpack_from('<I', self.data, 0x3C)[0]

        # PE signature
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")

        # COFF header
        coff = pe_offset + 4
        self.num_sections = struct.unpack_from('<H', self.data, coff + 2)[0]
        optional_header_size = struct.unpack_from('<H', self.data, coff + 16)[0]

        # Optional header
        opt = coff + 20
        magic = struct.unpack_from('<H', self.data, opt)[0]
        if magic != 0x20B:  # PE32+
            raise ValueError(f"Not a PE32+ executable (magic=0x{magic:04X})")

        self.preferred_base = struct.unpack_from('<Q', self.data, opt + 24)[0]

        # Sections
        section_start = opt + optional_header_size
        self.sections = []
        for i in range(self.num_sections):
            off = section_start + i * 40
            name = self.data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack_from('<I', self.data, off + 8)[0]
            vaddr = struct.unpack_from('<I', self.data, off + 12)[0]
            raw_size = struct.unpack_from('<I', self.data, off + 16)[0]
            raw_off = struct.unpack_from('<I', self.data, off + 20)[0]
            chars = struct.unpack_from('<I', self.data, off + 36)[0]
            self.sections.append({
                'name': name,
                'virtual_address': vaddr,
                'virtual_size': vsize,
                'raw_offset': raw_off,
                'raw_size': raw_size,
                'characteristics': chars,
            })

    def get_code_sections(self):
        """Return sections with IMAGE_SCN_CNT_CODE (0x20) or IMAGE_SCN_MEM_EXECUTE (0x20000000)."""
        return [s for s in self.sections
                if s['characteristics'] & 0x20 or s['characteristics'] & 0x20000000]

    def get_data_sections(self):
        """Return sections that contain initialized data."""
        return [s for s in self.sections
                if s['characteristics'] & 0x40  # IMAGE_SCN_CNT_INITIALIZED_DATA
                and not (s['characteristics'] & 0x20)]  # exclude code

    def rva_to_offset(self, rva):
        """Convert RVA to file offset."""
        for s in self.sections:
            if s['virtual_address'] <= rva < s['virtual_address'] + s['virtual_size']:
                return s['raw_offset'] + (rva - s['virtual_address'])
        return None

    def build_code_buffer(self):
        """Build a contiguous buffer of all code sections, mapped by RVA.
        Gaps are filled with 0xCC (INT3)."""
        code_sects = self.get_code_sections()
        if not code_sects:
            return None, 0, 0

        min_rva = min(s['virtual_address'] for s in code_sects)
        max_end = max(s['virtual_address'] + s['virtual_size'] for s in code_sects)
        total_size = max_end - min_rva

        buf = bytearray(b'\xCC' * total_size)
        for s in code_sects:
            start = s['virtual_address'] - min_rva
            chunk = self.data[s['raw_offset']:s['raw_offset'] + s['raw_size']]
            buf[start:start + len(chunk)] = chunk

        return bytes(buf), min_rva, total_size

    def get_bytes_at_rva(self, rva, size):
        """Read bytes at a given RVA."""
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        return self.data[off:off + size]


def load_scan_results(filepath):
    """Load scan results JSON."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data.get('results', [])


def load_signatures(filepath):
    """Load signature JSON to get offset types."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data.get('signatures', {})


def compute_deltas(results):
    """Compute separate median deltas for code (functions) and data (globals).
    Returns (code_delta, data_delta, overall_delta)."""
    code_deltas = []
    data_deltas = []
    all_deltas = []

    for r in results:
        if r['confidence'] == 'not_found':
            continue
        delta = r['delta']
        all_deltas.append(delta)

        if is_global_name(r['name']):
            data_deltas.append(delta)
        else:
            code_deltas.append(delta)

    overall = median(all_deltas) if all_deltas else 0

    # For data, cluster by common delta since data sections may shift differently
    if data_deltas:
        data_delta = compute_clustered_delta(data_deltas)
    else:
        data_delta = int(overall)

    if code_deltas:
        code_delta = int(median(code_deltas))
    else:
        code_delta = int(overall)

    return code_delta, data_delta, int(overall)


def compute_clustered_delta(deltas):
    """Find the most common delta cluster for data section offsets.
    Data offsets often share a consistent shift that differs from code."""
    if not deltas:
        return 0

    # Round deltas to nearest 0x10 and find the most common cluster
    rounded = defaultdict(list)
    for d in deltas:
        key = (d >> 4) << 4  # round to 0x10
        rounded[key].append(d)

    # Find the largest cluster
    best_cluster = max(rounded.values(), key=len)
    return int(median(best_cluster))


def _build_disp_array(code_buf):
    """Build an array of int32 displacements read at every byte offset.
    Returns a numpy array if available, otherwise a plain array."""
    buf_len = len(code_buf)
    if buf_len < 4:
        return None, 0
    count = buf_len - 3  # last valid offset for a 4-byte read

    if HAS_NUMPY:
        # Create overlapping int32 views using stride tricks
        raw = np.frombuffer(code_buf, dtype=np.uint8)
        # Use as_strided for zero-copy overlapping int32 view
        from numpy.lib.stride_tricks import as_strided
        strided = as_strided(raw, shape=(count,), strides=(1,),
                             writeable=False)
        # Can't directly view overlapping as int32, so build from 4 byte columns
        b0 = raw[:count].astype(np.int64)
        b1 = raw[1:count+1].astype(np.int64)
        b2 = raw[2:count+2].astype(np.int64)
        b3 = raw[3:count+3].astype(np.int64)
        unsigned = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        # Convert to signed int32
        disps = np.where(unsigned >= 0x80000000, unsigned - 0x100000000, unsigned)
        return disps, count
    else:
        # Pure Python fallback using struct
        disps = array.array('i', [0] * count)
        for i in range(count):
            disps[i] = struct.unpack_from('<i', code_buf, i)[0]
        return disps, count


def find_rip_references_batch(code_buf, code_rva, target_rvas, tolerance=0x200):
    """Find RIP-relative references to multiple target RVAs in a single pass.
    Returns dict of target_rva -> [(instr_rva, resolved_rva), ...]."""

    buf_len = len(code_buf)
    code_end = code_rva + buf_len
    results = defaultdict(list)

    if buf_len < 8:
        return results

    if HAS_NUMPY:
        return _find_rip_refs_numpy(code_buf, code_rva, target_rvas, tolerance)
    else:
        return _find_rip_refs_python(code_buf, code_rva, target_rvas, tolerance)


def _find_rip_refs_numpy(code_buf, code_rva, target_rvas, tolerance):
    """Numpy-accelerated batch RIP-reference search."""
    buf_len = len(code_buf)
    code_end = code_rva + buf_len
    results = defaultdict(list)

    raw = np.frombuffer(code_buf, dtype=np.uint8)
    count = buf_len - 3

    # Build int32 displacement array from overlapping bytes
    b0 = raw[:count].astype(np.int64)
    b1 = raw[1:count+1].astype(np.int64)
    b2 = raw[2:count+2].astype(np.int64)
    b3 = raw[3:count+3].astype(np.int64)
    unsigned = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    disps = np.where(unsigned >= 0x80000000, unsigned - 0x100000000, unsigned)

    # For each instruction length, compute resolved RVAs for all positions
    for insn_len in (7, 6, 3, 4, 5, 8):
        disp_offset = insn_len - 4
        if disp_offset < 1:
            continue

        n = count - disp_offset
        if n <= 0:
            continue

        # displacement values starting at byte offset disp_offset
        d = disps[disp_offset:disp_offset + n]

        # instruction end RVAs
        instr_end_rvas = np.arange(code_rva + insn_len, code_rva + insn_len + n, dtype=np.int64)

        # resolved target for each position
        resolved = instr_end_rvas + d

        for target_rva in target_rvas:
            # Find positions where resolved is within tolerance of target
            diff = np.abs(resolved - target_rva)
            hits = np.nonzero(diff <= tolerance)[0]

            for idx in hits:
                resolved_rva = int(resolved[idx])
                # Only keep references to outside code section (data references)
                if resolved_rva < code_rva or resolved_rva >= code_end:
                    instr_rva = code_rva + int(idx)
                    results[target_rva].append((instr_rva, resolved_rva))

    # Deduplicate per target
    for target_rva in list(results.keys()):
        seen = set()
        unique = []
        for instr_rva, resolved_rva in results[target_rva]:
            if instr_rva not in seen:
                seen.add(instr_rva)
                unique.append((instr_rva, resolved_rva))
        results[target_rva] = unique

    return results


def _find_rip_refs_python(code_buf, code_rva, target_rvas, tolerance):
    """Pure Python batch RIP-reference search (slower but no dependencies)."""
    buf_len = len(code_buf)
    code_end = code_rva + buf_len
    results = defaultdict(list)

    # Precompute displacement array once
    count = buf_len - 3
    disps = array.array('i', struct.unpack_from(f'<{count}i',
                        code_buf[:count * 4] + code_buf[count:count+3] if False else b''))
    # Actually build it properly
    disps = [0] * count
    for i in range(count):
        disps[i] = struct.unpack_from('<i', code_buf, i)[0]

    # Build a set of target ranges for fast checking
    target_set = sorted(target_rvas)

    for insn_len in (7, 6, 3, 4, 5, 8):
        disp_offset = insn_len - 4
        if disp_offset < 1:
            continue

        n = count - disp_offset
        if n <= 0:
            continue

        for i in range(n):
            d = disps[disp_offset + i]
            instr_end_rva = code_rva + i + insn_len
            resolved_rva = instr_end_rva + d

            # Skip if inside code section
            if code_rva <= resolved_rva < code_end:
                continue

            # Check against all targets
            for target_rva in target_set:
                if abs(resolved_rva - target_rva) <= tolerance:
                    results[target_rva].append((code_rva + i, resolved_rva))

    # Deduplicate
    for target_rva in list(results.keys()):
        seen = set()
        unique = []
        for instr_rva, resolved_rva in results[target_rva]:
            if instr_rva not in seen:
                seen.add(instr_rva)
                unique.append((instr_rva, resolved_rva))
        results[target_rva] = unique

    return results


def check_function_prologue(code_buf, code_rva, target_rva, search_range=0):
    """Check if there's a valid function prologue at or near target_rva.
    search_range: scan this many bytes before and after target_rva for prologues."""
    buf_len = len(code_buf)

    # Check exact address first
    offset = target_rva - code_rva
    if 0 <= offset < buf_len - 16:
        for p in FUNCTION_PROLOGUES:
            if code_buf[offset:offset + len(p)] == p:
                return target_rva

    # Check nearby for INT3/NOP-aligned prologues
    start = max(0, offset - search_range)
    end = min(buf_len - 16, offset + search_range + 16)

    candidates = []
    for pos in range(start, end):
        # A function start is typically preceded by INT3 (0xCC), NOP (0x90), or RET (0xC3)
        if pos > 0 and code_buf[pos - 1] not in (0xCC, 0x90, 0xC3):
            continue
        for p in FUNCTION_PROLOGUES:
            if code_buf[pos:pos + len(p)] == p:
                candidates.append(code_rva + pos)
                break

    if candidates:
        # Return the candidate closest to target_rva
        return min(candidates, key=lambda c: abs(c - target_rva))

    return None


def find_call_targets_batch(code_buf, code_rva, target_rvas, tolerance=0x200):
    """Find E8 (CALL rel32) instructions targeting near any of the target RVAs.
    Returns dict of target_rva -> [(caller_rva, call_target_rva), ...]."""
    buf_len = len(code_buf)
    results = defaultdict(list)

    if HAS_NUMPY:
        raw = np.frombuffer(code_buf, dtype=np.uint8)
        # Find all E8 byte positions
        e8_positions = np.nonzero(raw[:buf_len - 5] == 0xE8)[0]

        if len(e8_positions) == 0:
            return results

        # Read rel32 at each E8 position
        count = buf_len - 3
        b0 = raw[:count].astype(np.int64)
        b1 = raw[1:count+1].astype(np.int64)
        b2 = raw[2:count+2].astype(np.int64)
        b3 = raw[3:count+3].astype(np.int64)
        unsigned = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        disps_all = np.where(unsigned >= 0x80000000, unsigned - 0x100000000, unsigned)

        # For each E8 position, the rel32 starts at position+1
        valid = e8_positions[e8_positions + 1 < len(disps_all)]
        rel32s = disps_all[valid + 1]
        caller_rvas = code_rva + valid
        call_targets = caller_rvas + 5 + rel32s

        for target_rva in target_rvas:
            diffs = np.abs(call_targets - target_rva)
            hits = np.nonzero(diffs <= tolerance)[0]
            for idx in hits:
                results[target_rva].append((int(caller_rvas[idx]), int(call_targets[idx])))
    else:
        for i in range(buf_len - 5):
            if code_buf[i] != 0xE8:
                continue
            rel32 = struct.unpack_from('<i', code_buf, i + 1)[0]
            call_rva = code_rva + i
            call_target = call_rva + 5 + rel32
            for target_rva in target_rvas:
                if abs(call_target - target_rva) <= tolerance:
                    results[target_rva].append((call_rva, call_target))

    return results


def resolve_globals(missing_globals, found_results, code_buf, code_rva, pe,
                    data_delta, tolerance=0x200):
    """Try to resolve missing globals by cross-referencing from found code."""
    resolved = []

    # Build predicted RVAs for all missing globals
    predictions = {}  # predicted_rva -> entry info
    target_rvas = []
    for entry in missing_globals:
        name = entry['name']
        old_addr = entry['old_address']
        if isinstance(old_addr, str):
            old_addr = int(old_addr, 16)

        predicted_rva = (old_addr - pe.preferred_base) + data_delta
        predictions[predicted_rva] = (name, old_addr)
        target_rvas.append(predicted_rva)

    # Batch scan for all targets at once
    print(f"    Scanning {len(code_buf):,} bytes for RIP-relative references to {len(target_rvas)} targets...")
    all_refs = find_rip_references_batch(code_buf, code_rva, target_rvas, tolerance)

    for predicted_rva in target_rvas:
        name, old_addr = predictions[predicted_rva]
        predicted_addr = pe.preferred_base + predicted_rva
        refs = all_refs.get(predicted_rva, [])

        if refs:
            # Group by resolved target address
            target_counts = defaultdict(list)
            for instr_rva, resolved_rva in refs:
                target_counts[resolved_rva].append(instr_rva)

            # Pick the target closest to predicted address, using ref count as tiebreaker
            best_target_rva, ref_list = min(
                target_counts.items(),
                key=lambda x: (abs(x[0] - predicted_rva), -len(x[1]))
            )
            best_addr = pe.preferred_base + best_target_rva

            confidence = 'high' if len(ref_list) >= 3 else 'low' if len(ref_list) >= 1 else 'not_found'
            delta = best_addr - old_addr

            resolved.append({
                'name': name,
                'confidence': confidence,
                'new_address': f'0x{best_addr:X}',
                'old_address': f'0x{old_addr:X}',
                'delta': delta,
                'ref_count': len(ref_list),
                'total_refs': len(refs),
                'method': 'rip_xref',
                'predicted': f'0x{predicted_addr:X}',
                'referencing_code': [f'0x{pe.preferred_base + rva:X}' for rva in ref_list[:5]],
            })
        else:
            resolved.append({
                'name': name,
                'confidence': 'not_found',
                'new_address': '0x0',
                'old_address': f'0x{old_addr:X}',
                'delta': 0,
                'ref_count': 0,
                'method': 'rip_xref',
                'predicted': f'0x{predicted_addr:X}',
                'note': f'No RIP-relative references found within {tolerance} bytes of predicted address',
            })

    return resolved


def resolve_functions(missing_functions, found_results, code_buf, code_rva, pe,
                      code_delta, tolerance=0x200):
    """Try to resolve missing functions by prologue verification and call xrefs."""
    resolved = []
    needs_call_search = []  # entries that didn't match a prologue directly

    # Compute multiple delta candidates from successfully found functions
    found_func_deltas = []
    for r in found_results:
        if r['confidence'] != 'not_found' and not is_global_name(r['name']):
            found_func_deltas.append(r['delta'])

    # Get a few representative deltas to try (median, and common clusters)
    delta_candidates = [code_delta]
    if found_func_deltas:
        rounded = defaultdict(list)
        for d in found_func_deltas:
            key = (d >> 4) << 4
            rounded[key].append(d)
        # Top 5 most common delta clusters
        top_clusters = sorted(rounded.values(), key=len, reverse=True)[:5]
        for cluster in top_clusters:
            cd = int(median(cluster))
            if cd not in delta_candidates:
                delta_candidates.append(cd)

    print(f"    Trying {len(delta_candidates)} delta candidates: {', '.join(f'0x{d:X}' for d in delta_candidates)}")

    # First pass: check for function prologues at predicted addresses using multiple deltas
    for entry in missing_functions:
        name = entry['name']
        old_addr = entry['old_address']
        if isinstance(old_addr, str):
            old_addr = int(old_addr, 16)

        best_match = None
        best_distance = float('inf')
        primary_predicted_rva = (old_addr - pe.preferred_base) + code_delta
        primary_predicted_addr = pe.preferred_base + primary_predicted_rva

        for delta_candidate in delta_candidates:
            predicted_rva = (old_addr - pe.preferred_base) + delta_candidate
            # Search within a window around the prediction
            prologue_rva = check_function_prologue(code_buf, code_rva, predicted_rva, search_range=0x80)
            if prologue_rva is not None:
                dist = abs(prologue_rva - predicted_rva)
                if dist < best_distance:
                    best_distance = dist
                    best_match = prologue_rva

        if best_match is not None:
            found_addr = pe.preferred_base + best_match
            delta = found_addr - old_addr
            resolved.append({
                'name': name,
                'confidence': 'high' if best_distance <= 0x10 else 'low',
                'new_address': f'0x{found_addr:X}',
                'old_address': f'0x{old_addr:X}',
                'delta': delta,
                'method': 'prologue_at_predicted',
            })
        else:
            needs_call_search.append((name, old_addr, primary_predicted_rva, primary_predicted_addr))

    # Second pass: batch search for CALL xrefs to remaining functions
    if needs_call_search:
        # Try all delta candidates for call search
        all_target_rvas = []
        target_map = {}  # target_rva -> (name, old_addr, predicted_addr)
        for name, old_addr, primary_pred_rva, primary_pred_addr in needs_call_search:
            for dc in delta_candidates:
                pred = (old_addr - pe.preferred_base) + dc
                all_target_rvas.append(pred)
                target_map[pred] = (name, old_addr, pe.preferred_base + pred)

        print(f"    Scanning for CALL xrefs to {len(needs_call_search)} remaining functions ({len(all_target_rvas)} predictions)...")
        all_calls = find_call_targets_batch(code_buf, code_rva, all_target_rvas, tolerance)

        # Merge results per function name
        func_calls = defaultdict(list)  # name -> [(caller_rva, target_rva)]
        for pred_rva, calls in all_calls.items():
            if pred_rva in target_map:
                name = target_map[pred_rva][0]
                func_calls[name].extend(calls)

        for name, old_addr, predicted_rva, predicted_addr in needs_call_search:
            calls = func_calls.get(name, [])

            if calls:
                target_counts = defaultdict(list)
                for caller_rva, target_rva in calls:
                    target_counts[target_rva].append(caller_rva)

                best = None
                best_count = 0
                for target_rva, callers in target_counts.items():
                    prologue = check_function_prologue(code_buf, code_rva, target_rva)
                    if prologue is not None and len(callers) > best_count:
                        best = pe.preferred_base + prologue
                        best_count = len(callers)

                if best is not None:
                    delta = best - old_addr
                    resolved.append({
                        'name': name,
                        'confidence': 'high' if best_count >= 3 else 'low',
                        'new_address': f'0x{best:X}',
                        'old_address': f'0x{old_addr:X}',
                        'delta': delta,
                        'call_xrefs': best_count,
                        'method': 'call_xref',
                    })
                    continue

            resolved.append({
                'name': name,
                'confidence': 'not_found',
                'new_address': '0x0',
                'old_address': f'0x{old_addr:X}',
                'delta': 0,
                'method': 'none',
                'predicted': f'0x{predicted_addr:X}',
                'note': 'No valid function found near predicted address',
            })

    return resolved


def main():
    parser = argparse.ArgumentParser(
        description='Resolve missing offsets by cross-referencing found offsets in a new PE binary.')
    parser.add_argument('scan_results', help='Path to scan_results.json from SigScan')
    parser.add_argument('executable', help='Path to the new PE executable (e.g., eqgame.exe)')
    parser.add_argument('--signatures', '-s', help='Path to signatures JSON (for offset type info)')
    parser.add_argument('--output', '-o', default='resolved.json', help='Output file (default: resolved.json)')
    parser.add_argument('--tolerance', '-t', type=int, default=0x200,
                        help='Search tolerance in bytes around predicted address (default: 512)')
    args = parser.parse_args()

    # Load scan results
    results = load_scan_results(args.scan_results)
    if not results:
        print("Error: No results found in scan results file", file=sys.stderr)
        return 1

    # Load optional signature type info
    sig_types = {}
    if args.signatures:
        sigs = load_signatures(args.signatures)
        for name, sig in sigs.items():
            sig_types[name] = sig.get('type', 'function')

    # Separate found vs missing
    found = [r for r in results if r['confidence'] != 'not_found']
    missing = [r for r in results if r['confidence'] == 'not_found']

    if not missing:
        print("All offsets were found! Nothing to resolve.")
        return 0

    print(f"Scan results: {len(found)} found, {len(missing)} missing")

    # Compute deltas
    code_delta, data_delta, overall_delta = compute_deltas(results)
    print(f"Computed deltas:")
    print(f"  Code (functions): 0x{code_delta:X}")
    print(f"  Data (globals):   0x{data_delta:X}")
    print(f"  Overall median:   0x{overall_delta:X}")

    # Load PE
    print(f"\nLoading {args.executable}...")
    pe = PEFile(args.executable)
    print(f"  Preferred base: 0x{pe.preferred_base:X}")
    print(f"  Sections: {', '.join(s['name'] for s in pe.sections)}")

    # Build code buffer
    code_buf, code_rva, code_size = pe.build_code_buffer()
    if code_buf is None:
        print("Error: No code sections found", file=sys.stderr)
        return 1
    print(f"  Code buffer: RVA 0x{code_rva:X}, size 0x{code_size:X}")

    # Classify missing offsets
    missing_globals = []
    missing_functions = []
    for entry in missing:
        name = entry['name']
        if name in sig_types:
            if sig_types[name] == 'global_ref':
                missing_globals.append(entry)
            else:
                missing_functions.append(entry)
        elif is_global_name(name):
            missing_globals.append(entry)
        else:
            missing_functions.append(entry)

    print(f"\nMissing offsets: {len(missing_globals)} globals, {len(missing_functions)} functions")

    # Resolve globals
    all_resolved = []
    if missing_globals:
        print(f"\nResolving globals (tolerance={args.tolerance} bytes)...")
        global_results = resolve_globals(
            missing_globals, found, code_buf, code_rva, pe, data_delta, args.tolerance)
        all_resolved.extend(global_results)

        g_found = sum(1 for r in global_results if r['confidence'] != 'not_found')
        print(f"  Resolved {g_found}/{len(missing_globals)} globals")

    # Resolve functions
    if missing_functions:
        print(f"\nResolving functions (tolerance={args.tolerance} bytes)...")
        func_results = resolve_functions(
            missing_functions, found, code_buf, code_rva, pe, code_delta, args.tolerance)
        all_resolved.extend(func_results)

        f_found = sum(1 for r in func_results if r['confidence'] != 'not_found')
        print(f"  Resolved {f_found}/{len(missing_functions)} functions")

    # Summary
    total_resolved = sum(1 for r in all_resolved if r['confidence'] != 'not_found')
    still_missing = sum(1 for r in all_resolved if r['confidence'] == 'not_found')

    high_count = sum(1 for r in all_resolved if r['confidence'] == 'high')
    low_count = sum(1 for r in all_resolved if r['confidence'] == 'low')

    print(f"\n{'='*60}")
    print(f"RESOLUTION SUMMARY")
    print(f"{'='*60}")
    print(f"  High confidence:  {high_count}/{len(missing)}")
    print(f"  Low confidence:   {low_count}/{len(missing)}")
    print(f"  Still missing:    {still_missing}/{len(missing)}")

    # Print resolved offsets split by confidence
    high_resolved = [r for r in all_resolved if r['confidence'] == 'high']
    low_resolved = [r for r in all_resolved if r['confidence'] == 'low']

    if high_resolved:
        print(f"\n--- HIGH CONFIDENCE ({len(high_resolved)}) ---")
        for r in high_resolved:
            method = r.get('method', '?')
            extra = ''
            if 'ref_count' in r:
                extra = f', {r["ref_count"]} xrefs'
            elif 'call_xrefs' in r:
                extra = f', {r["call_xrefs"]} call xrefs'
            print(f"  {r['name']}: {r['old_address']} -> {r['new_address']} "
                  f"(delta=0x{r['delta']:X}, {method}{extra})")

    if low_resolved:
        print(f"\n--- LOW CONFIDENCE ({len(low_resolved)}) --- review before applying ---")
        for r in low_resolved:
            method = r.get('method', '?')
            extra = ''
            if 'ref_count' in r:
                extra = f', {r["ref_count"]} xrefs'
            elif 'call_xrefs' in r:
                extra = f', {r["call_xrefs"]} call xrefs'
            print(f"  {r['name']}: {r['old_address']} -> {r['new_address']} "
                  f"(delta=0x{r['delta']:X}, {method}{extra})")

    if still_missing > 0:
        print(f"\n--- STILL MISSING ---")
        for r in all_resolved:
            if r['confidence'] == 'not_found':
                note = r.get('note', '')
                predicted = r.get('predicted', '?')
                print(f"  {r['name']}: predicted={predicted} - {note}")

    # Write output
    output = {
        'deltas': {
            'code': code_delta,
            'data': data_delta,
            'overall': overall_delta,
        },
        'resolved': all_resolved,
        'summary': {
            'total_missing': len(missing),
            'resolved': total_resolved,
            'still_missing': still_missing,
        }
    }

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {args.output}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
