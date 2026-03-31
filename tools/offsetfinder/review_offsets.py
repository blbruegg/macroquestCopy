#!/usr/bin/env python3
"""
Interactive offset review tool for MacroQuest.

Displays disassembly around unresolved/ambiguous offsets from scan results,
allowing visual inspection and manual address selection. Outputs a final
corrected scan_results.json.

Requirements:
    pip install pefile capstone

Usage:
    python review_offsets.py <scan_results.json> <executable> [--signatures signatures.json]
    python review_offsets.py scan_results.json E:\\EverQuest\\eqgame.exe

Controls:
    Up/Down or j/k    Navigate between offsets
    Left/Right or h/l Scroll disassembly up/down
    Enter              Edit address for current offset
    a                  Accept current suggested address
    s                  Skip (mark as not_found)
    f                  Filter: show all / not_found / ambiguous
    d                  Toggle between old and new binary disassembly view
    w                  Write results and exit
    q                  Quit without saving
    /                  Search for offset by name
    g                  Go to address (enter hex address to disassemble)
    ?                  Show help
"""

import json
import sys
import os
import struct
import argparse
import re
from collections import OrderedDict

try:
    import pefile
except ImportError:
    print("ERROR: pefile is required. Install with: pip install pefile")
    sys.exit(1)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("ERROR: capstone is required. Install with: pip install capstone")
    sys.exit(1)

# Windows console color support
if sys.platform == 'win32':
    os.system('')  # Enable ANSI escape codes on Windows


# ANSI color codes
class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BG_BLUE = '\033[44m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'


class PEAnalyzer:
    """Loads a PE file and provides disassembly."""

    def __init__(self, filepath):
        self.pe = pefile.PE(filepath, fast_load=True)
        self.pe.parse_data_directories()
        self.filepath = filepath
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        # Build section map for quick RVA -> data lookups
        self._sections = []
        for section in self.pe.sections:
            self._sections.append({
                'name': section.Name.rstrip(b'\x00').decode('ascii', errors='replace'),
                'va': section.VirtualAddress,
                'vs': section.Misc_VirtualSize,
                'rd_offset': section.PointerToRawData,
                'rd_size': section.SizeOfRawData,
                'chars': section.Characteristics,
            })

    def rva_to_file_offset(self, rva):
        for sec in self._sections:
            if sec['va'] <= rva < sec['va'] + sec['rd_size']:
                return sec['rd_offset'] + (rva - sec['va'])
        return None

    def read_at_va(self, va, size):
        """Read bytes at a virtual address."""
        rva = va - self.image_base
        offset = self.rva_to_file_offset(rva)
        if offset is None:
            return None
        return self.pe.__data__[offset:offset + size]

    def disassemble_at(self, va, count=30, context_before=10):
        """Disassemble instructions around a virtual address.

        Returns list of (address, hex_bytes, mnemonic, op_str, is_target) tuples.
        """
        # Start a bit before the target to show context
        start_va = va - context_before * 8  # rough estimate, 8 bytes per instruction avg
        if start_va < self.image_base:
            start_va = self.image_base

        # Read a chunk of code
        total_bytes = (count + context_before) * 15  # max 15 bytes per x64 instruction
        data = self.read_at_va(start_va, total_bytes)
        if not data:
            return []

        instructions = []
        for insn in self.cs.disasm(data, start_va):
            hex_bytes = ' '.join(f'{b:02X}' for b in insn.bytes)
            is_target = (insn.address == va)
            instructions.append((
                insn.address,
                hex_bytes,
                insn.mnemonic,
                insn.op_str,
                is_target,
            ))
            if len(instructions) >= count + context_before * 2:
                break

        return instructions

    def find_function_start(self, va):
        """Try to find the start of the function containing va.
        Scans backward for INT3 padding or common prologues."""
        for offset in range(0, 0x1000, 1):
            check_va = va - offset
            data = self.read_at_va(check_va - 1, 2)
            if data is None:
                continue
            prev_byte = data[0]
            curr_byte = data[1]
            # INT3 padding followed by code
            if prev_byte == 0xCC and curr_byte != 0xCC:
                return check_va
            # After a RET
            if prev_byte in (0xC3, 0xCB) and curr_byte != 0xCC:
                return check_va
        return va

    def find_references_to(self, target_va, search_start=None, search_size=None):
        """Find RIP-relative and E8 call references to target_va.
        Returns list of (ref_addr, ref_type) tuples."""
        if search_start is None:
            # Search .text section
            for sec in self._sections:
                if sec['chars'] & 0x20:  # IMAGE_SCN_CNT_CODE
                    search_start = self.image_base + sec['va']
                    search_size = sec['vs']
                    break
        if search_start is None:
            return []

        results = []
        data = self.read_at_va(search_start, search_size)
        if data is None:
            return []

        # Search for E8 (CALL rel32) references
        for i in range(len(data) - 5):
            if data[i] == 0xE8:
                rel = struct.unpack_from('<i', data, i + 1)[0]
                call_target = search_start + i + 5 + rel
                if call_target == target_va:
                    results.append((search_start + i, 'call'))
                    if len(results) >= 20:
                        break

        # Search for RIP-relative references (displacement scanning)
        for i in range(len(data) - 7):
            for insn_len in range(3, 9):
                disp_pos = insn_len - 4
                if disp_pos < 1 or i + insn_len > len(data):
                    continue
                disp = struct.unpack_from('<i', data, i + disp_pos)[0]
                ref_target = search_start + i + insn_len + disp
                if abs(ref_target - target_va) <= 8:  # small tolerance for struct members
                    results.append((search_start + i, f'rip-rel (-> 0x{ref_target:X})'))
                    if len(results) >= 20:
                        return results
                    break

        return results


class OffsetEntry:
    """One offset being reviewed."""
    def __init__(self, name, old_address, new_address, confidence, delta,
                 match_count, error_message, sig_type):
        self.name = name
        self.old_address = old_address
        self.new_address = new_address
        self.confidence = confidence
        self.delta = delta
        self.match_count = match_count
        self.error_message = error_message
        self.sig_type = sig_type
        # User-edited fields
        self.user_address = new_address if confidence != 'not_found' else 0
        self.user_confirmed = (confidence == 'high')
        self.user_skipped = False


def load_results(filepath):
    """Load scan results and return list of OffsetEntry."""
    with open(filepath) as f:
        data = json.load(f)

    entries = []
    for r in data.get('results', []):
        old_addr = int(r.get('old_address', '0x0'), 16)
        new_addr = int(r.get('new_address', '0x0'), 16)
        entries.append(OffsetEntry(
            name=r['name'],
            old_address=old_addr,
            new_address=new_addr,
            confidence=r.get('confidence', 'not_found'),
            delta=r.get('delta', 0),
            match_count=r.get('match_count', 0),
            error_message=r.get('error', ''),
            sig_type=r.get('type', 'function'),
        ))
    return entries


def load_signatures(filepath):
    """Load signature database for type info."""
    if not filepath or not os.path.exists(filepath):
        return {}
    with open(filepath) as f:
        data = json.load(f)
    sigs = {}
    for name, info in data.get('signatures', {}).items():
        sigs[name] = info.get('type', 'function')
    return sigs


def save_results(entries, output_path):
    """Save corrected results back to JSON."""
    results = []
    for e in entries:
        if e.user_skipped:
            conf = 'not_found'
            addr = e.old_address  # keep old
        elif e.user_confirmed:
            conf = 'high' if e.confidence == 'high' else 'low'
            addr = e.user_address
        else:
            conf = e.confidence
            addr = e.new_address

        results.append({
            'name': e.name,
            'confidence': conf,
            'new_address': f'0x{addr:X}',
            'old_address': f'0x{e.old_address:X}',
            'delta': int(addr) - int(e.old_address) if addr else 0,
            'match_count': e.match_count,
        })

    with open(output_path, 'w') as f:
        json.dump({'results': results}, f, indent=2)


def clear_screen():
    print('\033[2J\033[H', end='')


def move_cursor(row, col):
    print(f'\033[{row};{col}H', end='')


def get_terminal_size():
    try:
        columns, lines = os.get_terminal_size()
        return lines, columns
    except OSError:
        return 40, 120


def confidence_color(conf):
    if conf == 'high':
        return C.GREEN
    elif conf == 'low':
        return C.YELLOW
    else:
        return C.RED


def render_status_bar(text, width):
    """Render an inverted status bar."""
    padded = text.ljust(width)[:width]
    return f'{C.BG_BLUE}{C.WHITE}{padded}{C.RESET}'


def render_offset_list(entries, selected_idx, filter_mode, start_idx, max_lines):
    """Render the offset list panel."""
    lines = []
    visible = get_filtered_indices(entries, filter_mode)

    for line_num in range(max_lines):
        list_idx = start_idx + line_num
        if list_idx >= len(visible):
            lines.append('')
            continue

        entry_idx = visible[list_idx]
        e = entries[entry_idx]

        marker = '>' if entry_idx == selected_idx else ' '
        conf_c = confidence_color(e.confidence)

        if e.user_skipped:
            status = f'{C.DIM}SKIP{C.RESET}'
        elif e.user_confirmed:
            status = f'{C.GREEN}OK{C.RESET}  '
        elif e.confidence == 'not_found':
            status = f'{C.RED}MISS{C.RESET}'
        else:
            status = f'{C.YELLOW}REV {C.RESET}'

        highlight = C.BG_BLUE if entry_idx == selected_idx else ''
        name_trunc = e.name[:35].ljust(35)
        line = (f'{highlight}{marker} {status} {conf_c}{name_trunc}{C.RESET}'
                f'{highlight} 0x{e.old_address:014X}{C.RESET}')
        lines.append(line)

    return lines


def get_filtered_indices(entries, filter_mode):
    """Get indices of entries matching the current filter."""
    if filter_mode == 'all':
        return list(range(len(entries)))
    elif filter_mode == 'not_found':
        return [i for i, e in enumerate(entries) if e.confidence == 'not_found']
    elif filter_mode == 'ambiguous':
        return [i for i, e in enumerate(entries) if e.confidence == 'low']
    elif filter_mode == 'unresolved':
        return [i for i, e in enumerate(entries)
                if e.confidence != 'high' and not e.user_confirmed]
    return list(range(len(entries)))


def render_disasm_panel(pe, entry, disasm_offset, median_delta, width):
    """Render disassembly view for current offset."""
    lines = []

    # Header info
    lines.append(f'{C.BOLD}{C.CYAN}=== {entry.name} ==={C.RESET}')
    lines.append(f'  Old: {C.WHITE}0x{entry.old_address:014X}{C.RESET}'
                 f'  Confidence: {confidence_color(entry.confidence)}'
                 f'{entry.confidence}{C.RESET}'
                 f'  Matches: {entry.match_count}')

    predicted = entry.old_address + median_delta if median_delta else 0
    lines.append(f'  New: {C.GREEN}0x{entry.new_address:014X}{C.RESET}'
                 f'  Delta: 0x{entry.delta:X}'
                 f'  Predicted: {C.DIM}0x{predicted:014X}{C.RESET}')

    if entry.user_address and entry.user_address != entry.new_address:
        lines.append(f'  {C.YELLOW}User set: 0x{entry.user_address:014X}{C.RESET}')
    if entry.error_message:
        lines.append(f'  {C.DIM}{entry.error_message}{C.RESET}')

    lines.append('')

    # Determine which address to show disassembly for
    show_addr = entry.user_address or entry.new_address or predicted or entry.old_address
    show_addr += disasm_offset * 0x10  # scroll by 16 bytes per step

    # Disassemble
    if pe and show_addr > 0:
        lines.append(f'{C.BOLD}Disassembly at 0x{show_addr:X}:{C.RESET}')

        instructions = pe.disassemble_at(show_addr, count=25, context_before=5)
        if instructions:
            for addr, hex_bytes, mnemonic, op_str, is_target in instructions:
                # Color the target instruction
                if is_target:
                    prefix = f'{C.BG_GREEN}{C.WHITE}'
                    suffix = C.RESET
                else:
                    prefix = ''
                    suffix = ''

                # Color mnemonics
                if mnemonic in ('call', 'jmp'):
                    mn_color = C.CYAN
                elif mnemonic.startswith('j'):
                    mn_color = C.YELLOW
                elif mnemonic in ('ret', 'retn', 'int3'):
                    mn_color = C.RED
                elif mnemonic in ('push', 'pop'):
                    mn_color = C.MAGENTA
                elif mnemonic.startswith('mov') or mnemonic.startswith('lea'):
                    mn_color = C.GREEN
                else:
                    mn_color = ''

                hex_trunc = hex_bytes[:35].ljust(35)
                line = (f'{prefix}  0x{addr:014X}  {C.DIM}{hex_trunc}{C.RESET}'
                        f'{prefix}  {mn_color}{mnemonic:8s}{C.RESET}'
                        f'{prefix} {op_str}{suffix}')
                lines.append(line)
        else:
            lines.append(f'  {C.RED}(cannot read memory at this address){C.RESET}')

        # Show references if we have a suggested address
        if entry.new_address or entry.user_address:
            ref_addr = entry.user_address or entry.new_address
            refs = pe.find_references_to(ref_addr)
            if refs:
                lines.append('')
                lines.append(f'{C.BOLD}References to 0x{ref_addr:X} ({len(refs)} found):{C.RESET}')
                for ref_va, ref_type in refs[:8]:
                    lines.append(f'  {C.DIM}0x{ref_va:014X}{C.RESET}  {ref_type}')
    else:
        lines.append(f'{C.RED}No address to disassemble{C.RESET}')

    return lines


def input_address(prompt='Enter address (hex): '):
    """Read a hex address from the user."""
    print(f'\n{prompt}', end='', flush=True)
    try:
        line = input().strip()
        if not line:
            return None
        # Accept with or without 0x prefix
        if not line.startswith('0x') and not line.startswith('0X'):
            line = '0x' + line
        return int(line, 16)
    except (ValueError, EOFError):
        return None


def input_string(prompt=''):
    """Read a string from the user."""
    print(f'\n{prompt}', end='', flush=True)
    try:
        return input().strip()
    except EOFError:
        return ''


def main():
    parser = argparse.ArgumentParser(description='Interactive offset review tool')
    parser.add_argument('scan_results', help='Path to scan_results.json')
    parser.add_argument('executable', help='Path to target PE executable')
    parser.add_argument('--signatures', '-s', default=None,
                        help='Path to signatures.json for type info')
    parser.add_argument('--output', '-o', default=None,
                        help='Output path (default: overwrite input)')
    args = parser.parse_args()

    # Load data
    print('Loading scan results...')
    entries = load_results(args.scan_results)

    sig_types = load_signatures(args.signatures)
    for e in entries:
        if e.name in sig_types:
            e.sig_type = sig_types[e.name]

    print(f'Loading PE: {args.executable}...')
    pe = PEAnalyzer(args.executable)

    output_path = args.output or args.scan_results

    # Compute median delta
    deltas = [e.delta for e in entries if e.confidence == 'high' and e.delta != 0]
    median_delta = sorted(deltas)[len(deltas) // 2] if deltas else 0

    # Stats
    n_high = sum(1 for e in entries if e.confidence == 'high')
    n_low = sum(1 for e in entries if e.confidence == 'low')
    n_notfound = sum(1 for e in entries if e.confidence == 'not_found')

    # State
    selected_idx = 0
    filter_mode = 'unresolved'
    disasm_offset = 0
    list_scroll = 0
    message = ''

    # Start on first unresolved entry
    filtered = get_filtered_indices(entries, filter_mode)
    if filtered:
        selected_idx = filtered[0]

    while True:
        term_h, term_w = get_terminal_size()
        clear_screen()

        # Title bar
        n_confirmed = sum(1 for e in entries if e.user_confirmed)
        n_skipped = sum(1 for e in entries if e.user_skipped)
        title = (f' Offset Review | {n_high} found | {n_low} ambiguous | '
                 f'{n_notfound} missing | {n_confirmed} confirmed | '
                 f'{n_skipped} skipped | Median Δ: 0x{median_delta:X} '
                 f'| Filter: {filter_mode}')
        print(render_status_bar(title, term_w))

        # Layout: left panel = offset list (50 chars), right = disassembly
        list_width = 60
        disasm_width = term_w - list_width - 3
        panel_height = term_h - 4  # minus title, status, help

        # Get filtered list
        filtered = get_filtered_indices(entries, filter_mode)

        # Find selected in filtered list
        sel_in_filtered = -1
        for i, idx in enumerate(filtered):
            if idx == selected_idx:
                sel_in_filtered = i
                break

        # Auto-scroll list
        if sel_in_filtered >= 0:
            if sel_in_filtered < list_scroll:
                list_scroll = sel_in_filtered
            elif sel_in_filtered >= list_scroll + panel_height:
                list_scroll = sel_in_filtered - panel_height + 1

        # Render panels
        list_lines = render_offset_list(entries, selected_idx, filter_mode,
                                        list_scroll, panel_height)
        entry = entries[selected_idx] if selected_idx < len(entries) else None
        disasm_lines = render_disasm_panel(pe, entry, disasm_offset,
                                           median_delta, disasm_width) if entry else []

        for row in range(panel_height):
            move_cursor(row + 2, 1)
            left = list_lines[row] if row < len(list_lines) else ''
            right = disasm_lines[row] if row < len(disasm_lines) else ''
            # Print left panel, separator, right panel
            # Can't easily truncate ANSI strings, just print them
            print(f'{left}  {C.DIM}│{C.RESET} {right}', end='')

        # Help bar
        move_cursor(term_h - 1, 1)
        help_text = (' j/k:Navigate  h/l:Scroll  Enter:Edit  a:Accept  '
                     's:Skip  f:Filter  g:GoTo  w:Write  q:Quit  ?:Help')
        print(render_status_bar(help_text, term_w), end='')

        # Message line
        if message:
            move_cursor(term_h, 1)
            print(f'{C.YELLOW}{message}{C.RESET}', end='')
            message = ''

        # Input
        move_cursor(term_h, 1)
        print('', end='', flush=True)

        try:
            # Simple single-character input
            if sys.platform == 'win32':
                import msvcrt
                ch = msvcrt.getwch()
                if ch == '\xe0' or ch == '\x00':  # special key prefix
                    ch2 = msvcrt.getwch()
                    key_map = {'H': 'up', 'P': 'down', 'K': 'left', 'M': 'right'}
                    ch = key_map.get(ch2, '')
                elif ch == '\r':
                    ch = 'enter'
            else:
                import tty
                import termios
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    ch = sys.stdin.read(1)
                    if ch == '\x1b':
                        ch2 = sys.stdin.read(2)
                        arrow_map = {'[A': 'up', '[B': 'down', '[C': 'right', '[D': 'left'}
                        ch = arrow_map.get(ch2, '')
                    elif ch == '\r' or ch == '\n':
                        ch = 'enter'
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (EOFError, KeyboardInterrupt):
            ch = 'q'

        # Handle input
        if ch in ('q', '\x03'):  # q or Ctrl+C
            move_cursor(term_h, 1)
            print(f'{C.YELLOW}Quit without saving? (y/n): {C.RESET}', end='', flush=True)
            if sys.platform == 'win32':
                confirm = msvcrt.getwch()
            else:
                confirm = sys.stdin.read(1)
            if confirm.lower() == 'y':
                break
            continue

        elif ch == 'w':
            save_results(entries, output_path)
            move_cursor(term_h, 1)
            print(f'{C.GREEN}Saved to {output_path}. Press any key...{C.RESET}',
                  end='', flush=True)
            if sys.platform == 'win32':
                msvcrt.getwch()
            else:
                sys.stdin.read(1)
            break

        elif ch in ('j', 'down'):
            # Next entry in filtered list
            if sel_in_filtered >= 0 and sel_in_filtered + 1 < len(filtered):
                selected_idx = filtered[sel_in_filtered + 1]
                disasm_offset = 0

        elif ch in ('k', 'up'):
            # Previous entry
            if sel_in_filtered > 0:
                selected_idx = filtered[sel_in_filtered - 1]
                disasm_offset = 0

        elif ch in ('l', 'right'):
            disasm_offset += 1

        elif ch in ('h', 'left'):
            disasm_offset -= 1

        elif ch == 'enter':
            addr = input_address(f'New address for {entry.name} (hex): ')
            if addr is not None:
                entry.user_address = addr
                entry.user_confirmed = True
                entry.user_skipped = False
                message = f'Set {entry.name} = 0x{addr:X}'
                # Auto-advance
                if sel_in_filtered + 1 < len(filtered):
                    selected_idx = filtered[sel_in_filtered + 1]
                    disasm_offset = 0

        elif ch == 'a':
            if entry and (entry.new_address or entry.user_address):
                entry.user_confirmed = True
                entry.user_skipped = False
                if not entry.user_address:
                    entry.user_address = entry.new_address
                message = f'Accepted {entry.name} = 0x{entry.user_address:X}'
                if sel_in_filtered + 1 < len(filtered):
                    selected_idx = filtered[sel_in_filtered + 1]
                    disasm_offset = 0
            else:
                message = 'No address to accept'

        elif ch == 's':
            if entry:
                entry.user_skipped = True
                entry.user_confirmed = False
                message = f'Skipped {entry.name}'
                if sel_in_filtered + 1 < len(filtered):
                    selected_idx = filtered[sel_in_filtered + 1]
                    disasm_offset = 0

        elif ch == 'f':
            modes = ['all', 'unresolved', 'not_found', 'ambiguous']
            current = modes.index(filter_mode) if filter_mode in modes else 0
            filter_mode = modes[(current + 1) % len(modes)]
            filtered = get_filtered_indices(entries, filter_mode)
            if filtered:
                selected_idx = filtered[0]
            list_scroll = 0
            disasm_offset = 0
            message = f'Filter: {filter_mode} ({len(filtered)} entries)'

        elif ch == 'g':
            addr = input_address('Go to address (hex): ')
            if addr is not None:
                disasm_offset = 0
                if entry:
                    # Temporarily set user_address for viewing
                    entry.user_address = addr
                message = f'Viewing 0x{addr:X}'

        elif ch == '/':
            search = input_string('Search name: ')
            if search:
                for i, e in enumerate(entries):
                    if search.lower() in e.name.lower():
                        selected_idx = i
                        disasm_offset = 0
                        # Switch to all filter to make sure it's visible
                        filter_mode = 'all'
                        message = f'Found: {e.name}'
                        break
                else:
                    message = f'Not found: {search}'

        elif ch == 'p':
            # Jump to predicted address
            if entry and median_delta:
                predicted = entry.old_address + median_delta
                entry.user_address = predicted
                disasm_offset = 0
                message = f'Showing predicted: 0x{predicted:X}'

        elif ch == '?':
            clear_screen()
            print(__doc__)
            print('\nPress any key to continue...', flush=True)
            if sys.platform == 'win32':
                msvcrt.getwch()
            else:
                sys.stdin.read(1)

    clear_screen()
    print('Done.')


if __name__ == '__main__':
    main()
