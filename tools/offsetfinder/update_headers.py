#!/usr/bin/env python3
"""
Update eqlib offset header files from scan results.

Reads results.json (scan results and/or resolved results) and updates the
offset #define values in eqgame.h, eqmain.h, and eqgraphics.h.

Only offsets with confidence "confirmed" are applied. After running the scan
and resolve_missing.py, manually review and change the confidence field to
"confirmed" for each offset you have verified.

Usage:
    python update_headers.py <results.json> [--eqlib-path PATH] [--dry-run]
                             [--client-date YYYYMMDD]
"""

import json
import re
import os
import sys
import argparse
from datetime import datetime

OFFSET_PATTERN = re.compile(r'(#define\s+(\w+_x)\s+)(0x[0-9A-Fa-f]+)(.*)')
DATE_PATTERN = re.compile(r'(#define\s+__ClientDate\s+)\d+u(.*)')
EXPECTED_DATE_PATTERN = re.compile(r'(#define\s+__ExpectedVersionDate\s+)"[^"]+"(.*)')
EXPECTED_TIME_PATTERN = re.compile(r'(#define\s+__ExpectedVersionTime\s+)"[^"]+"(.*)')


def load_results(filepath):
    """Load results JSON and return confirmed offsets and stats."""
    with open(filepath, 'r') as f:
        data = json.load(f)

    offsets = {}
    stats = {'confirmed': 0, 'high': 0, 'low': 0, 'not_found': 0, 'other': 0}

    # Support both scan results format and resolved format
    entries = data.get('results', []) + data.get('resolved', [])

    for entry in entries:
        name = entry['name']
        confidence = entry.get('confidence', 'not_found')
        new_address = entry.get('new_address', '0x0')

        if confidence == 'confirmed':
            stats['confirmed'] += 1
            define_name = name + '_x'
            offsets[define_name] = new_address
        elif confidence == 'high':
            stats['high'] += 1
        elif confidence == 'low':
            stats['low'] += 1
        elif confidence == 'not_found':
            stats['not_found'] += 1
        else:
            stats['other'] += 1

    return offsets, stats


def update_header(filepath, new_offsets, dry_run=False):
    """Update offset values in a header file."""
    if not os.path.exists(filepath):
        print(f"  File not found: {filepath}")
        return 0

    with open(filepath, 'r') as f:
        lines = f.readlines()

    updated = 0
    new_lines = []

    for line in lines:
        m = OFFSET_PATTERN.match(line)
        if m:
            prefix = m.group(1)
            define_name = m.group(2)
            old_value = m.group(3)
            suffix = m.group(4)

            if define_name in new_offsets:
                new_value = new_offsets[define_name]
                if old_value.lower() != new_value.lower():
                    # Format to match existing style (uppercase hex, consistent width)
                    # Parse the address to reformat it
                    addr = int(new_value, 16)
                    formatted = f"0x{addr:014X}" if addr > 0xFFFFFFFF else f"0x{addr:08X}"

                    new_line = f"{prefix}{formatted}{suffix}\n"
                    if dry_run:
                        print(f"  {define_name}: {old_value} -> {formatted}")
                    new_lines.append(new_line)
                    updated += 1
                    continue

        new_lines.append(line)

    if not dry_run and updated > 0:
        with open(filepath, 'w') as f:
            f.writelines(new_lines)

    return updated


def update_version_info(filepath, client_date=None, dry_run=False):
    """Update __ClientDate and expected version fields."""
    if not client_date or not os.path.exists(filepath):
        return

    with open(filepath, 'r') as f:
        content = f.read()

    # Update __ClientDate
    date_str = client_date if isinstance(client_date, str) else str(client_date)
    if not date_str.endswith('u'):
        date_str += 'u'

    new_content = content
    new_content = DATE_PATTERN.sub(rf'\g<1>{date_str}\2', new_content)

    # Try to parse date for __ExpectedVersionDate
    try:
        # Assume format YYYYMMDD
        clean = date_str.rstrip('u')
        dt = datetime.strptime(clean, '%Y%m%d')
        formatted_date = dt.strftime('%b %e %Y').replace('  ', ' ')
        # Pad single-digit days with space to match EQ format
        new_content = EXPECTED_DATE_PATTERN.sub(
            rf'\1"{formatted_date}"\2', new_content)
    except ValueError:
        pass

    if new_content != content:
        if dry_run:
            print(f"  Would update version info in {filepath}")
        else:
            with open(filepath, 'w') as f:
                f.write(new_content)


def main():
    parser = argparse.ArgumentParser(description='Update offset headers from confirmed results')
    parser.add_argument('results', nargs='+',
                        help='Path(s) to results JSON files (scan_results.json, resolved.json, etc.)')
    parser.add_argument('--eqlib-path', default=None,
                        help='Path to eqlib offsets directory')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show changes without writing files')
    parser.add_argument('--client-date', default=None,
                        help='New client date (YYYYMMDD format)')
    args = parser.parse_args()

    # Find paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(script_dir, '..', '..'))

    if args.eqlib_path:
        offsets_dir = args.eqlib_path
    else:
        offsets_dir = os.path.join(repo_root, 'src', 'eqlib', 'include', 'eqlib', 'offsets')

    # Load all result files
    all_offsets = {}
    total_stats = {'confirmed': 0, 'high': 0, 'low': 0, 'not_found': 0, 'other': 0}

    for filepath in args.results:
        print(f"Loading {filepath}...")
        offsets, stats = load_results(filepath)
        all_offsets.update(offsets)
        for k in total_stats:
            total_stats[k] += stats[k]

    print(f"\nResults summary:")
    print(f"  Confirmed:  {total_stats['confirmed']}")
    print(f"  High:       {total_stats['high']} (not applied, change to \"confirmed\" to apply)")
    print(f"  Low:        {total_stats['low']} (not applied, change to \"confirmed\" to apply)")
    print(f"  Not found:  {total_stats['not_found']}")
    print(f"\nOffsets to update: {len(all_offsets)}\n")

    if len(all_offsets) == 0:
        print("No confirmed offsets to apply. Mark offsets as \"confirmed\" in the JSON to apply them.")
        return 0

    if args.dry_run:
        print("DRY RUN - no files will be modified\n")

    # Update each header file
    headers = ['eqgame.h', 'eqmain.h', 'eqgraphics.h']
    total_updated = 0

    for header in headers:
        filepath = os.path.join(offsets_dir, header)
        print(f"Processing {header}...")
        count = update_header(filepath, all_offsets, args.dry_run)
        total_updated += count
        print(f"  Updated {count} offsets")

    # Update version info if requested
    if args.client_date:
        eqgame_path = os.path.join(offsets_dir, 'eqgame.h')
        update_version_info(eqgame_path, args.client_date, args.dry_run)

    print(f"\nTotal: {total_updated} offsets updated across all files")

    unconfirmed = total_stats['high'] + total_stats['low']
    if unconfirmed > 0:
        print(f"\nNOTE: {unconfirmed} offsets are not yet confirmed. "
              f"Review and change their confidence to \"confirmed\" to apply them.")


if __name__ == '__main__':
    main()
