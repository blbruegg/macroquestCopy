#!/usr/bin/env python3
"""
Update eqlib offset header files from scan results.

Reads scan_results.json produced by the SigScan tool and updates the
offset #define values in eqgame.h, eqmain.h, and eqgraphics.h.

Usage:
    python update_headers.py <scan_results.json> [--eqlib-path PATH] [--dry-run]
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


def load_scan_results(filepath):
    """Load scan results JSON and return a dict of name -> new_address."""
    with open(filepath, 'r') as f:
        data = json.load(f)

    results = {}
    stats = {'high': 0, 'low': 0, 'not_found': 0, 'skipped': 0}

    for entry in data.get('results', []):
        name = entry['name']
        confidence = entry.get('confidence', 'not_found')
        new_address = entry.get('new_address', '0x0')

        if confidence == 'not_found':
            stats['not_found'] += 1
            continue

        if confidence == 'low':
            stats['low'] += 1
            # Still include low-confidence results but warn
            print(f"  WARNING: Low confidence for {name} "
                  f"({entry.get('match_count', '?')} matches)")

        if confidence == 'high':
            stats['high'] += 1

        # Convert name to the _x define format
        define_name = name + '_x'
        results[define_name] = new_address

    return results, stats


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
    parser = argparse.ArgumentParser(description='Update offset headers from scan results')
    parser.add_argument('scan_results', help='Path to scan_results.json')
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

    print(f"Loading scan results from {args.scan_results}...")
    new_offsets, stats = load_scan_results(args.scan_results)

    print(f"\nScan results: {stats['high']} high confidence, "
          f"{stats['low']} low confidence, "
          f"{stats['not_found']} not found")
    print(f"Total offsets to update: {len(new_offsets)}\n")

    if args.dry_run:
        print("DRY RUN - no files will be modified\n")

    # Update each header file
    headers = ['eqgame.h', 'eqmain.h', 'eqgraphics.h']
    total_updated = 0

    for header in headers:
        filepath = os.path.join(offsets_dir, header)
        print(f"Processing {header}...")
        count = update_header(filepath, new_offsets, args.dry_run)
        total_updated += count
        print(f"  Updated {count} offsets")

    # Update version info if requested
    if args.client_date:
        eqgame_path = os.path.join(offsets_dir, 'eqgame.h')
        update_version_info(eqgame_path, args.client_date, args.dry_run)

    print(f"\nTotal: {total_updated} offsets updated across all files")

    if stats['not_found'] > 0:
        print(f"\nWARNING: {stats['not_found']} offsets could not be found. "
              f"These must be updated manually.")

    if stats['low'] > 0:
        print(f"WARNING: {stats['low']} offsets had low confidence (multiple matches). "
              f"Review these carefully.")


if __name__ == '__main__':
    main()
