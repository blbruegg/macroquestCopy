# Offset Finder Tools

Python utilities for updating MacroQuest offset headers after an EQ patch.

These tools work with the output of the MQ2SigScan plugin or its standalone CLI (`SigScanCLI.exe`), which produce a `scan_results.json` file containing new addresses for each offset.

## Prerequisites

- Python 3.8+
- [numpy](https://pypi.org/project/numpy/) (recommended, for fast cross-reference scanning in `resolve_missing.py`)

## Full Offset Update Workflow

After EQ patches, the full process to update all offsets is:

### 1. Scan the new binary

Using the standalone CLI (no running EQ process needed):

```bash
SigScanCLI.exe scan signatures_eqgame.json eqgame.exe --output results.json
```

Or in-game with the plugin:

```
/sigscan scan
```

### 2. Resolve missing offsets

The initial scan typically finds 80-90% of offsets. Use `resolve_missing.py` to find the rest by cross-referencing found offsets in the new binary:

```bash
python tools/offsetfinder/resolve_missing.py results.json eqgame.exe \
    -s signatures_eqgame.json --output resolved.json
```

This computes separate deltas for code and data sections, then:
- **Globals**: predicts new addresses using the data-section delta, verifies by scanning for RIP-relative instructions that reference each predicted address
- **Functions**: predicts using the code delta (trying multiple delta clusters), verifies by checking for valid function prologues and CALL cross-references

Results are classified as HIGH or LOW confidence.

### 3. Review and confirm offsets

Both `results.json` and `resolved.json` contain offsets with confidence values of `"high"`, `"low"`, or `"not_found"`. **Only offsets marked as `"confirmed"` will be applied to the headers.**

Review each offset and change its confidence to `"confirmed"` in the JSON when you have verified it is correct:

```json
{
  "name": "__gWorld",
  "confidence": "confirmed",
  "new_address": "0x140EAC4A7",
  ...
}
```

For HIGH confidence results from the scanner, bulk verification is usually sufficient — check that the deltas are consistent and the addresses make sense. For LOW confidence and resolved results, verify in Ghidra or a disassembler (see tips below).

You can pass multiple JSON files to `update_headers.py` — confirmed offsets from all files will be merged:

```bash
python tools/offsetfinder/update_headers.py results.json resolved.json --dry-run
```

### 4. Apply confirmed offsets

Preview changes first with `--dry-run`:

```bash
python tools/offsetfinder/update_headers.py results.json resolved.json --dry-run
```

Apply for real:

```bash
python tools/offsetfinder/update_headers.py results.json resolved.json
```

### 5. Regenerate the offset table and rebuild

```bash
python tools/offsetfinder/generate_offset_table.py
```

Then rebuild MacroQuest with the updated offsets.

## Verification Tips

- **Import known offsets into Ghidra** — use a script to label all found addresses in the new binary. This makes navigating and cross-referencing much easier.
- **Globals that are zero at rest** (e.g., `pinstEverQuestInfo`) can't be found by value. Instead, find a function that references them (check the xref list in the old binary) and follow the RIP-relative operand in the new binary.
- **Mid-function offsets** (e.g., `__ThrottleFrameRate`) point to a specific instruction, not a function start. Find the containing function, then locate the equivalent instruction in the new binary.
- **BSim** (Ghidra's binary similarity tool) is effective for finding functions that were significantly rewritten between patches, where byte-pattern scanning fails.
- **Ambiguous/LOW confidence results** with odd-looking deltas or addresses not aligned to function boundaries should be verified manually before confirming.

## Tools

### `update_headers.py`

Updates the `#define` values in the offset header files. Only applies offsets with `"confidence": "confirmed"`.

```bash
python update_headers.py <results.json> [<resolved.json> ...] [--eqlib-path PATH]
                         [--dry-run] [--client-date YYYYMMDD]
```

| Flag | Description |
|---|---|
| `--eqlib-path` | Override path to eqlib offsets directory |
| `--dry-run` | Show changes without writing files |
| `--client-date` | Update `__ClientDate` and version strings |

Accepts multiple JSON files. Reads both `results` and `resolved` arrays from each file. Only offsets with `"confidence": "confirmed"` are applied.

### `resolve_missing.py`

Resolves offsets that the scanner couldn't find by cross-referencing found offsets in the new PE binary.

```bash
python resolve_missing.py <scan_results.json> <executable>
                          [-s <signatures.json>] [-o <resolved.json>]
                          [-t <tolerance>]
```

| Flag | Description |
|---|---|
| `-s`, `--signatures` | Signatures JSON (provides offset type info for better classification) |
| `-o`, `--output` | Output file (default: `resolved.json`) |
| `-t`, `--tolerance` | Search tolerance in bytes around predicted address (default: 512) |

**How it works**:

1. Computes separate median deltas for code sections (functions) and data sections (globals) from the found offsets
2. For missing **globals**: predicts new address using data delta, scans the `.text` section for RIP-relative instructions referencing near the predicted address, picks the target closest to prediction
3. For missing **functions**: tries multiple delta candidates from common shift clusters, searches for valid function prologues within a window of each prediction, falls back to CALL cross-reference scanning

**Output** (`resolved.json`):

```json
{
  "deltas": { "code": 8256, "data": 113456, "overall": 8336 },
  "resolved": [
    {
      "name": "__gWorld",
      "confidence": "high",
      "new_address": "0x140EAC4A7",
      "old_address": "0x140E90998",
      "delta": 113935,
      "ref_count": 4,
      "method": "rip_xref"
    }
  ],
  "summary": { "total_missing": 49, "resolved": 49, "still_missing": 0 }
}
```

Review results and change confidence to `"confirmed"` for verified offsets before running `update_headers.py`.

### `generate_offset_table.py`

Regenerates the auto-generated `OffsetTable.h` used by the SigScan plugin at runtime.

```bash
python generate_offset_table.py
```

Run this after `update_headers.py` so the plugin's offset table matches the updated headers.

### `review_offsets.py`

Interactive tool for reviewing ambiguous or low-confidence scan results.

```bash
python review_offsets.py <scan_results.json>
```
