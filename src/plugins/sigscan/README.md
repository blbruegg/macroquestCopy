# MQ2SigScan

A MacroQuest plugin that automatically generates and scans byte-pattern signatures for EverQuest memory offsets. When EQ updates and all known addresses shift, SigScan helps developers find where those offsets moved in the new build.

## How It Works

1. **Generate** signatures from current known-good offsets (defined in `OffsetTable.h`)
2. **Scan** a new EQ build using those signatures to locate the updated addresses
3. **Report** results showing which offsets were found, which were missed, and the overall address delta

Signatures are byte patterns with wildcards for bytes that change between builds (relocations, relative branches, large immediates). The plugin uses the Zydis x86-64 disassembler to understand instruction structure and wildcard only the necessary bytes.

### Signature Types

- **Function signatures** -- built by disassembling the first N bytes of a function, wildcarding RIP-relative displacements and relative call/jump targets.
- **Global signatures** -- built by finding code that references the global via RIP-relative addressing, then capturing the surrounding instruction context.

## Commands

The plugin registers a single command with three subcommands:

### `/sigscan generate`

Generates signature JSON files from the currently loaded offsets across all three EQ modules (EQGame, EQMain, EQGraphics). Output is written to the `signatures/` directory next to the executable.

### `/sigscan scan`

Loads signature JSON files from `signatures/` and scans the running process. Produces `scan_results.json` (per-offset results with new addresses) and `scan_report.txt` (human-readable summary).

If the initial scan fails on some offsets but succeeds on enough others, a delta-guided fallback pass uses the median address shift to predict and verify missing offsets.

### `/sigscan report`

Prints the last scan report to the MacroQuest chat window.

## Typical Workflow

```
# On a known-good EQ build, generate signatures:
/sigscan generate

# After EQ patches, scan the new build:
/sigscan scan

# View results:
/sigscan report
```

## Updating Offsets After a Scan

After scanning a new EQ build, use the Python tools in `tools/offsetfinder/` to apply the results. See `tools/offsetfinder/README.md` for the full workflow, including resolving offsets that the initial scan missed.

## Standalone CLI

The `cli/` subdirectory contains a standalone command-line tool (`SigScanCLI.exe`) that can scan PE executables on disk without injecting into a running process. Useful for offline/automated processing.

### Generate Signatures

Before EQ patches, generate signatures from a known-good binary and its offset header:

```
SigScanCLI.exe generate eqgame.exe eqgame.h --output signatures_eqgame.json
```

The header must define offsets in `#define SomeName_x 0xADDRESS` format. The tool also reads `__ClientDate` from the header to tag the signature set.

### Scan a Patched Binary

After EQ patches, scan the new executable using the previously generated signatures:

```
SigScanCLI.exe scan signatures_eqgame.json eqgame_new.exe --output results.json
```

If the initial scan misses some offsets but finds enough others, a delta-guided fallback pass uses the median address shift to locate the remaining ones.

### View Report

```
SigScanCLI.exe report results.json
```

### Update Offset Headers

Use the Python tools in `tools/offsetfinder/` to apply scan results. See `tools/offsetfinder/README.md` for the full workflow including resolving missing offsets.

## Files

| File | Purpose |
|---|---|
| `MQ2SigScan.cpp` | Plugin entry point and `/sigscan` command handler |
| `SigGen.cpp/h` | Signature generation from known offsets |
| `SigScan.cpp/h` | Signature scanning engine |
| `Report.cpp/h` | Result reporting and formatting |
| `OffsetTable.h` | Auto-generated offset database (~300+ entries) |
| `PatternFormat.h` | IDA-style pattern parsing/serialization |
| `ZydisHelper.h` | Zydis disassembler wrapper |
| `cli/` | Standalone PE-based scanner |
