# IPA64-Converter

IPA64-Converter is an IPA inspection and binary-porting research tool. It reads an iOS IPA without extracting or executing its contents, inspects bundle metadata, and detects CPU architectures in Mach-O binaries.

> The current version analyzes binaries. It does not translate ARMv6/ARMv7 machine instructions into ARM64 or produce a runnable converted app.

## Current features

- Read IPA files without extracting or executing their contents.
- Read the main app Info.plist and locate CFBundleExecutable.
- Find declared executable files in app bundles, extensions, and frameworks.
- Scan Payload for additional recognizable Mach-O files.
- Detect thin Mach-O and universal (FAT/FAT64) binaries.
- Recognize ARMv6, ARMv7, ARMv7s, ARM64, ARM64e, i386, and x86_64.
- Produce a JSON report with each binary's path, size, architecture list, and bundle metadata.
- Apply archive entry, path, per-binary, and total-scan size limits.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run on Windows

Open a terminal in the project folder:

```powershell
py -3 main.py "C:\path\to\Example.ipa" --output report.json
```

The report is also printed to the terminal. The original IPA is never modified.

## Project layout

```
core/
  architecture.py   CPU type and subtype names
  macho_parser.py   Mach-O header inspection
  ipa_reader.py     IPA metadata and all-Mach-O scanning
gui.py              Tkinter desktop interface
main.py             Command-line interface
```

## Porting research and limitations

ARMv6/ARMv7 machine code cannot be made ARM64 by changing a Mach-O header or relabeling the CPU type. The instruction sets, calling conventions, register model, and binary interfaces differ. A genuine port normally needs source code and compatible dependencies, or substantial function-by-function reverse engineering and reimplementation.

This project is being developed in stages:
1. Inventory every Mach-O executable and its architecture.
2. Inspect load commands, linked libraries, symbols, and encryption status.
3. Identify code and dependencies that would need replacement for an ARM64 build.
4. Only then evaluate whether parts can be automated safely.

Architecture detection does not prove compatibility with a particular iOS release. Simulator architectures (i386 and x86_64) are not executable architectures for physical iPhones. ARM64e is reported separately when the Mach-O subtype identifies it. The tool does not bypass code signing, DRM, encryption, or platform security.
