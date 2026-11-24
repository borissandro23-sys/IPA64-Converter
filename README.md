# IPA64-Converter

IPA64-Converter is an **IPA inspection tool**. The first version reads an iOS IPA, locates its main executable, detects Mach-O architectures, and writes a JSON report.

> This project does not convert ARMv7 machine code into ARM64. A real 32-bit-to-64-bit port generally requires source code, compatible dependencies, and a new build.

## Current MVP

- Read IPA files without extracting or executing their contents.
- Read `Info.plist` and locate `CFBundleExecutable`.
- Detect thin Mach-O and universal (FAT/FAT64) binaries.
- Recognize ARMv6, ARMv7, ARMv7s, ARM64, ARM64e, i386, and x86_64.
- Report unknown CPU types instead of guessing.
- Apply basic archive size and path checks.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run on Windows

Open a terminal in the project folder:

```powershell
py -3 main.py "C:\path\to\Example.ipa" --output report.json
```

If the `py` launcher is unavailable:

```powershell
python main.py "C:\path\to\Example.ipa" --output report.json
```

The report is also printed to the terminal. The original IPA is never modified.

## Project layout

```
core/
  architecture.py   CPU type and subtype names
  macho_parser.py   Mach-O header inspection
  ipa_reader.py     IPA/ZIP and Info.plist inspection
main.py             Command-line interface
```

## Limitations

- Architecture detection does not prove that an app is compatible with a particular iOS release.
- Simulator architectures (i386 and x86_64) are not executable architectures for physical iPhones.
- ARM64e is reported separately when the Mach-O subtype identifies it. Many ARM64 apps can still run on ARM64e devices.
- Some apps contain multiple executables, frameworks, extensions, or encrypted/protected components. This MVP inspects the main app executable only.
- The tool does not bypass code signing, DRM, encryption, or platform security.

## Roadmap

1. Add tests and inspect nested frameworks/extensions.
2. Add compatibility hints for selected iOS/device targets.
3. Build an iPhone interface and a repeatable IPA build workflow.
