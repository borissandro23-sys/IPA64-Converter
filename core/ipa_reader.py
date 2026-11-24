"""Read IPA metadata and inspect every Mach-O binary without extracting files."""

import plistlib
import zipfile
from pathlib import PurePosixPath

from .macho_parser import MachOError, parse_macho

MAX_ARCHIVE_ENTRIES = 20_000
MAX_INFO_PLIST_SIZE = 8 * 1024 * 1024
MAX_EXECUTABLE_SIZE = 512 * 1024 * 1024
MAX_TOTAL_MACHO_SIZE = 1024 * 1024 * 1024

MACHO_MAGICS = {
    b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE",
    b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
    b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA",
    b"\xCA\xFE\xBA\xBF", b"\xBF\xBA\xFE\xCA",
}


class IPAError(ValueError):
    """Raised when an IPA cannot be safely inspected."""


def _safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in name


def _read_info_plists(archive, entries):
    """Read app/extension/framework bundle metadata, with per-file limits."""
    bundles = []
    for entry in entries:
        name = entry.filename
        if not name.startswith("Payload/") or not name.endswith("/Info.plist"):
            continue
        if entry.file_size > MAX_INFO_PLIST_SIZE:
            continue
        try:
            info = plistlib.loads(archive.read(entry))
        except (plistlib.InvalidFileException, ValueError, OSError, RuntimeError):
            continue
        if isinstance(info, dict):
            bundle_dir = name.rsplit("/", 1)[0]
            executable = info.get("CFBundleExecutable")
            if isinstance(executable, str) and executable and "/" not in executable and "\\" not in executable:
                bundles.append({
                    "bundle_path": bundle_dir,
                    "executable_path": f"{bundle_dir}/{executable}",
                    "bundle_identifier": info.get("CFBundleIdentifier"),
                    "bundle_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
                    "bundle_type": info.get("CFBundlePackageType"),
                })
    return bundles


def inspect_ipa(ipa_path: str) -> dict:
    """Inspect all recognizable Mach-O files in an IPA without extracting or executing them."""
    try:
        archive = zipfile.ZipFile(ipa_path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise IPAError(f"Cannot open IPA: {exc}") from exc

    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise IPAError(f"Archive contains too many entries ({len(entries)})")

        for entry in entries:
            if not _safe_member_name(entry.filename):
                raise IPAError(f"Unsafe archive path: {entry.filename!r}")

        bundles = _read_info_plists(archive, entries)
        app_bundles = [b for b in bundles if b["bundle_path"].endswith(".app")]
        if not app_bundles:
            raise IPAError("No Payload/*.app/Info.plist found")

        # Select the shallowest .app bundle deterministically.
        main_bundle = min(
            app_bundles,
            key=lambda item: (item["bundle_path"].count("/"), item["bundle_path"]),
        )
        main_info_entry = next(
            (e for e in entries if e.filename == main_bundle["bundle_path"] + "/Info.plist"),
            None,
        )
        if main_info_entry is None or main_info_entry.file_size > MAX_INFO_PLIST_SIZE:
            raise IPAError("Main app Info.plist is missing or too large")

        try:
            main_info = plistlib.loads(archive.read(main_info_entry))
        except (plistlib.InvalidFileException, ValueError, OSError, RuntimeError) as exc:
            raise IPAError(f"Cannot read main Info.plist: {exc}") from exc
        if not isinstance(main_info, dict):
            raise IPAError("Main Info.plist root is not a dictionary")

        main_executable = main_bundle["executable_path"]
        entry_by_name = {}
        for entry in entries:
            entry_by_name.setdefault(entry.filename, entry)
        main_entry = entry_by_name.get(main_executable)
        if main_entry is None:
            raise IPAError(f"Main executable not found: {main_executable}")
        if main_entry.file_size > MAX_EXECUTABLE_SIZE:
            raise IPAError("Main executable exceeds the size limit")

        binary_records = []
        total_macho_bytes = 0
        seen_names = set()

        # Prefer bundle-declared executable paths, then inspect any other Mach-O
        # files under Payload (for example loose helper binaries).
        candidate_names = []
        for bundle in bundles:
            candidate_names.append(bundle["executable_path"])
        candidate_names.extend(
            entry.filename for entry in entries
            if entry.filename.startswith("Payload/") and not entry.is_dir()
        )

        for name in candidate_names:
            if name in seen_names:
                continue
            seen_names.add(name)
            entry = entry_by_name.get(name)
            if entry is None or entry.is_dir():
                continue
            if entry.file_size < 4 or entry.file_size > MAX_EXECUTABLE_SIZE:
                continue
            try:
                with archive.open(entry, "r") as member:
                    magic = member.read(4)
                    if magic not in MACHO_MAGICS:
                        continue
                    total_macho_bytes += entry.file_size
                    if total_macho_bytes > MAX_TOTAL_MACHO_SIZE:
                        raise IPAError("Total Mach-O data exceeds the scan limit")
                    data = magic + member.read(entry.file_size - 4)
                architectures = parse_macho(data)
            except IPAError:
                raise
            except (OSError, RuntimeError, zipfile.BadZipFile, MachOError) as exc:
                binary_records.append({
                    "path": name,
                    "size": entry.file_size,
                    "error": str(exc),
                })
                continue

            owning_bundle = next(
                (b for b in bundles if name == b["executable_path"]), None
            )
            binary_records.append({
                "path": name,
                "size": entry.file_size,
                "architectures": architectures,
                "bundle_identifier": owning_bundle["bundle_identifier"] if owning_bundle else None,
                "bundle_type": owning_bundle["bundle_type"] if owning_bundle else None,
                "is_main_executable": name == main_executable,
            })

        main_record = next(
            (item for item in binary_records if item["path"] == main_executable),
            None,
        )
        if main_record is None or "architectures" not in main_record:
            raise IPAError("Main executable is not a recognized Mach-O binary")

        architecture_counts = {}
        linked_libraries = set()
        encryption_records = []
        for binary in binary_records:
            for arch in binary.get("architectures", []):
                label = arch["architecture"]
                architecture_counts[label] = architecture_counts.get(label, 0) + 1
                linked_libraries.update(arch.get("linked_libraries", []))
                if arch.get("encryption") is not None:
                    encryption_records.append({
                        "path": binary["path"],
                        "architecture": label,
                        **arch["encryption"],
                    })

        main_architectures = main_record["architectures"]
        detected_minimum_ios = main_info.get("MinimumOSVersion") or next(
            (arch.get("minimum_os") for arch in main_architectures if arch.get("minimum_os")),
            None,
        )
        detected_sdk = next(
            (arch.get("sdk_version") for arch in main_architectures if arch.get("sdk_version")),
            None,
        )

        return {
            "file": str(ipa_path),
            "bundle_identifier": main_info.get("CFBundleIdentifier"),
            "bundle_name": main_info.get("CFBundleDisplayName") or main_info.get("CFBundleName"),
            "version": main_info.get("CFBundleShortVersionString"),
            "build": main_info.get("CFBundleVersion"),
            "minimum_ios": detected_minimum_ios,
            "sdk_version": detected_sdk,
            "linked_libraries": sorted(linked_libraries),
            "encryption": encryption_records,
            "executable": main_executable,
            "architectures": main_record["architectures"],
            "binary_count": len(binary_records),
            "architecture_counts": architecture_counts,
            "binaries": binary_records,
            "notes": [
                "All recognized Mach-O files under Payload are inspected, including declared bundle executables.",
                "Architecture detection does not guarantee runtime compatibility.",
                "No conversion or modification was performed.",
                "Load commands, linked libraries, SDK versions, minimum OS versions, and encryption flags are read when present.",
                "Encryption flags report Mach-O metadata only; this tool does not decrypt or modify binaries.",
            ],
        }
