"""Read IPA metadata and inspect its main Mach-O executable."""

import plistlib
import zipfile
from pathlib import PurePosixPath

from .macho_parser import MachOError, parse_macho

MAX_ARCHIVE_ENTRIES = 20_000
MAX_INFO_PLIST_SIZE = 8 * 1024 * 1024
MAX_EXECUTABLE_SIZE = 512 * 1024 * 1024


class IPAError(ValueError):
    """Raised when an IPA cannot be safely inspected."""


def _safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and "\\" not in name


def inspect_ipa(ipa_path: str) -> dict:
    """Inspect an IPA without extracting files or executing its contents."""
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

        plist_entries = [
            entry for entry in entries
            if entry.filename.startswith("Payload/")
            and entry.filename.endswith(".app/Info.plist")
        ]
        if not plist_entries:
            raise IPAError("No Payload/*.app/Info.plist found")

        # Select the shallowest app bundle deterministically.
        plist_entry = min(plist_entries, key=lambda item: (item.filename.count("/"), item.filename))
        if plist_entry.file_size > MAX_INFO_PLIST_SIZE:
            raise IPAError("Info.plist exceeds the size limit")

        try:
            info = plistlib.loads(archive.read(plist_entry))
        except (plistlib.InvalidFileException, ValueError, OSError) as exc:
            raise IPAError(f"Cannot read Info.plist: {exc}") from exc

        if not isinstance(info, dict):
            raise IPAError("Info.plist root is not a dictionary")

        executable_name = info.get("CFBundleExecutable")
        if not isinstance(executable_name, str) or not executable_name:
            raise IPAError("CFBundleExecutable is missing or invalid")

        app_directory = plist_entry.filename.rsplit("/", 1)[0]
        executable_path = f"{app_directory}/{executable_name}"
        matches = [entry for entry in entries if entry.filename == executable_path]
        if not matches:
            raise IPAError(f"Main executable not found: {executable_path}")
        executable_entry = matches[0]

        if executable_entry.file_size > MAX_EXECUTABLE_SIZE:
            raise IPAError("Main executable exceeds the size limit")

        try:
            executable_data = archive.read(executable_entry)
            architectures = parse_macho(executable_data)
        except (OSError, RuntimeError, zipfile.BadZipFile, MachOError) as exc:
            raise IPAError(f"Cannot inspect main executable: {exc}") from exc

        return {
            "file": str(ipa_path),
            "bundle_identifier": info.get("CFBundleIdentifier"),
            "bundle_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
            "version": info.get("CFBundleShortVersionString"),
            "build": info.get("CFBundleVersion"),
            "minimum_ios": info.get("MinimumOSVersion"),
            "executable": executable_path,
            "architectures": architectures,
            "notes": [
                "Architecture detection does not guarantee runtime compatibility.",
                "This tool analyzes the main executable only.",
                "No conversion or modification was performed.",
            ],
        }
