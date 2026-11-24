"""Minimal, bounds-checked Mach-O architecture parser.

This module reads headers only. It never loads or executes the inspected binary.
"""

import struct

from .architecture import describe_architecture

# Magic values are compared as raw bytes to avoid host-endianness assumptions.
THIN_MAGICS = {
    b"\xCE\xFA\xED\xFE": ("<", False),  # MH_MAGIC
    b"\xCF\xFA\xED\xFE": ("<", True),   # MH_MAGIC_64
    b"\xFE\xED\xFA\xCE": (">", False),
    b"\xFE\xED\xFA\xCF": (">", True),
}
FAT_MAGICS = {
    b"\xCA\xFE\xBA\xBE": (">", False),  # FAT_MAGIC
    b"\xBE\xBA\xFE\xCA": ("<", False),  # FAT_CIGAM
    b"\xCA\xFE\xBA\xBF": (">", True),   # FAT_MAGIC_64
    b"\xBF\xBA\xFE\xCA": ("<", True),   # FAT_CIGAM_64
}

MAX_FAT_ARCHES = 64


class MachOError(ValueError):
    """Raised when a Mach-O header is malformed or unsupported."""


def _parse_thin(data: bytes, offset: int = 0) -> dict:
    if offset < 0 or offset + 28 > len(data):
        raise MachOError("Mach-O header is truncated")

    magic = data[offset:offset + 4]
    info = THIN_MAGICS.get(magic)
    if info is None:
        raise MachOError("Unrecognized Mach-O magic")

    endian, is_64 = info
    header_size = 32 if is_64 else 28
    if offset + header_size > len(data):
        raise MachOError("Mach-O header is truncated")

    cpu_type, cpu_subtype = struct.unpack_from(endian + "ii", data, offset + 4)
    return {
        "cpu_type": cpu_type,
        "cpu_subtype": cpu_subtype,
        "architecture": describe_architecture(cpu_type, cpu_subtype),
        "format": "Mach-O 64-bit" if is_64 else "Mach-O 32-bit",
    }


def parse_macho(data: bytes) -> list[dict]:
    """Return architecture records for a thin or universal Mach-O binary."""
    if len(data) < 4:
        raise MachOError("File is too small to contain a Mach-O header")

    magic = data[:4]
    if magic in THIN_MAGICS:
        return [_parse_thin(data)]

    fat_info = FAT_MAGICS.get(magic)
    if fat_info is None:
        raise MachOError("Executable is not a recognized Mach-O binary")

    endian, is_64 = fat_info
    if len(data) < 8:
        raise MachOError("Universal Mach-O header is truncated")

    count = struct.unpack_from(endian + "I", data, 4)[0]
    if count == 0 or count > MAX_FAT_ARCHES:
        raise MachOError(f"Invalid universal architecture count: {count}")

    entry_size = 32 if is_64 else 20
    table_end = 8 + count * entry_size
    if table_end > len(data):
        raise MachOError("Universal Mach-O architecture table is truncated")

    results = []
    for index in range(count):
        entry_offset = 8 + index * entry_size
        if is_64:
            cpu_type, cpu_subtype, _offset, _size, _align, _reserved = struct.unpack_from(
                endian + "iiQQII", data, entry_offset
            )
        else:
            cpu_type, cpu_subtype, _offset, _size, _align = struct.unpack_from(
                endian + "iiIII", data, entry_offset
            )

        results.append({
            "cpu_type": cpu_type,
            "cpu_subtype": cpu_subtype,
            "architecture": describe_architecture(cpu_type, cpu_subtype),
            "format": "Universal Mach-O (FAT64)" if is_64 else "Universal Mach-O (FAT)",
        })

    return results
