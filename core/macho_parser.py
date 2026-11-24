"""Bounds-checked Mach-O architecture and load-command parser.

The parser reads binary metadata only. It never loads or executes inspected code.
"""

import struct

from .architecture import describe_architecture

THIN_MAGICS = {
    b"\xCE\xFA\xED\xFE": ("<", False),
    b"\xCF\xFA\xED\xFE": ("<", True),
    b"\xFE\xED\xFA\xCE": (">", False),
    b"\xFE\xED\xFA\xCF": (">", True),
}
FAT_MAGICS = {
    b"\xCA\xFE\xBA\xBE": (">", False),
    b"\xBE\xBA\xFE\xCA": ("<", False),
    b"\xCA\xFE\xBA\xBF": (">", True),
    b"\xBF\xBA\xFE\xCA": ("<", True),
}

MAX_FAT_ARCHES = 64
MAX_LOAD_COMMANDS = 100_000
MAX_SYMBOLS_TO_REPORT = 5000
MAX_SYMBOL_STRING_TABLE_SIZE = 64 * 1024 * 1024
LOAD_COMMAND_NAMES = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB",
    0xE: "LC_LOAD_DYLINKER",
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0x18: "LC_LOAD_WEAK_DYLIB",
    0x1B: "LC_RPATH",
    0x1D: "LC_CODE_SIGNATURE",
    0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO",
    0x23: "LC_DYLD_INFO_ONLY",
    0x25: "LC_VERSION_MIN_IPHONEOS",
    0x2: "LC_SYMTAB",
    0x2C: "LC_ENCRYPTION_INFO_64",
    0x32: "LC_BUILD_VERSION",
    0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x8000001C: "LC_RPATH",
}
PLATFORMS = {1: "MACOS", 2: "IOS", 3: "TVOS", 4: "WATCHOS", 6: "MACCATALYST", 7: "IOSSIMULATOR"}


class MachOError(ValueError):
    """Raised when a Mach-O header or load-command table is malformed."""


def _version(value: int) -> str:
    return f"{(value >> 16) & 0xffff}.{(value >> 8) & 0xff}.{value & 0xff}"


def _parse_thin(data: bytes, offset: int = 0, slice_end: int | None = None) -> dict:
    end = len(data) if slice_end is None else min(slice_end, len(data))
    if offset < 0 or offset + 28 > end:
        raise MachOError("Mach-O header is truncated")

    info = THIN_MAGICS.get(data[offset:offset + 4])
    if info is None:
        raise MachOError("Unrecognized Mach-O magic")
    endian, is_64 = info
    header_size = 32 if is_64 else 28
    if offset + header_size > end:
        raise MachOError("Mach-O header is truncated")

    cpu_type, cpu_subtype = struct.unpack_from(endian + "ii", data, offset + 4)
    _filetype, ncmds, sizeofcmds = struct.unpack_from(endian + "III", data, offset + 12)
    commands_start = offset + header_size
    commands_end = commands_start + sizeofcmds
    if ncmds > MAX_LOAD_COMMANDS or commands_end > end:
        raise MachOError("Invalid or truncated Mach-O load-command table")

    commands = []
    linked_libraries = []
    min_ios = None
    sdk_version = None
    encryption = None
    symtab = None
    cursor = commands_start

    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise MachOError("Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > commands_end:
            raise MachOError("Invalid Mach-O load-command size")

        command = {"name": LOAD_COMMAND_NAMES.get(cmd, f"UNKNOWN_0x{cmd:08X}"), "size": cmdsize}
        base_cmd = cmd & 0x7fffffff

        if base_cmd in (0xC, 0x18, 0x1F, 0x8000001F, 0x80000023, 0x8000001C):
            if cmdsize >= 24:
                name_offset = struct.unpack_from(endian + "I", data, cursor + 8)[0]
                if 8 <= name_offset < cmdsize:
                    raw = data[cursor + name_offset:cursor + cmdsize].split(b"\0", 1)[0]
                    try:
                        library = raw.decode("utf-8", errors="replace")
                    except Exception:
                        library = ""
                    if library:
                        command["name"] = LOAD_COMMAND_NAMES.get(cmd, "LC_LOAD_DYLIB")
                        command["library"] = library
                        if base_cmd != 0x1F:
                            linked_libraries.append(library)

        if cmd == 0x2 and cmdsize >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, cursor + 8)
            symtab = {
                "symbol_offset": symoff,
                "symbol_count": nsyms,
                "string_table_offset": stroff,
                "string_table_size": strsize,
            }

        if cmd == 0x25 and cmdsize >= 16:
            version, sdk = struct.unpack_from(endian + "II", data, cursor + 8)
            min_ios, sdk_version = _version(version), _version(sdk)
            command["minimum_os"] = min_ios
            command["sdk"] = sdk_version
        elif cmd == 0x32 and cmdsize >= 24:
            platform, minimum, sdk, _tools = struct.unpack_from(endian + "IIII", data, cursor + 8)
            command["platform"] = PLATFORMS.get(platform, f"UNKNOWN_{platform}")
            command["minimum_os"] = _version(minimum)
            command["sdk"] = _version(sdk)
            if platform == 2:
                min_ios, sdk_version = command["minimum_os"], command["sdk"]
        elif cmd in (0x21, 0x2C) and cmdsize >= 20:
            cryptid = struct.unpack_from(endian + "I", data, cursor + 16)[0]
            encryption = {"encrypted": cryptid != 0, "cryptid": cryptid}
            command["encryption"] = encryption

        commands.append(command)
        cursor += cmdsize

    return {
        "cpu_type": cpu_type,
        "cpu_subtype": cpu_subtype,
        "architecture": describe_architecture(cpu_type, cpu_subtype),
        "format": "Mach-O 64-bit" if is_64 else "Mach-O 32-bit",
        "load_commands": commands,
        "linked_libraries": sorted(set(linked_libraries)),
        "minimum_os": min_ios,
        "sdk_version": sdk_version,
        "encryption": encryption,
        "symbol_table": _parse_symbol_table(data, offset, end, endian, is_64, symtab),
    }


def _parse_symbol_table(data, slice_offset, slice_end, endian, is_64, symtab):
    """Read a bounded subset of nlist entries and recover Objective-C class names."""
    if symtab is None:
        return None

    symbol_count = symtab["symbol_count"]
    symbol_offset = symtab["symbol_offset"]
    string_offset = symtab["string_table_offset"]
    string_size = symtab["string_table_size"]
    entry_size = 16 if is_64 else 12

    if string_size > MAX_SYMBOL_STRING_TABLE_SIZE:
        raise MachOError("Mach-O symbol string table exceeds the size limit")
    if symbol_count > (slice_end - slice_offset) // entry_size:
        raise MachOError("Mach-O symbol count is outside the binary slice")

    symbol_bytes = symbol_count * entry_size
    absolute_symbols = slice_offset + symbol_offset
    absolute_strings = slice_offset + string_offset
    if (absolute_symbols < slice_offset or absolute_symbols + symbol_bytes > slice_end
            or absolute_strings < slice_offset or absolute_strings + string_size > slice_end):
        raise MachOError("Mach-O symbol or string table is outside the binary slice")

    strings = data[absolute_strings:absolute_strings + string_size]
    symbols = []
    objc_classes = set()
    parsed_count = min(symbol_count, MAX_SYMBOLS_TO_REPORT)

    for index in range(parsed_count):
        entry = absolute_symbols + index * entry_size
        strx, n_type, n_sect, n_desc = struct.unpack_from(endian + "IBBH", data, entry)
        n_value = struct.unpack_from(endian + ("Q" if is_64 else "I"), data, entry + 8)[0]

        if strx >= len(strings):
            continue
        name_bytes = strings[strx:].split(bytes([0]), 1)[0]
        if not name_bytes:
            continue
        name = name_bytes.decode("utf-8", errors="replace")
        symbols.append({
            "name": name,
            "type": n_type,
            "section": n_sect,
            "description": n_desc,
            "value": n_value,
        })

        for marker in ("OBJC_CLASS_$_", "OBJC_METACLASS_$_"):
            if marker in name:
                class_name = name.split(marker, 1)[1]
                if class_name:
                    objc_classes.add(class_name)

    return {
        "declared_symbol_count": symbol_count,
        "reported_symbol_count": len(symbols),
        "truncated": symbol_count > MAX_SYMBOLS_TO_REPORT,
        "objc_classes": sorted(objc_classes),
        "symbols": symbols,
    }


def parse_macho(data: bytes) -> list[dict]:
    """Return architecture and load-command records for thin or universal Mach-O."""
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
    if 8 + count * entry_size > len(data):
        raise MachOError("Universal Mach-O architecture table is truncated")

    results = []
    for index in range(count):
        entry_offset = 8 + index * entry_size
        if is_64:
            cpu_type, cpu_subtype, slice_offset, slice_size, _align, _reserved = struct.unpack_from(
                endian + "iiQQII", data, entry_offset
            )
        else:
            cpu_type, cpu_subtype, slice_offset, slice_size, _align = struct.unpack_from(
                endian + "iiIII", data, entry_offset
            )
        if slice_offset > len(data) or slice_size > len(data) - slice_offset:
            raise MachOError("Universal Mach-O slice is outside the file")

        details = _parse_thin(data, slice_offset, slice_offset + slice_size)
        if details["cpu_type"] != cpu_type or details["cpu_subtype"] != cpu_subtype:
            raise MachOError("Universal Mach-O slice header does not match its architecture table")
        details["format"] = "Universal Mach-O (FAT64)" if is_64 else "Universal Mach-O (FAT)"
        results.append(details)

    return results
