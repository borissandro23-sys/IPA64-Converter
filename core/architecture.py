"""Names for CPU types and subtypes found in Mach-O binaries."""

CPU_TYPE_X86 = 7
CPU_TYPE_ARM = 12
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

CPU_NAMES = {
    CPU_TYPE_X86: "i386",
    CPU_TYPE_ARM: "ARM",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM64: "ARM64",
}

# Mach-O subtype values use the low 24 bits for the subtype number.
ARM_SUBTYPES = {
    6: "ARMv6",
    9: "ARMv7",
    11: "ARMv7s",
}
ARM64_SUBTYPES = {
    0: "ARM64",
    2: "ARM64e",
}
X86_SUBTYPES = {
    3: "i386",
}
X86_64_SUBTYPES = {
    3: "x86_64",
}


def describe_architecture(cpu_type: int, cpu_subtype: int) -> str:
    """Return a readable architecture label without guessing unknown values."""
    subtype = cpu_subtype & 0x00FFFFFF

    if cpu_type == CPU_TYPE_ARM:
        return ARM_SUBTYPES.get(subtype, f"ARM (subtype {subtype})")
    if cpu_type == CPU_TYPE_ARM64:
        return ARM64_SUBTYPES.get(subtype, f"ARM64 (subtype {subtype})")
    if cpu_type == CPU_TYPE_X86:
        return X86_SUBTYPES.get(subtype, f"i386 (subtype {subtype})")
    if cpu_type == CPU_TYPE_X86_64:
        return X86_64_SUBTYPES.get(subtype, f"x86_64 (subtype {subtype})")

    return f"Unknown CPU (type {cpu_type}, subtype {subtype})"
