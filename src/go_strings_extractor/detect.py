import struct
from pathlib import Path


def parse_file_type(binary):
    data = Path(binary).read_bytes()
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "elf", "ELF", ""
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe", "PE", ""
    if len(data) >= 4:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA):
            return "macho", "Mach-O", ""
    return "unknown", "unknown", ""


def _detect_elf_arch(data):
    if len(data) < 0x14:
        return "unknown"
    ei_data = data[5]
    bo = "<" if ei_data == 1 else ">"
    e_machine = struct.unpack_from(bo + "H", data, 18)[0]
    if e_machine == 0x3E:
        return "x86_64"
    if e_machine == 0x03:
        return "386"
    if e_machine == 0x28:
        return "arm"
    if e_machine == 0xB7:
        return "arm64"
    return "unknown"


def _detect_pe_arch(data):
    if len(data) < 0x40:
        return "unknown"
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 6 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return "unknown"
    machine = struct.unpack_from("<H", data, pe_off + 4)[0]
    if machine == 0x8664:
        return "x86_64"
    if machine == 0x14C:
        return "386"
    if machine in (0x1C0, 0x1C2, 0x1C4):
        return "arm"
    if machine == 0xAA64:
        return "arm64"
    return "unknown"


def _detect_macho_arch(data):
    if len(data) < 8:
        return "unknown"
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        # Thin parser: pick first arch in FAT header.
        be = ">"
        if magic == 0xBEBAFECA:
            be = "<"
        if len(data) < 12:
            return "unknown"
        cputype = struct.unpack_from(be + "I", data, 8)[0]
    else:
        # thin macho
        if magic in (0xCEFAEDFE, 0xCFFAEDFE):
            bo = ">"
        else:
            bo = "<"
        if len(data) < 8:
            return "unknown"
        cputype = struct.unpack_from(bo + "I", data, 4)[0]
    cpu = cputype & 0x00FFFFFF
    is64 = (cputype & 0x01000000) != 0
    if cpu == 7:
        return "x86_64" if is64 else "386"
    if cpu == 12:
        return "arm64" if is64 else "arm"
    return "unknown"


def detect_arch(binary, file_desc):
    _ = file_desc
    data = Path(binary).read_bytes()
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return _detect_elf_arch(data)
    if len(data) >= 2 and data[:2] == b"MZ":
        return _detect_pe_arch(data)
    return _detect_macho_arch(data)
