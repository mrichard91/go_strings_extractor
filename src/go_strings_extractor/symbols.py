import struct
from pathlib import Path


def parse_nm_main_symbols(binary):
    data = Path(binary).read_bytes()
    if data[:4] == b"\x7fELF":
        return _parse_elf_main_symbols(data)
    if data[:2] == b"MZ":
        return _parse_pe_main_symbols(data)
    return _parse_macho_main_symbols(data)


def select_symbols_to_analyze(syms):
    selected = []
    for a, n in syms:
        clean = n.lstrip("_")
        if not clean.startswith("main."):
            continue
        if clean in ("main..inittask", "main.init"):
            continue
        selected.append((a, n))
    return selected


def _parse_elf_main_symbols(data):
    if len(data) < 0x40:
        return [], "truncated ELF"
    ei_class = data[4]
    ei_data = data[5]
    bo = "<" if ei_data == 1 else ">"
    try:
        if ei_class == 2:
            e_shoff = struct.unpack_from(bo + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(bo + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(bo + "H", data, 0x3C)[0]
        else:
            e_shoff = struct.unpack_from(bo + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(bo + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(bo + "H", data, 0x30)[0]
    except struct.error:
        return [], "truncated ELF header"
    if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
        return [], ""
    if e_shoff + e_shentsize * e_shnum > len(data):
        return [], "invalid ELF section table"

    sec = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        try:
            if ei_class == 2:
                sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_addralign, sh_entsize = struct.unpack_from(
                    bo + "IIQQQQIIQQ", data, off
                )
            else:
                sh_name, sh_type, _sh_flags, sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_addralign, sh_entsize = struct.unpack_from(
                    bo + "IIIIIIIIII", data, off
                )
        except struct.error:
            return [], "truncated ELF section"
        sec.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))

    syms = []
    for (_name_off, sh_type, _addr, sh_offset, sh_size, sh_link, sh_entsize) in sec:
        if sh_type not in (2, 11):  # SYMTAB / DYNSYM
            continue
        if sh_offset <= 0 or sh_size <= 0 or sh_offset + sh_size > len(data):
            continue
        if not (0 <= sh_link < len(sec)):
            continue
        _n2, _t2, _a2, str_off, str_size, _l2, _e2 = sec[sh_link]
        if str_off <= 0 or str_size <= 0 or str_off + str_size > len(data):
            continue
        strtab = data[str_off:str_off + str_size]
        ent = sh_entsize or (24 if ei_class == 2 else 16)
        if ent <= 0:
            continue
        for off in range(sh_offset, sh_offset + sh_size - ent + 1, ent):
            try:
                if ei_class == 2:
                    st_name, st_info, _st_other, _st_shndx, st_value, _st_size = struct.unpack_from(bo + "IBBHQQ", data, off)
                else:
                    st_name, st_value, _st_size, st_info, _st_other, _st_shndx = struct.unpack_from(bo + "IIIBBH", data, off)
            except struct.error:
                continue
            typ = st_info & 0xF
            if typ != 2:  # STT_FUNC
                continue
            if st_name < 0 or st_name >= len(strtab):
                continue
            end = strtab.find(b"\x00", st_name)
            if end < 0:
                end = len(strtab)
            name = strtab[st_name:end].decode("utf-8", errors="replace")
            clean = name.lstrip("_")
            if clean.startswith("main."):
                syms.append((int(st_value), name))
    syms.sort(key=lambda x: x[0])
    return syms, ""


def _parse_macho_main_symbols(data):
    if len(data) < 32:
        return [], "truncated Mach-O"

    # Handle FAT by choosing first slice.
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (0xCAFEBABE, 0xBEBAFECA):
        bo = ">" if magic_le == 0xCAFEBABE else "<"
        arch_size = 20 if magic_le == 0xCAFEBABE else 24
        if len(data) < 8 + arch_size:
            return [], "truncated FAT header"
        if magic_le == 0xCAFEBABE:
            _cputype, _cpusub, off, _size, _align = struct.unpack_from(bo + "IIIII", data, 8)
        else:
            _cputype, _cpusub, off, _size, _align, _res = struct.unpack_from(bo + "IIIIII", data, 8)
        if off <= 0 or off >= len(data):
            return [], "invalid FAT slice offset"
        data = data[off:]

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        bo = "<"
    elif magic in (0xCEFAEDFE, 0xCFFAEDFE):
        bo = ">"
    else:
        return [], ""
    is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
    if is64:
        if len(data) < 32:
            return [], "truncated mach_header_64"
        _magic, _cpu, _sub, _ftype, ncmds, _sizeofcmds, _flags, _res = struct.unpack_from(bo + "IiiIIIII", data, 0)
        off = 32
    else:
        if len(data) < 28:
            return [], "truncated mach_header"
        _magic, _cpu, _sub, _ftype, ncmds, _sizeofcmds, _flags = struct.unpack_from(bo + "IiiIIII", data, 0)
        off = 28

    symoff = nsyms = stroff = strsize = 0
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(bo + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        if cmd == 0x2 and off + 24 <= len(data):  # LC_SYMTAB
            _cmd, _cmdsize, symoff, nsyms, stroff, strsize = struct.unpack_from(bo + "IIIIII", data, off)
            break
        off += cmdsize

    if nsyms <= 0 or symoff <= 0 or stroff <= 0 or stroff + strsize > len(data):
        return [], ""
    strtab = data[stroff:stroff + strsize]
    ent = 16 if is64 else 12
    syms = []
    for i in range(nsyms):
        so = symoff + i * ent
        if so + ent > len(data):
            break
        try:
            if is64:
                n_strx, _n_type, _n_sect, _n_desc, n_value = struct.unpack_from(bo + "IBBHQ", data, so)
            else:
                n_strx, _n_type, _n_sect, _n_desc, n_value = struct.unpack_from(bo + "IBBHI", data, so)
        except struct.error:
            continue
        if n_strx <= 0 or n_strx >= len(strtab):
            continue
        end = strtab.find(b"\x00", n_strx)
        if end < 0:
            end = len(strtab)
        name = strtab[n_strx:end].decode("utf-8", errors="replace")
        clean = name.lstrip("_")
        if clean.startswith("main."):
            syms.append((int(n_value), name))
    syms.sort(key=lambda x: x[0])
    return syms, ""


def _parse_pe_main_symbols(data):
    # COFF symbols are often stripped in Go release binaries; return empty on purpose.
    _ = data
    return [], ""
