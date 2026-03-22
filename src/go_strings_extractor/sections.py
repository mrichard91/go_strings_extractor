import struct
from pathlib import Path


def parse_macho_sections(binary):
    data = Path(binary).read_bytes()
    if len(data) < 32:
        return [], "truncated Mach-O"

    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (0xCAFEBABE, 0xBEBAFECA):
        # FAT Mach-O: parse first slice.
        bo = ">" if magic_le == 0xCAFEBABE else "<"
        if len(data) < 8:
            return [], "truncated FAT header"
        nfat = struct.unpack_from(bo + "I", data, 4)[0]
        if nfat <= 0:
            return [], "invalid FAT arch count"
        arch_size = 20 if magic_le == 0xCAFEBABE else 24
        if len(data) < 8 + arch_size:
            return [], "truncated FAT arch table"
        if magic_le == 0xCAFEBABE:
            _cputype, _cpusub, off, _size, _align = struct.unpack_from(bo + "IIIII", data, 8)
        else:
            _cputype, _cpusub, off, _size, _align, _res = struct.unpack_from(bo + "IIIIII", data, 8)
        if off <= 0 or off >= len(data):
            return [], "invalid FAT slice offset"
        data = data[off:]
        if len(data) < 32:
            return [], "truncated FAT Mach-O slice"

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (0xFEEDFACE, 0xFEEDFACF):
        bo = "<"
    elif magic in (0xCEFAEDFE, 0xCFFAEDFE):
        bo = ">"
    else:
        return [], "not a Mach-O file"

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

    sections = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(bo + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break

        if (is64 and cmd == 0x19) or ((not is64) and cmd == 0x1):
            if is64:
                if off + 72 > len(data):
                    break
                _cmd, _cmdsize, segname_raw, _vmaddr, _vmsize, _fileoff, _filesize, _maxprot, _initprot, nsects, _flags = struct.unpack_from(
                    bo + "II16sQQQQiiII", data, off
                )
                sec_off = off + 72
                sec_size = 80
                fmt = bo + "16s16sQQIIIIIIII"
            else:
                if off + 56 > len(data):
                    break
                _cmd, _cmdsize, segname_raw, _vmaddr, _vmsize, _fileoff, _filesize, _maxprot, _initprot, nsects, _flags = struct.unpack_from(
                    bo + "II16sIIIIiiII", data, off
                )
                sec_off = off + 56
                sec_size = 68
                fmt = bo + "16s16sIIIIIIIII"

            for i in range(nsects):
                so = sec_off + i * sec_size
                if so + sec_size > off + cmdsize or so + sec_size > len(data):
                    break
                vals = struct.unpack_from(fmt, data, so)
                sectname = vals[0].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                segname = vals[1].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                addr = int(vals[2])
                size = int(vals[3])
                offset = int(vals[4])
                if size <= 0:
                    continue
                sections.append({
                    "sectname": sectname,
                    "segname": segname,
                    "addr": addr,
                    "offset": offset,
                    "size": size,
                })

        off += cmdsize

    if not sections:
        return [], "no Mach-O sections parsed"
    return sections, ""


def parse_elf_sections(binary):
    data = Path(binary).read_bytes()
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return [], "not an ELF file"

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        return [], "unsupported ELF class"
    if ei_data not in (1, 2):
        return [], "unsupported ELF endianness"
    bo = "<" if ei_data == 1 else ">"

    try:
        if ei_class == 2:
            e_shoff = struct.unpack_from(bo + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(bo + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(bo + "H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(bo + "H", data, 0x3E)[0]
        else:
            e_shoff = struct.unpack_from(bo + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(bo + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(bo + "H", data, 0x30)[0]
            e_shstrndx = struct.unpack_from(bo + "H", data, 0x32)[0]
    except struct.error:
        return [], "truncated ELF header"

    if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
        return [], "ELF has no section table"
    if e_shoff + e_shentsize * e_shnum > len(data):
        return [], "invalid ELF section table bounds"

    raw_secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        try:
            if ei_class == 2:
                sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, _sh_entsize = struct.unpack_from(
                    bo + "IIQQQQIIQQ", data, off
                )
            else:
                sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size, _sh_link, _sh_info, _sh_addralign, _sh_entsize = struct.unpack_from(
                    bo + "IIIIIIIIII", data, off
                )
        except struct.error:
            return [], "truncated ELF section header"
        raw_secs.append({"name_off": sh_name, "addr": int(sh_addr), "offset": int(sh_offset), "size": int(sh_size)})

    if not (0 <= e_shstrndx < len(raw_secs)):
        return [], "invalid ELF shstrndx"
    shstr = raw_secs[e_shstrndx]
    if shstr["offset"] + shstr["size"] > len(data):
        return [], "invalid ELF shstrtab bounds"
    shstr_blob = data[shstr["offset"]: shstr["offset"] + shstr["size"]]

    def sec_name(name_off):
        if name_off < 0 or name_off >= len(shstr_blob):
            return ""
        end = shstr_blob.find(b"\x00", name_off)
        if end < 0:
            end = len(shstr_blob)
        return shstr_blob[name_off:end].decode("ascii", errors="replace")

    sections = []
    for s in raw_secs:
        if s["size"] <= 0:
            continue
        if s["offset"] + s["size"] > len(data):
            continue
        sections.append({
            "sectname": sec_name(s["name_off"]),
            "segname": "",
            "addr": s["addr"],
            "offset": s["offset"],
            "size": s["size"],
        })
    return sections, ""


def parse_pe_sections(binary):
    data = Path(binary).read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        return [], None, "not a PE file"
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            return [], None, "invalid PE signature"
        coff_off = pe_off + 4
        _machine, num_sections, _time, _ptrsym, _numsym, size_opt, _chars = struct.unpack_from("<HHIIIHH", data, coff_off)
        opt_off = coff_off + 20
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic == 0x20B:
            image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        elif magic == 0x10B:
            image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        else:
            image_base = None
        sec_off = opt_off + size_opt
    except struct.error:
        return [], None, "truncated PE header"

    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        raw_name = data[off:off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        size = max(virtual_size, raw_size)
        if size <= 0:
            continue
        sections.append({
            "sectname": name,
            "segname": "",
            "addr": int(virtual_addr),
            "offset": int(raw_ptr),
            "size": int(size),
            "raw_size": int(raw_size),
            "virtual_size": int(virtual_size),
        })
    return sections, image_base, ""


def va_to_off(va, sections, image_base=None):
    # PE may present absolute VAs (image_base + RVA) or RVAs; normalize both.
    candidates = [va]
    if image_base is not None and va >= image_base:
        candidates.append(va - image_base)

    for cand in candidates:
        for s in sections:
            a = s.get("addr", -1)
            z = s.get("size", 0)
            o = s.get("offset", -1)
            if a <= cand < a + z and o >= 0:
                return o + (cand - a)
    return -1
