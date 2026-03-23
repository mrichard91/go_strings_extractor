import struct
from pathlib import Path


SUPPORTED_GOPCLNTAB_MAGICS = (0xFFFFFFFB, 0xFFFFFFFA, 0xFFFFFFF0, 0xFFFFFFF1)


def _read_u(blob, off, ptr_size, byteorder):
    if ptr_size == 8:
        return struct.unpack_from(byteorder + "Q", blob, off)[0]
    return struct.unpack_from(byteorder + "I", blob, off)[0]


def _detect_gopclntab_byteorder(blob):
    if len(blob) < 4:
        return None, None
    magic_le = struct.unpack_from("<I", blob, 0)[0]
    if magic_le in SUPPORTED_GOPCLNTAB_MAGICS:
        return "<", magic_le
    magic_be = struct.unpack_from(">I", blob, 0)[0]
    if magic_be in SUPPORTED_GOPCLNTAB_MAGICS:
        return ">", magic_be
    return None, None


def _magic_patterns():
    patterns = []
    for byteorder in ("<", ">"):
        for magic in SUPPORTED_GOPCLNTAB_MAGICS:
            raw = struct.pack(byteorder + "I", magic)
            if raw not in patterns:
                patterns.append(raw)
    return patterns


def _read_cstring(blob, off):
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("utf-8", errors="replace")


def parse_gopclntab_blob(blob, base_va):
    del base_va  # The current parser only needs the raw table contents.

    if len(blob) < 64:
        return [], "gopclntab too small"

    byteorder, magic = _detect_gopclntab_byteorder(blob)
    if byteorder is None:
        got = struct.unpack_from("<I", blob, 0)[0]
        return [], f"unsupported gopclntab magic: {hex(got)}"

    ptr_size = blob[7]
    if ptr_size not in (4, 8):
        return [], f"unsupported pointer size in gopclntab: {ptr_size}"

    try:
        nfunc = _read_u(blob, 8, ptr_size, byteorder)
        text_start = _read_u(blob, 8 + 2 * ptr_size, ptr_size, byteorder)
        funcname_off = _read_u(blob, 8 + 3 * ptr_size, ptr_size, byteorder)
        functab_off = _read_u(blob, 8 + 7 * ptr_size, ptr_size, byteorder)
    except struct.error:
        return [], "truncated gopclntab header"

    if nfunc <= 0 or nfunc > 5_000_000:
        return [], f"invalid nfunc in gopclntab: {nfunc}"

    entry_fmt = byteorder + "II"
    func_fmt = byteorder + "Ii"
    entry_size = struct.calcsize(entry_fmt)
    func_size = struct.calcsize(func_fmt)

    entries = []
    for i in range(nfunc):
        off = functab_off + i * entry_size
        if off + entry_size > len(blob):
            break
        entry_off, func_off = struct.unpack_from(entry_fmt, blob, off)
        foff = functab_off + func_off
        if foff + func_size > len(blob):
            continue
        entry_rel, name_rel = struct.unpack_from(func_fmt, blob, foff)
        name_abs = funcname_off + name_rel
        name = _read_cstring(blob, name_abs)
        if not name:
            continue
        start = int(text_start + entry_rel)
        entries.append({"name": name, "start": start, "source": "gopclntab"})

    if not entries:
        return [], "no functions parsed from gopclntab"

    entries.sort(key=lambda x: x["start"])
    for i in range(len(entries) - 1):
        nxt = entries[i + 1]["start"]
        cur = entries[i]["start"]
        if nxt > cur:
            entries[i]["end"] = nxt
    return entries, ""


def recover_go_symbols_from_pclntab(binary, sections):
    sec = None
    for s in sections:
        name = s.get("sectname", "")
        if name in (".gopclntab", "__gopclntab"):
            sec = s
            break
    blob = Path(binary).read_bytes()
    if sec is None:
        # Fallback scan for pclntab magic when section names are unavailable.
        for magic in _magic_patterns():
            off = 0
            while True:
                idx = blob.find(magic, off)
                if idx < 0:
                    break
                syms, err = parse_gopclntab_blob(blob[idx:], 0)
                if syms:
                    return syms, ""
                off = idx + 1
        return [], "gopclntab section not found"

    off = sec.get("offset", -1)
    size = sec.get("size", 0)
    base = sec.get("addr", 0)
    if off < 0 or size <= 0 or off + size > len(blob):
        return [], "invalid gopclntab section bounds"
    return parse_gopclntab_blob(blob[off: off + size], base)
