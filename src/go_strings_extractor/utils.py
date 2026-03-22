import json


def printable_ratio(bs):
    if not bs:
        return 0.0
    good = 0
    for b in bs:
        if b in (9, 10, 13) or 32 <= b <= 126:
            good += 1
    return good / len(bs)


def read_cstring(blob, off, max_len=256):
    if off < 0 or off >= len(blob):
        return ""
    out = bytearray()
    i = off
    while i < len(blob) and len(out) < max_len:
        b = blob[i]
        if b == 0:
            break
        out.append(b)
        i += 1
    if not out:
        return ""
    if printable_ratio(out) < 0.85:
        return ""
    return out.decode("ascii", errors="replace")


def read_fixed_ascii(blob, off, n):
    if off < 0 or n <= 0 or off + n > len(blob):
        return ""
    bs = blob[off:off + n]
    if printable_ratio(bs) < 0.7:
        return ""
    return bs.decode("ascii", errors="replace")


def dedupe_dicts(items):
    seen = set()
    out = []
    for d in items:
        key = json.dumps(d, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out
