import re


def fallback_strings_arm32(blob):
    # Pattern-focused fallback for environments where ARM32 disassembly is unavailable/unreliable.
    patterns = [
        rb"Got OS info %s\n",
        rb"connected to: %s\n",
        rb"Error connecting [^:\n]{1,32}:",
        rb"Error reading:",
        rb"Error writing:",
        rb"\[[0-9a-fA-F:]{6,}\]:\d{2,5}",
        rb"(?<![a-z0-9.-])[a-z0-9.-]{3,}\.[a-z]{2,}:\d{2,5}(?![a-z0-9.-])",
        rb"GET /[^\r\n ]{0,64} HTTP/1\.[01]\n\n",
        rb"tcp6",
        rb"tcp4",
        rb"tcp",
        rb"udp",
        rb"\bwindows\b",
        rb"\blinux\b",
        rb"\bdarwin\b",
    ]

    out = []
    seen = set()
    for p in patterns:
        for m in re.finditer(p, blob):
            s = m.group(0).decode("ascii", errors="ignore")
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append({"va": None, "offset": m.start(), "len_hint": len(s), "string": s})
    return out
