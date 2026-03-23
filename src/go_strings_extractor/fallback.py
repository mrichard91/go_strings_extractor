import re


FALLBACK_PATTERNS = [
    rb"Got OS info %s\n",
    rb"connected to: %s\n",
    rb"Error connecting [^:\r\n]{1,64}:",
    rb"Error reading:",
    rb"Error writing:",
    rb"\[[0-9a-fA-F:]{6,}\]:\d{2,5}",
    rb"(?<![A-Za-z0-9.-])[A-Za-z0-9.-]{3,}\.[A-Za-z]{2,}:\d{2,5}(?![A-Za-z0-9.-])",
    rb"[A-Za-z0-9.-]{8,}\.[A-Za-z]{2,}:\d{2,5}",
    rb"(?:GET|POST|PUT|HEAD|OPTIONS|DELETE|PATCH)\s+[^\r\n ]{1,96}\s+HTTP/1\.[01](?:\r?\n){2}",
    rb"tcp6",
    rb"tcp4",
    rb"tcp",
    rb"udp",
    rb"\bwindows\b",
    rb"\blinux\b",
    rb"\bdarwin\b",
]


def fallback_strings_basic(blob):
    # Pattern-focused fallback for environments where native decode is unavailable or too sparse.
    out = []
    seen = set()
    for pattern in FALLBACK_PATTERNS:
        for match in re.finditer(pattern, blob):
            s = match.group(0).decode("ascii", errors="ignore")
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append({"va": None, "offset": match.start(), "len_hint": len(s), "string": s})
    return out


def fallback_strings_arm32(blob):
    return fallback_strings_basic(blob)
