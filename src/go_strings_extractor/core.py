from pathlib import Path
import re
import hashlib

from .detect import parse_file_type, detect_arch
from .symbols import parse_nm_main_symbols, select_symbols_to_analyze
from .sections import parse_macho_sections, parse_elf_sections, parse_pe_sections, va_to_off
from .native_disasm import disassemble_range
from .pclntab import recover_go_symbols_from_pclntab
from .utils import read_fixed_ascii, read_cstring, dedupe_dicts, printable_ratio
from .analyzers.x86 import parse_block_x86
from .analyzers.arm64 import parse_block_arm64
from .fallback import fallback_strings_arm32


def is_stdlib_call(name):
    n = name.lower()
    std_prefixes = [
        "runtime.", "_runtime.",
        "fmt.", "_fmt.",
        "net.", "_net.",
        "os.", "_os.",
        "syscall.", "_syscall.",
        "reflect.", "_reflect.",
        "time.", "_time.",
        "strings.", "_strings.",
        "bytes.", "_bytes.",
        "sync.", "_sync.",
        "internal/", "_internal/",
    ]
    return any(p in n for p in std_prefixes)


def select_parser(arch):
    if arch in ("x86_64", "386"):
        return parse_block_x86
    if arch == "arm64":
        return parse_block_arm64
    return None


DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9-])"
    r"(?:https?://)?"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z]{2,63}"
    r"(?::\d{2,5})?"
    r"(?:/[a-z0-9._~:/?#@!$&'()*+,;=%-]*)?"
    r"(?![a-z0-9-])"
)

STOP_TOKENS = {
    "github", "google", "golang", "gopkg", "internal", "vendor", "proto",
    "grpc", "runtime", "stdlib", "com", "org", "io", "net", "www",
    "foundation", "frontend", "backend", "service", "client", "server", "api",
}
EXTERNAL_IMPORT_PREFIXES = (
    "github.com/",
    "golang.org/",
    "google.golang.org/",
    "gopkg.in/",
    "go.",
)
VALID_TLDS = {
    "com", "org", "net", "io", "dev", "app", "co", "edu", "gov", "mil",
    "info", "biz", "ai", "us", "uk", "de", "fr", "jp", "ca", "au",
}


def _is_rodata_section(sec):
    sn = (sec.get("sectname") or "").lower()
    sg = (sec.get("segname") or "").lower()
    if sn in (".rodata", "__cstring", "__rodata", ".rdata", ".data.rel.ro"):
        return True
    if "rodata" in sn:
        return True
    if sg == "__text" and sn == "__cstring":
        return True
    return False


def _scan_rodata_domains(blob, sections, image_base=None):
    out = []
    seen = set()
    for s in sections:
        if not _is_rodata_section(s):
            continue
        off = s.get("offset", -1)
        size = s.get("size", 0)
        va = s.get("addr", 0)
        if off < 0 or size <= 0 or off + size > len(blob):
            continue
        text = blob[off: off + size].decode("latin1", errors="ignore")
        for m in DOMAIN_RE.finditer(text):
            val = m.group(0).strip(".,;:()[]{}<>\"'")
            if len(val) < 8:
                continue
            # Skip obvious parser noise and placeholders.
            if "%s" in val or "%d" in val or "{{" in val or "}}" in val:
                continue
            # Keep domains/endpoints only.
            if "." not in val:
                continue
            if val in seen:
                continue
            seen.add(val)
            host = val
            if "://" in host:
                host = host.split("://", 1)[1]
            host = host.split("/", 1)[0]
            host = host.split(":", 1)[0]
            # Mixed-case host labels are often merged string-table artifacts.
            host_is_lower = host.lower() == host
            if host_is_lower:
                rec = {
                    "va": hex(va + m.start()),
                    "offset": off + m.start(),
                    "len_hint": len(val),
                    "string": val,
                    "source": "rodata_scan",
                }
                out.append(rec)

            # If host has 3+ labels, add one-step suffix host (api.app.example.com -> app.example.com).
            labels = host.split(".")
            if len(labels) >= 3:
                suffix = ".".join(labels[1:])
                if suffix not in seen:
                    seen.add(suffix)
                    out.append({
                        "va": hex(va + m.start()),
                        "offset": off + m.start(),
                        "len_hint": len(suffix),
                        "string": suffix,
                        "source": "rodata_scan_suffix",
                    })
    return out


def _extract_namespace_tokens(symbol_names):
    tokens = set()
    for n in symbol_names:
        if "/" not in n:
            continue
        path = n
        for mark in ("(", " ", "\t"):
            i = path.find(mark)
            if i >= 0:
                path = path[:i]
        if "/" not in path:
            continue
        p = path.lower()
        if any(p.startswith(pref) for pref in EXTERNAL_IMPORT_PREFIXES):
            continue
        root = p.split("/", 1)[0]
        if "." in root:
            continue
        if len(root) < 4 or root in STOP_TOKENS or root.isdigit():
            continue
        tokens.add(root)
    return tokens


def _infer_connection_endpoints(blob, sections, symbol_names):
    tokens = _extract_namespace_tokens(symbol_names)
    if not tokens:
        return []
    out = []
    seen = set()
    for rec in _scan_rodata_domains(blob, sections):
        s = rec["string"]
        host = s
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/", 1)[0]
        host = host.split(":", 1)[0]
        host_l = host.lower()
        labels = [x for x in host_l.split(".") if x]
        if len(labels) < 2:
            continue
        tld = labels[-1]
        if tld not in VALID_TLDS:
            continue
        if any(not re.match(r"^[a-z0-9-]{1,63}$", lb) for lb in labels):
            continue
        if any(lb.startswith("-") or lb.endswith("-") for lb in labels):
            continue

        has_signal_token = any(t in labels for t in tokens)
        looks_endpointy = (":" in s) or s.startswith("http://") or s.startswith("https://")
        if not has_signal_token:
            continue

        # Skip obvious concatenation artifacts.
        if any(c.isupper() for c in host):
            continue
        if len(host_l) < 8 or "." not in host_l:
            continue

        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return sorted(out)


def _parse_endpoint_candidate(raw, tokens):
    s = raw.strip(".,;:()[]{}<>\"'")
    if not s:
        return None
    host = s
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    host = host.split(":", 1)[0]
    host_l = host.lower()
    labels = [x for x in host_l.split(".") if x]
    if len(labels) < 2:
        return None
    tld = labels[-1]
    if tld not in VALID_TLDS:
        return None
    if any(not re.match(r"^[a-z0-9-]{1,63}$", lb) for lb in labels):
        return None
    if any(lb.startswith("-") or lb.endswith("-") for lb in labels):
        return None
    if any(c.isupper() for c in host):
        return None
    if tokens and not any(t in labels for t in tokens):
        return None
    return s


def _extract_endpoints_from_ref_string(text, tokens):
    out = set()
    for m in DOMAIN_RE.finditer(text):
        ep = _parse_endpoint_candidate(m.group(0), tokens)
        if ep:
            out.add(ep)
            host = ep
            if "://" in host:
                host = host.split("://", 1)[1]
            host = host.split("/", 1)[0]
            port = ""
            if ":" in host:
                host, port = host.split(":", 1)
            labels = [x for x in host.split(".") if x]
            if len(labels) >= 3:
                suf = ".".join(labels[1:])
                if port:
                    out.add(f"{suf}:{port}")
                out.add(suf)
    return sorted(out)


def _hex(bs):
    return " ".join(f"{b:02x}" for b in bs)


def _esc_yara_string(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == "\"":
            out.append("\\\"")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif 32 <= o <= 126:
            out.append(ch)
        else:
            out.append(f"\\x{o:02x}")
    return "".join(out)


def _build_yara_candidates(binary_path, blob, result, string_func_map):
    sha256 = hashlib.sha256(blob).hexdigest()
    seen = set()
    string_candidates = []
    sid = 0
    for rec in result.get("user_strings", []):
        s = rec.get("string", "")
        if len(s) < 4:
            continue
        off = rec.get("offset", -1)
        if off < 0 or off >= len(blob):
            continue
        sb = s.encode("ascii", errors="ignore")
        if len(sb) < 4:
            continue
        key = (s, rec.get("va"))
        if key in seen:
            continue
        seen.add(key)
        pre = blob[max(0, off - 8):off]
        post = blob[off + len(sb):off + len(sb) + 8]
        sid += 1
        cid = f"s{sid:03d}"
        funcs = sorted(string_func_map.get(s, set()))
        string_candidates.append({
            "id": cid,
            "type": "string",
            "string": s,
            "va": rec.get("va"),
            "offset": off,
            "functions": funcs,
            "yara_text": f"${cid} = \"{_esc_yara_string(s)}\" ascii",
            "yara_hex_context": f"${cid}_ctx = {{ {_hex(pre)} {_hex(sb)} {_hex(post)} }}".strip(),
            "context_before_hex": _hex(pre),
            "context_after_hex": _hex(post),
        })

    const_candidates = []
    cidn = 0
    cseen = set()
    for c in result.get("user_constants", []):
        kind = c.get("kind")
        if kind == "immediate":
            v = int(c.get("value", 0))
            if v < 0x10000000 or v > 0xFFFFFFFF:
                continue
            b = v.to_bytes(4, "little", signed=False)
            key = ("imm", v)
            if key in cseen:
                continue
            cseen.add(key)
            cidn += 1
            ccid = f"c{cidn:03d}"
            const_candidates.append({
                "id": ccid,
                "type": "magic_constant",
                "value_hex": f"0x{v:08x}",
                "size_bytes": 4,
                "why": "32-bit immediate likely used as a semantic constant",
                "yara_hex_little_endian": f"${ccid} = {{ {_hex(b)} }}",
            })
        elif kind == "ascii_immediate":
            s = c.get("value", "")
            if len(s) < 4:
                continue
            b = s.encode("ascii", errors="ignore")
            if len(b) < 4:
                continue
            key = ("ascii", s)
            if key in cseen:
                continue
            cseen.add(key)
            cidn += 1
            ccid = f"c{cidn:03d}"
            const_candidates.append({
                "id": ccid,
                "type": "ascii_immediate",
                "value": s,
                "size_bytes": len(b),
                "why": "inline immediate bytes likely protocol/magic data",
                "yara_hex_little_endian": f"${ccid} = {{ {_hex(b)} }}",
            })

    # Build compact rule templates from the strongest unique candidates.
    top_strings = string_candidates[:12]
    top_consts = const_candidates[:8]
    rule_lines = []
    rule_name = re.sub(r"[^A-Za-z0-9_]+", "_", Path(binary_path).name)
    rule_lines.append(f"rule Auto_{rule_name}_Strings {{")
    rule_lines.append("  meta:")
    rule_lines.append("    generated_by = \"go-strings-extractor --yara\"")
    rule_lines.append(f"    binary_sha256 = \"{sha256}\"")
    rule_lines.append("  strings:")
    for r in top_strings:
        rule_lines.append(f"    {r['yara_text']}")
    for r in top_consts:
        rule_lines.append(f"    {r['yara_hex_little_endian']}")
    rule_lines.append("  condition:")
    pieces = [f"#{r['id']} > 0" for r in top_strings[:4]]
    pieces += [f"#{r['id']} > 0" for r in top_consts[:2]]
    if not pieces:
        pieces = ["false"]
    rule_lines.append("    " + " and ".join(pieces))
    rule_lines.append("}")

    return {
        "binary_sha256": sha256,
        "string_candidates": string_candidates,
        "constant_candidates": const_candidates,
        "rules": [{
            "name": f"Auto_{rule_name}_Strings",
            "rule": "\n".join(rule_lines),
        }],
    }


def analyze_binary(binary_path, include_rodata_fallback=False, include_yara=False):
    binary = Path(binary_path)
    if not binary.exists():
        raise FileNotFoundError(f"binary not found: {binary}")

    fmt, file_desc, ferr = parse_file_type(binary)
    arch = detect_arch(binary, file_desc)
    result = {
        "binary": str(binary),
        "format": fmt,
        "arch": arch,
        "file": file_desc,
        "errors": [e for e in [ferr] if e],
        "main_symbols": [],
        "analyzed_symbols": [],
        "user_strings": [],
        "user_constants": [],
        "call_targets": [],
        "function_strings": [],
        "endpoint_xrefs": [],
        "connection_endpoints": [],
        "yara_candidates": None,
        "notes": [
            "Heuristic extraction from Go string references in main package functions.",
            "Architecture-specific native disassembly parser selected by file metadata.",
        ],
    }

    parse_block = select_parser(arch)
    if parse_block is None:
        if fmt == "pe" and arch == "arm":
            blob = binary.read_bytes()
            result["user_strings"] = fallback_strings_arm32(blob)
            result["errors"].append("ARM32 disassembly parser unavailable on this host; used pattern-based fallback extraction.")
            return result
        result["errors"].append(f"Unsupported architecture parser: {arch}")
        return result

    sections = []
    image_base = None

    if fmt == "macho":
        sections, serr = parse_macho_sections(binary)
        if serr:
            result["errors"].append(serr)
    elif fmt == "elf":
        sections, serr = parse_elf_sections(binary)
        if serr:
            result["errors"].append(serr)
    elif fmt == "pe":
        sections, image_base, serr = parse_pe_sections(binary)
        if serr:
            result["errors"].append(serr)
    else:
        result["errors"].append("Unsupported binary format for disassembly-backed extraction.")
        return result

    syms, nerr = parse_nm_main_symbols(binary)
    if nerr:
        result["errors"].append(nerr)

    symbol_ranges = {}
    all_symbol_names = []
    if sections:
        rec_syms, rerr = recover_go_symbols_from_pclntab(binary, sections)
        if rec_syms:
            all_symbol_names = [r["name"] for r in rec_syms]
            by_name = {n.lstrip("_"): (a, n) for a, n in syms}
            for rec in rec_syms:
                nm = rec["name"]
                if "end" in rec:
                    symbol_ranges[nm] = (rec["start"], rec["end"])
                else:
                    symbol_ranges[nm] = (rec["start"], None)
                if not nm.startswith("main."):
                    continue
                if nm not in by_name:
                    by_name[nm] = (rec["start"], nm)
            syms = sorted(by_name.values(), key=lambda x: x[0])
            result["notes"].append("Recovered/merged function symbols from .gopclntab.")
        elif (not syms) and rerr:
            result["errors"].append(rerr)

    syms_to_analyze = select_symbols_to_analyze(syms)
    result["main_symbols"] = [{"addr": hex(a), "name": n} for a, n in syms]
    result["analyzed_symbols"] = [{"addr": hex(a), "name": n} for a, n in syms_to_analyze]

    if not syms:
        result["errors"].append("No main.* symbols found (nm/gopclntab).")
    if not syms_to_analyze:
        result["errors"].append("No main.* symbols selected for analysis.")
        return result

    blob = binary.read_bytes()
    if not all_symbol_names:
        all_symbol_names = [n.lstrip("_") for _, n in syms]

    # If no pclntab ranges were recovered, infer ranges from symbol ordering.
    if not symbol_ranges and syms:
        ordered = sorted([(a, n.lstrip("_")) for a, n in syms], key=lambda x: x[0])
        for i, (start, nm) in enumerate(ordered):
            end = ordered[i + 1][0] if i + 1 < len(ordered) else None
            symbol_ranges[nm] = (start, end)

    def decode_ref(ref):
        va = ref["va"]
        strlen = ref.get("len")
        off = va_to_off(va, sections, image_base=image_base)
        if off < 0:
            return None
        s = ""
        if strlen and 0 < strlen <= 4096:
            s = read_fixed_ascii(blob, off, strlen)
        if not s and not strlen:
            cand = read_cstring(blob, off)
            if cand and 1 < len(cand) <= 40:
                has_sep = any(ch in cand for ch in " .:/[]()%_-+\n\r\t")
                if (not has_sep) and len(cand) > 12:
                    cand = ""
            if cand and 1 < len(cand) <= 40:
                bad = False
                for ch in cand:
                    o = ord(ch)
                    if ch in ("\n", "\r", "\t"):
                        continue
                    if o < 32 or o > 126:
                        bad = True
                        break
                if not bad:
                    s = cand
        # Go stores strings contiguously without null terminators; a wrong
        # len_hint often pulls in adjacent runtime strings.  Detect and fix
        # the two most common mis-reads.

        # 1) OS name followed by unrelated text (e.g. "windowsfloat32float").
        if s:
            m_os = re.match(r"^(windows|linux|darwin)[a-zA-Z0-9_]+", s)
            if m_os and len(s) > len(m_os.group(1)):
                s = m_os.group(1)

        # 2) Over-read domain/endpoint strings (len_hint grabbed a nearby
        #    constant like a port number instead of the real string length).
        if s and strlen and len(s) > 60:
            # Look for a domain:port or IP:port prefix.
            m_dp = re.match(
                r"^(?:\[[0-9a-fA-F:.]+\]:\d+|[a-zA-Z0-9._-]+\.[a-z]{2,}:\d+)",
                s,
            )
            if m_dp:
                s = m_dp.group(0)
            elif not any(ch in s for ch in (" ", "/", "%", "\n")):
                # Long alphanumeric blob with no separators — likely garbage.
                s = ""

        if s and strlen and s.startswith("[") and "]" not in s:
            cand = read_cstring(blob, off)
            if cand and cand.startswith(s) and "]" in cand and len(cand) <= 96:
                s = cand
        if s and s.startswith("[") and "]:" not in s:
            chunk = blob[off:off + 96].decode("latin1", errors="ignore")
            m = re.match(r"^\[[0-9a-fA-F:.]+\](?::\d+)?", chunk)
            if m and len(m.group(0)) > len(s):
                s = m.group(0)
        if not s:
            return None
        return {"va": hex(va), "offset": off, "len_hint": strlen, "string": s}

    disasm_cache = {}

    def get_body_for_symbol(sym_name):
        key = sym_name.lstrip("_")
        if key in disasm_cache:
            return disasm_cache[key]
        rng = symbol_ranges.get(key)
        if not rng:
            disasm_cache[key] = []
            return []
        start, end = rng
        body = disassemble_range(blob, sections, arch, start, end, image_base=image_base)
        disasm_cache[key] = body
        return body

    def collect_from_symbols(symbol_list):
        addr_refs = []
        imms = []
        calls = []
        func_refs = {}
        for _, sym in symbol_list:
            body = get_body_for_symbol(sym)
            if not body:
                continue
            a, i, c = parse_block(body)
            addr_refs.extend(a)
            imms.extend(i)
            calls.extend(c)
            func_refs.setdefault(sym, []).extend(a)
        return addr_refs, imms, calls, func_refs

    all_addr_refs, all_imms, all_calls, per_func_refs = collect_from_symbols(syms_to_analyze)

    seen_ref = set()
    for ref in all_addr_refs:
        k = (ref["va"], ref.get("len"))
        if k in seen_ref:
            continue
        seen_ref.add(k)
        decoded = decode_ref(ref)
        if decoded:
            result["user_strings"].append(decoded)

    for c in all_imms:
        if c.get("kind") == "movabs":
            s = c.get("ascii_little", "")
            if s and printable_ratio(s.encode("ascii", errors="ignore")) >= 0.7:
                result["user_constants"].append({"kind": "ascii_immediate", "hex": c["hex"], "value": s})
        elif c.get("kind") == "imm":
            v = c.get("value", 0)
            if 2 <= v <= 0xFFFFFFFF:
                result["user_constants"].append({"kind": "immediate", "hex": c["hex"], "value": v})

    dedup_calls = []
    seen = set()
    for c in all_calls:
        if c not in seen:
            seen.add(c)
            dedup_calls.append(c)
    result["call_targets"] = [c for c in dedup_calls if not is_stdlib_call(c)]

    filtered_strings = []
    seen_s = set()
    for rec in result["user_strings"]:
        s = rec["string"]
        if len(s) < 2:
            continue
        if rec.get("len_hint") == 1:
            continue
        if rec.get("len_hint") is None and len(s) > 120:
            continue
        if s in seen_s:
            continue
        seen_s.add(s)
        filtered_strings.append(rec)
    result["user_strings"] = filtered_strings
    result["user_constants"] = dedupe_dicts(result["user_constants"])

    namespace_tokens = _extract_namespace_tokens(all_symbol_names)

    endpoint_symbol_list = []
    if symbol_ranges:
        for nm, rng in symbol_ranges.items():
            nml = nm.lower()
            if nml.startswith("main.") or any((t + "/") in nml for t in namespace_tokens):
                endpoint_symbol_list.append((rng[0], nm))
        endpoint_symbol_list.sort(key=lambda x: x[0])
    else:
        endpoint_symbol_list = list(syms_to_analyze)

    _, _, _, endpoint_func_refs = collect_from_symbols(endpoint_symbol_list)
    endpoint_xrefs = []
    seen_epx = set()
    for fn, refs in endpoint_func_refs.items():
        for ref in refs:
            decoded = decode_ref(ref)
            if not decoded:
                continue
            endpoints = _extract_endpoints_from_ref_string(decoded["string"], namespace_tokens)
            if not endpoints:
                continue
            for ep in endpoints:
                key = (ep, fn, decoded["va"], ref.get("xref_va"))
                if key in seen_epx:
                    continue
                seen_epx.add(key)
                rec = {
                    "endpoint": ep,
                    "function": fn,
                    "string_va": decoded["va"],
                }
                if ref.get("xref_va") is not None:
                    rec["xref_va"] = hex(ref["xref_va"])
                endpoint_xrefs.append(rec)
    result["endpoint_xrefs"] = sorted(endpoint_xrefs, key=lambda x: (x["endpoint"], x["function"], x.get("xref_va", "")))
    result["connection_endpoints"] = sorted({x["endpoint"] for x in endpoint_xrefs})

    # Supplement direct references with domain/endpoint literals from rodata.
    if include_rodata_fallback:
        existing = {x["string"] for x in result["user_strings"]}
        for rec in _scan_rodata_domains(blob, sections, image_base=image_base):
            if rec["string"] in existing:
                continue
            existing.add(rec["string"])
            result["user_strings"].append(rec)
        result["notes"].append("Included optional rodata domain fallback scan.")
        # Optional endpoint fallback only when xrefs miss references.
        if not result["connection_endpoints"]:
            result["connection_endpoints"] = _infer_connection_endpoints(blob, sections, all_symbol_names)
            if result["connection_endpoints"]:
                result["notes"].append("Endpoint fallback inferred from rodata because no endpoint xrefs were found.")

    func_strings = {}
    for fn, refs in per_func_refs.items():
        seen = set()
        for ref in refs:
            decoded = decode_ref(ref)
            if not decoded:
                continue
            s = decoded["string"]
            if len(s) < 2:
                continue
            if s in seen:
                continue
            seen.add(s)
            func_strings.setdefault(fn, []).append(s)
    result["function_strings"] = [
        {"function": fn, "strings": vals}
        for fn, vals in sorted(func_strings.items())
        if vals
    ]

    if include_yara:
        string_func_map = {}
        for rec in result["function_strings"]:
            fn = rec["function"]
            for s in rec["strings"]:
                string_func_map.setdefault(s, set()).add(fn)
        result["yara_candidates"] = _build_yara_candidates(binary_path, blob, result, string_func_map)
        result["notes"].append("Included YARA candidate generation.")

    return result
