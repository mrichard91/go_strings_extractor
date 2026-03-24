import re


def parse_num_token(tok):
    t = tok.strip().rstrip(",")
    if t.startswith("0x") or t.startswith("0X"):
        try:
            return int(t, 16)
        except ValueError:
            return None
    if re.match(r"^\d+$", t):
        try:
            return int(t, 10)
        except ValueError:
            return None
    return None


def parse_arm64_reg_imm(line, reg):
    s = line.strip().split("//", 1)[0].strip()
    m = re.search(rf"\b(?:orr|mov|movz|movn)\s+{reg},\s*(?:xzr,\s*)?#(0x[0-9a-fA-F]+|\d+)\b", s)
    if not m:
        return None
    return parse_num_token(m.group(1))


def find_call_index(block_lines, start, end, needle):
    for j in range(start, min(end, len(block_lines))):
        s = block_lines[j].strip().split("//", 1)[0].strip()
        if re.search(r"\bbl\s+", s) and needle in s:
            return j
    return None


def parse_block_arm64(block_lines):
    address_refs = []
    immediates = []
    calls = []
    adrp_base = {}
    adr_base = {}

    for idx, ln in enumerate(block_lines):
        s = ln.strip()
        s_nocomment = s.split("//", 1)[0].strip()

        mcall = re.search(r"\bbl\s+([^\s]+)(?:\s+<([^>]+)>)?", s_nocomment)
        if mcall:
            calls.append(mcall.group(2) or mcall.group(1))

        if re.search(r"\b(?:orr|mov|movz|movn)\s+[wx]\d+,\s*(?:xzr,\s*)?#", s_nocomment):
            for hm in re.finditer(r"#(0x[0-9a-fA-F]+|\d+)", s_nocomment):
                v = parse_num_token(hm.group(1))
                if v is not None:
                    immediates.append({"kind": "imm", "hex": hex(v), "value": v})

        m_adrp = re.match(r"^([0-9a-fA-F]+)\s+adrp\s+(x\d+),\s+([^;\s]+)(?:.*?;\s*(0x[0-9a-fA-F]+))?", s)
        if m_adrp:
            reg = m_adrp.group(2)
            base = None
            if m_adrp.group(4):
                base = parse_num_token(m_adrp.group(4))
            if base is None:
                base = parse_num_token(m_adrp.group(3))
            if base is not None:
                adrp_base[reg] = base
            continue

        m_adr = re.match(r"^([0-9a-fA-F]+)\s+adr\s+(x\d+),\s+([^;\s]+)(?:.*?;\s*(0x[0-9a-fA-F]+))?", s)
        if m_adr:
            reg = m_adr.group(2)
            base = None
            if m_adr.group(4):
                base = parse_num_token(m_adr.group(4))
            if base is None:
                base = parse_num_token(m_adr.group(3))
            if base is not None:
                adr_base[reg] = base
            continue

        m_add = re.match(r"^([0-9a-fA-F]+)\s+add\s+(x\d+),\s+(x\d+),\s+#(0x[0-9a-fA-F]+|\d+)", s_nocomment)
        if not m_add:
            continue
        dst = m_add.group(2)
        src = m_add.group(3)
        imm = parse_num_token(m_add.group(4))
        if imm is None:
            continue
        if src in adrp_base:
            target = adrp_base[src] + imm
        elif src in adr_base:
            target = adr_base[src] + imm
        else:
            continue
        strlen = None

        if dst == "x0":
            cj = find_call_index(block_lines, idx + 1, idx + 10, "convTstring")
            if cj is not None:
                for j in range(idx, cj + 1):
                    val = parse_arm64_reg_imm(block_lines[j], "x1")
                    if val is not None and 1 <= val <= 256:
                        strlen = val
                        break

        if strlen is None and dst == "x0":
            cj = find_call_index(block_lines, idx + 1, idx + 10, "net.Dial")
            if cj is not None:
                for j in range(idx, cj + 1):
                    val = parse_arm64_reg_imm(block_lines[j], "x1")
                    if val is not None and 1 <= val <= 64:
                        strlen = val
                        break

        if strlen is None and dst == "x2":
            cj = find_call_index(block_lines, idx + 1, idx + 14, "fmt.Fprintf")
            if cj is not None:
                for j in range(max(idx - 10, 0), cj + 1):
                    val = parse_arm64_reg_imm(block_lines[j], "x3")
                    if val is not None and 1 <= val <= 256:
                        strlen = val
                        break

        if strlen is None:
            for j in range(idx + 1, min(idx + 10, len(block_lines))):
                sj = block_lines[j].strip()
                if "\tbl\t" in sj:
                    break
                if re.search(rf"\bstr\s+{dst},\s+\[sp,\s*#0x[0-9a-fA-F]+\]", sj):
                    for k in range(j + 1, min(j + 6, len(block_lines))):
                        val = parse_arm64_reg_imm(block_lines[k], dst)
                        if val is None:
                            continue
                        if 1 <= val <= 256:
                            sk = block_lines[min(k + 1, len(block_lines) - 1)].strip()
                            if re.search(rf"\bstr\s+{dst},\s+\[sp,\s*#0x[0-9a-fA-F]+\]", sk):
                                strlen = val
                                break
                    if strlen is not None:
                        break

        if strlen is None:
            # Generic fallback when symbolized call names are unavailable:
            # pick a nearby immediate that likely represents string length.
            cands = []
            for j in range(max(0, idx - 4), min(idx + 8, len(block_lines))):
                sj = block_lines[j].strip().split("//", 1)[0].strip()
                if j > idx and re.search(r"\bbl\s+", sj):
                    break
                hm = re.search(r"\b(?:orr|mov|movz|movn)\s+[wx]\d+,\s*(?:xzr,\s*)?#(0x[0-9a-fA-F]+|\d+)\b", sj)
                if not hm:
                    continue
                val = parse_num_token(hm.group(1))
                if val is not None and 1 <= val <= 512:
                    cands.append((abs(j - idx), j, val))
            if cands:
                cands.sort(key=lambda x: (x[0], x[1]))
                strlen = cands[0][2]

        insn = int(m_add.group(1), 16)
        address_refs.append({"va": target, "len": strlen, "xref_va": insn})

    return address_refs, immediates, calls
