import re


def parse_block_x86(block_lines):
    address_refs = []
    immediates = []
    calls = []
    for idx, ln in enumerate(block_lines):
        s = ln.strip()
        s_asm = s.split("#", 1)[0].rstrip()

        mcall = re.search(r"call[lq]?\s+([^\s]+)$", s_asm)
        if mcall:
            calls.append(mcall.group(1))

        mm = re.search(r"movabsq\s+\$0x([0-9a-fA-F]+),", s_asm)
        if mm:
            hv = mm.group(1)
            val = int(hv, 16)
            bs = val.to_bytes((val.bit_length() + 7) // 8 or 1, "little")
            immediates.append({"kind": "movabs", "hex": "0x" + hv, "ascii_little": bs.decode("ascii", errors="replace")})

        if ", %" in s_asm and "(%rsp)" not in s_asm and "(%rbp)" not in s_asm and "(%esp)" not in s_asm and "(%ebp)" not in s_asm:
            for hm in re.finditer(r"\$0x([0-9a-fA-F]+)", s_asm):
                immediates.append({"kind": "imm", "hex": "0x" + hm.group(1), "value": int(hm.group(1), 16)})

        m = re.match(
            r"^([0-9a-fA-F]+)\s+lea[lq]?\s+([+-]?0x[0-9a-fA-F]+)\(%(?:rip|eip)\),\s+%([a-z0-9]+)(?:\s*;\s*0x([0-9a-fA-F]+))?",
            s_asm,
        )
        if m:
            insn = int(m.group(1), 16)
            reg = m.group(3)
            if m.group(4):
                target = int(m.group(4), 16)
            else:
                disp = int(m.group(2), 16)
                # Sign-extend 32-bit displacement for negative RIP-relative offsets.
                if disp >= 0x80000000:
                    disp -= 0x100000000
                # x86/x64 REX-prefixed lea [rip+disp32] is 7 bytes.
                target = insn + 7 + disp
            strlen = None

            for j in range(idx + 1, min(idx + 8, len(block_lines) - 1)):
                sj = block_lines[j].strip()
                if "call" in sj:
                    break
                if re.search(rf"mov[lq]\s+%{reg},\s+0x[0-9a-fA-F]+\(%(?:rsp|esp)\)", sj):
                    sj2 = block_lines[j + 1].strip()
                    hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+0x[0-9a-fA-F]+\(%(?:rsp|esp)\)", sj2)
                    if hm:
                        val = int(hm.group(1), 16)
                        if 1 <= val <= 256:
                            strlen = val
                            break

            if strlen is None:
                conv_j = None
                for j in range(idx + 1, min(idx + 10, len(block_lines))):
                    if "call" in block_lines[j] and "convTstring" in block_lines[j]:
                        conv_j = j
                        break
                has_conv = conv_j is not None
                if reg in ("rax", "eax") and has_conv:
                    for j in range(conv_j, idx - 1, -1):
                        sj = block_lines[j].strip()
                        hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+%(?:ebx|rbx)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 256:
                                strlen = val
                                break

            if strlen is None:
                has_fprintf = any(("call" in block_lines[j] and "fmt.Fprintf" in block_lines[j]) for j in range(idx + 1, min(idx + 12, len(block_lines))))
                if reg in ("rcx", "ecx") and has_fprintf:
                    for j in range(idx, max(0, idx - 12) - 1, -1):
                        sj = block_lines[j].strip()
                        hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+%(?:edi|rdi)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 256:
                                strlen = val
                                break

            if strlen is None and reg in ("eax", "rax", "ebx", "rbx", "ecx", "rcx", "edx", "rdx"):
                has_dial = any(("call" in block_lines[j] and "net.Dial" in block_lines[j]) for j in range(idx + 1, min(idx + 12, len(block_lines))))
                if has_dial:
                    if reg in ("rax", "eax"):
                        for j in range(min(idx + 7, len(block_lines) - 1), max(0, idx - 6) - 1, -1):
                            sj = block_lines[j].strip()
                            hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+%(?:ebx|rbx)", sj)
                            if hm:
                                val = int(hm.group(1), 16)
                                if 1 <= val <= 64:
                                    strlen = val
                                    break
                    if strlen is not None:
                        address_refs.append({"va": target, "len": strlen})
                        continue
                    for j in range(idx, min(idx + 12, len(block_lines))):
                        sj = block_lines[j].strip()
                        hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+0x[0-9a-fA-F]+\(%(?:esp|rsp)\)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 64:
                                strlen = val
                                break

            if strlen is None:
                # Generic nearby immediate-length hint used by many non-main callsites,
                # e.g. pointer in %rsi with length in %r8d before a call.
                cands = []
                for j in range(idx + 1, min(idx + 6, len(block_lines))):
                    sj = block_lines[j].strip()
                    if "call" in sj:
                        break
                    hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+%([a-z0-9]+)", sj)
                    if not hm:
                        continue
                    val = int(hm.group(1), 16)
                    r2 = hm.group(2)
                    if r2 not in ("rbx", "ebx", "rdi", "edi", "r8d", "r9d", "r10d", "rcx", "ecx", "rdx", "edx"):
                        continue
                    if 1 <= val <= 1024:
                        cands.append(val)
                if cands:
                    strlen = max(cands)

            if strlen is None:
                # Also check immediate lengths loaded shortly before the LEA.
                cands = []
                for j in range(max(0, idx - 10), idx + 1):
                    sj = block_lines[j].strip()
                    hm = re.search(r"mov[lq]\s+\$0x([0-9a-fA-F]+),\s+%([a-z0-9]+)", sj)
                    if not hm:
                        continue
                    val = int(hm.group(1), 16)
                    r2 = hm.group(2)
                    if r2 not in ("rbx", "ebx", "rdi", "edi", "r8d", "r9d", "rcx", "ecx", "rdx", "edx"):
                        continue
                    if 1 <= val <= 1024:
                        cands.append(val)
                if cands:
                    strlen = max(cands)

            address_refs.append({"va": target, "len": strlen, "xref_va": insn})

        # 32-bit absolute lea style: leal 0x4f1234, %eax
        m_abs = re.match(r"^([0-9a-fA-F]+)\s+lea[lq]?\s+0x([0-9a-fA-F]+),\s+%([a-z0-9]+)$", s_asm)
        if m_abs:
            target = int(m_abs.group(2), 16)
            reg = m_abs.group(3)
            strlen = None
            if reg == "eax":
                has_conv = any(("call" in block_lines[j] and "convTstring" in block_lines[j]) for j in range(idx + 1, min(idx + 10, len(block_lines))))
                if has_conv:
                    for j in range(max(0, idx - 4), idx + 6):
                        if j >= len(block_lines):
                            break
                        sj = block_lines[j].strip()
                        hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+0x4\(%esp\)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 256:
                                strlen = val
                                break
            if strlen is None and reg in ("eax", "ebx", "ecx", "edx"):
                has_dial = any(("call" in block_lines[j] and "net.Dial" in block_lines[j]) for j in range(idx + 1, min(idx + 12, len(block_lines))))
                if has_dial:
                    for j in range(idx, min(idx + 12, len(block_lines))):
                        sj = block_lines[j].strip()
                        hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+0x4\(%esp\)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 64:
                                strlen = val
                                break

            if strlen is None and reg == "eax":
                has_fprintf = any(("call" in block_lines[j] and "fmt.Fprintf" in block_lines[j]) for j in range(idx + 1, min(idx + 16, len(block_lines))))
                if has_fprintf:
                    for j in range(idx, min(idx + 16, len(block_lines))):
                        sj = block_lines[j].strip()
                        hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+0x[cC]\(%esp\)", sj)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 256:
                                strlen = val
                                break

            if strlen is None:
                # Generic stack pair for 32-bit style string tuples.
                for j in range(idx + 1, min(idx + 12, len(block_lines) - 1)):
                    sj = block_lines[j].strip()
                    if "call" in sj:
                        break
                    if re.search(rf"movl\s+%{reg},\s+0x[0-9a-fA-F]+\(%esp\)", sj):
                        sj2 = block_lines[j + 1].strip()
                        hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+0x[0-9a-fA-F]+\(%esp\)", sj2)
                        if hm:
                            val = int(hm.group(1), 16)
                            if 1 <= val <= 256:
                                strlen = val
                                break
            if strlen is None:
                cands = []
                for j in range(max(0, idx - 8), idx + 6):
                    if j >= len(block_lines):
                        break
                    sj = block_lines[j].strip()
                    hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+%(?:ebx|edi|ecx|edx)", sj)
                    if not hm:
                        continue
                    val = int(hm.group(1), 16)
                    if 1 <= val <= 256:
                        cands.append((abs(j - idx), j, val))
                if cands:
                    cands.sort(key=lambda x: (x[0], x[1]))
                    strlen = cands[0][2]
            insn = int(m_abs.group(1), 16)
            address_refs.append({"va": target, "len": strlen, "xref_va": insn})

        # 32-bit absolute move style: movl $0x4f1234, %eax
        m_movabs32 = re.match(r"^([0-9a-fA-F]+)\s+movl\s+\$0x([0-9a-fA-F]+),\s+%([a-z0-9]+)$", s_asm)
        if m_movabs32:
            insn = int(m_movabs32.group(1), 16)
            target = int(m_movabs32.group(2), 16)
            reg = m_movabs32.group(3)
            if target < 0x10000:
                continue
            strlen = None
            for j in range(idx + 1, min(idx + 12, len(block_lines) - 1)):
                sj = block_lines[j].strip()
                if "call" in sj:
                    break
                if re.search(rf"movl\s+%{reg},\s+0x[0-9a-fA-F]+\(%esp\)", sj):
                    sj2 = block_lines[j + 1].strip()
                    hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+0x[0-9a-fA-F]+\(%esp\)", sj2)
                    if hm:
                        val = int(hm.group(1), 16)
                        if 1 <= val <= 512:
                            strlen = val
                            break
            if strlen is None:
                cands = []
                for j in range(max(0, idx - 8), idx + 6):
                    if j >= len(block_lines):
                        break
                    sj = block_lines[j].strip()
                    hm = re.search(r"movl\s+\$0x([0-9a-fA-F]+),\s+%(?:ebx|edi|ecx|edx)", sj)
                    if not hm:
                        continue
                    val = int(hm.group(1), 16)
                    if 1 <= val <= 512:
                        cands.append((abs(j - idx), j, val))
                if cands:
                    cands.sort(key=lambda x: (x[0], x[1]))
                    strlen = cands[0][2]
            address_refs.append({"va": target, "len": strlen, "xref_va": insn})

    return address_refs, immediates, calls
