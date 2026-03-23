import struct

from .sections import va_to_off


X64_REGS = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
X86_REGS = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
]


def _signext(v, bits):
    mask = (1 << bits) - 1
    v &= mask
    if v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v


def _fmt_signed_hex(v):
    if v < 0:
        return f"-0x{-v:x}"
    return f"0x{v:x}"


def _decode_x86_64(code, start_va, symbols=None):
    out = []
    n = len(code)
    seen = set()

    for i in range(n):
        addr = start_va + i

        # call rel32
        if i + 4 < n and code[i] == 0xE8:
            disp = struct.unpack_from("<i", code, i + 1)[0]
            target = addr + 5 + disp
            key = (addr, "call", target)
            if key not in seen:
                seen.add(key)
                name = symbols.get(target) if symbols else None
                if name:
                    out.append(f"{addr:x}\tcallq 0x{target:x} <{name}>")
                else:
                    out.append(f"{addr:x}\tcallq 0x{target:x}")

        # REX-prefixed patterns.
        if i + 2 < n and 0x40 <= code[i] <= 0x4F:
            rex = code[i]
            rex_w = 1 if (rex & 0x8) else 0
            rex_r = 1 if (rex & 0x4) else 0
            rex_b = 1 if (rex & 0x1) else 0
            op = code[i + 1]

            # lea reg, [rip+disp32]
            if op == 0x8D and i + 6 < n:
                modrm = code[i + 2]
                mod = (modrm >> 6) & 0x3
                reg = ((modrm >> 3) & 0x7) | (rex_r << 3)
                rm = (modrm & 0x7) | (rex_b << 3)
                if mod == 0 and rm == 5:
                    disp = struct.unpack_from("<i", code, i + 3)[0]
                    target = addr + 7 + disp
                    reg_name = X64_REGS[reg] if rex_w else X86_REGS[reg]
                    key = (addr, "lea", target, reg_name)
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            f"{addr:x}\tlea{'q' if rex_w else 'l'} {_fmt_signed_hex(disp)}(%rip), %{reg_name} ; 0x{target:x}"
                        )

            # movabs imm64
            if rex_w and 0xB8 <= op <= 0xBF and i + 9 < n:
                reg = (op - 0xB8) | (rex_b << 3)
                imm = struct.unpack_from("<Q", code, i + 2)[0]
                key = (addr, "movabs", reg, imm)
                if key not in seen:
                    seen.add(key)
                    out.append(f"{addr:x}\tmovabsq $0x{imm:x}, %{X64_REGS[reg]}")

            # mov r -> [rsp/rbp+disp]
            if op == 0x89 and i + 3 < n:
                modrm = code[i + 2]
                mod = (modrm >> 6) & 0x3
                reg = ((modrm >> 3) & 0x7) | (rex_r << 3)
                rm = (modrm & 0x7) | (rex_b << 3)
                j = i + 3
                base = rm
                disp = 0
                if mod != 3 and (modrm & 0x7) == 4 and j < n:
                    sib = code[j]
                    j += 1
                    base = (sib & 0x7) | (rex_b << 3)
                if mod == 1 and j < n:
                    disp = _signext(code[j], 8)
                elif mod == 2 and j + 3 < n:
                    disp = struct.unpack_from("<i", code, j)[0]
                if mod != 3 and base in (4, 5):
                    key = (addr, "movmem", reg, base, disp, rex_w)
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            f"{addr:x}\tmov{'q' if rex_w else 'l'} %{X64_REGS[reg] if rex_w else X86_REGS[reg]}, 0x{(disp & 0xffffffff):x}(%{X64_REGS[base] if rex_w else X86_REGS[base]})"
                        )

            # mov imm -> [rsp/rbp+disp]
            if op == 0xC7 and i + 6 < n:
                modrm = code[i + 2]
                mod = (modrm >> 6) & 0x3
                regop = (modrm >> 3) & 0x7
                rm = (modrm & 0x7) | (rex_b << 3)
                j = i + 3
                base = rm
                disp = 0
                if mod != 3 and (modrm & 0x7) == 4 and j < n:
                    sib = code[j]
                    j += 1
                    base = (sib & 0x7) | (rex_b << 3)
                if mod == 1 and j < n:
                    disp = _signext(code[j], 8)
                    j += 1
                elif mod == 2 and j + 3 < n:
                    disp = struct.unpack_from("<i", code, j)[0]
                    j += 4
                if regop == 0 and j + 3 < n:
                    imm = struct.unpack_from("<I", code, j)[0]
                    if mod == 3:
                        dst = X64_REGS[rm] if rex_w else X86_REGS[rm]
                        out.append(f"{addr:x}\tmov{'q' if rex_w else 'l'} $0x{imm:x}, %{dst}")
                    elif base in (4, 5):
                        key = (addr, "movimmmem", base, disp, imm, rex_w)
                        if key not in seen:
                            seen.add(key)
                            out.append(
                                f"{addr:x}\tmov{'q' if rex_w else 'l'} $0x{imm:x}, 0x{(disp & 0xffffffff):x}(%{X64_REGS[base] if rex_w else X86_REGS[base]})"
                            )

        # Non-REX mov imm32 reg.
        if i + 4 < n and 0xB8 <= code[i] <= 0xBF:
            reg = code[i] - 0xB8
            imm = struct.unpack_from("<I", code, i + 1)[0]
            key = (addr, "movimm", reg, imm)
            if key not in seen:
                seen.add(key)
                out.append(f"{addr:x}\tmovl $0x{imm:x}, %{X86_REGS[reg]}")

    out.sort(key=lambda ln: int(ln.split("\t", 1)[0], 16))
    return out


def _decode_x86_32(code, start_va, symbols=None):
    out = []
    n = len(code)
    seen = set()
    for i in range(n):
        addr = start_va + i
        if i + 4 < n and code[i] == 0xE8:
            disp = struct.unpack_from("<i", code, i + 1)[0]
            target = addr + 5 + disp
            key = (addr, "call", target)
            if key not in seen:
                seen.add(key)
                name = symbols.get(target) if symbols else None
                if name:
                    out.append(f"{addr:x}\tcall 0x{target:x} <{name}>")
                else:
                    out.append(f"{addr:x}\tcall 0x{target:x}")
        if i + 5 < n and code[i] == 0x8D:
            modrm = code[i + 1]
            mod = (modrm >> 6) & 0x3
            reg = (modrm >> 3) & 0x7
            rm = modrm & 0x7
            if mod == 0 and rm == 5:
                imm = struct.unpack_from("<I", code, i + 2)[0]
                key = (addr, "lea", reg, imm)
                if key not in seen:
                    seen.add(key)
                    out.append(f"{addr:x}\tleal 0x{imm:x}, %{X86_REGS[reg]}")
        if i + 4 < n and 0xB8 <= code[i] <= 0xBF:
            reg = code[i] - 0xB8
            imm = struct.unpack_from("<I", code, i + 1)[0]
            key = (addr, "movimm", reg, imm)
            if key not in seen:
                seen.add(key)
                out.append(f"{addr:x}\tmovl $0x{imm:x}, %{X86_REGS[reg]}")
    out.sort(key=lambda ln: int(ln.split("\t", 1)[0], 16))
    return out


def _decode_arm64(code, start_va, symbols=None):
    out = []
    i = 0
    n = len(code)
    while i + 3 < n:
        addr = start_va + i
        ins = struct.unpack_from("<I", code, i)[0]

        # BL imm26
        if (ins & 0xFC000000) == 0x94000000:
            imm26 = _signext(ins & 0x03FFFFFF, 26) << 2
            target = addr + imm26
            name = symbols.get(target) if symbols else None
            if name:
                out.append(f"{addr:x}\tbl 0x{target:x} <{name}>")
            else:
                out.append(f"{addr:x}\tbl 0x{target:x}")
            i += 4
            continue

        # ADRP
        if (ins & 0x9F000000) == 0x90000000:
            rd = ins & 0x1F
            immlo = (ins >> 29) & 0x3
            immhi = (ins >> 5) & 0x7FFFF
            imm = _signext((immhi << 2) | immlo, 21) << 12
            page = (addr & ~0xFFF) + imm
            out.append(f"{addr:x}\tadrp x{rd}, 0x{page:x} ; 0x{page:x}")
            i += 4
            continue

        # ADR
        if (ins & 0x9F000000) == 0x10000000:
            rd = ins & 0x1F
            immlo = (ins >> 29) & 0x3
            immhi = (ins >> 5) & 0x7FFFF
            imm = _signext((immhi << 2) | immlo, 21)
            target = addr + imm
            out.append(f"{addr:x}\tadr x{rd}, 0x{target:x} ; 0x{target:x}")
            i += 4
            continue

        # ADD (immediate), 64-bit/32-bit
        if (ins & 0x7F000000) in (0x11000000, 0x91000000):
            sf = (ins >> 31) & 0x1
            op = (ins >> 30) & 0x1
            if op == 0:
                sh = (ins >> 22) & 0x1
                imm12 = (ins >> 10) & 0xFFF
                rn = (ins >> 5) & 0x1F
                rd = ins & 0x1F
                imm = imm12 << (12 if sh else 0)
                regp = "x" if sf else "w"
                out.append(f"{addr:x}\tadd {regp}{rd}, {regp}{rn}, #0x{imm:x}")
                i += 4
                continue

        # MOVZ (wide immediate)
        if (ins & 0x7F800000) in (0x52800000, 0xD2800000):
            sf = (ins >> 31) & 0x1
            rd = ins & 0x1F
            imm16 = (ins >> 5) & 0xFFFF
            hw = (ins >> 21) & 0x3
            imm = imm16 << (hw * 16)
            regp = "x" if sf else "w"
            out.append(f"{addr:x}\tmovz {regp}{rd}, #0x{imm:x}")
            i += 4
            continue

        i += 4
    return out


def disassemble_range(blob, sections, arch, start, end, image_base=None, symbols=None):
    if start is None:
        return []
    if end is not None and end <= start:
        return []
    start_off = va_to_off(start, sections, image_base=image_base)
    if start_off < 0:
        return []
    if end is None:
        end_off = min(start_off + 4096, len(blob))
    else:
        end_off = va_to_off(end, sections, image_base=image_base)
        if end_off < 0:
            # clamp to section bounds if exact end VA doesn't map
            end_off = min(start_off + 65536, len(blob))
    if end_off <= start_off:
        return []
    code = blob[start_off:end_off]
    if arch == "x86_64":
        return _decode_x86_64(code, start, symbols=symbols)
    if arch == "386":
        return _decode_x86_32(code, start, symbols=symbols)
    if arch == "arm64":
        return _decode_arm64(code, start, symbols=symbols)
    return []
