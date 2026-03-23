"""Low-level parser regressions.

These tests are intentionally more verbose than the implementation. They act as
executable documentation for the on-disk structures that matter to extraction:

- `gopclntab` must parse on big-endian Go targets, not only little-endian ones.
- FAT Mach-O wrappers must rebase section offsets back to the outer file so
  later VA-to-file-offset reads land on the correct bytes.

Using synthetic blobs keeps the tests readable and stable. We only encode the
fields the parser actually consumes, which makes each test a compact spec for
that parser's contract.
"""

import struct

from go_strings_extractor.pclntab import parse_gopclntab_blob, recover_go_symbols_from_pclntab
from go_strings_extractor.sections import parse_macho_sections, va_to_off


def _make_minimal_gopclntab(byteorder, ptr_size=4):
    """Build the smallest pclntab blob our parser understands.

    Layout notes:
    - byte 7 stores the pointer size.
    - header offsets are read from `8 + N * ptr_size`.
    - each functab entry is an `(entry_off, func_off)` pair.
    - each function record is `(entry_rel, name_rel)`.

    The blob contains two functions so the parser can also infer the `end`
    address of the first one from the start of the second.

    The synthetic table supports both 32-bit and 64-bit header layouts. The
    functab rows stay 8 bytes wide because that is the contract the parser
    consumes today.
    """
    blob = bytearray(192 if ptr_size == 8 else 128)
    pack_uint = "Q" if ptr_size == 8 else "I"
    struct.pack_into(byteorder + "I", blob, 0, 0xFFFFFFFB)
    blob[6] = 1
    blob[7] = ptr_size

    nfunc = 2
    text_start = 0x1000
    funcname_off = 80 if ptr_size == 8 else 48
    functab_off = 112 if ptr_size == 8 else 80

    struct.pack_into(byteorder + pack_uint, blob, 8, nfunc)
    struct.pack_into(byteorder + pack_uint, blob, 8 + 2 * ptr_size, text_start)
    struct.pack_into(byteorder + pack_uint, blob, 8 + 3 * ptr_size, funcname_off)
    struct.pack_into(byteorder + pack_uint, blob, 8 + 7 * ptr_size, functab_off)

    names = b"main.alpha\x00main.beta\x00"
    blob[funcname_off:funcname_off + len(names)] = names

    # Two functab entries. func_off is relative to functab_off.
    struct.pack_into(byteorder + "II", blob, functab_off + 0, 0x10, 16)
    struct.pack_into(byteorder + "II", blob, functab_off + 8, 0x20, 24)

    # Function records: (entry_rel, name_rel)
    struct.pack_into(byteorder + "Ii", blob, functab_off + 16, 0x10, 0)
    struct.pack_into(byteorder + "Ii", blob, functab_off + 24, 0x20, len(b"main.alpha\x00"))
    return bytes(blob)


def _make_macho64_slice(section_offset=0x100):
    """Build a one-section thin Mach-O slice.

    The section's `offset` field is intentionally slice-relative. FAT wrappers
    store slices later in the outer file, so the parser must add the wrapper's
    slice offset back when it reports section offsets.
    """
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x01000007,
        3,
        2,
        1,
        72 + 80,
        0,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72 + 80,
        b"__TEXT\x00".ljust(16, b"\x00"),
        0x100000000,
        0x2000,
        0,
        0x2000,
        0,
        0,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\x00".ljust(16, b"\x00"),
        b"__TEXT\x00".ljust(16, b"\x00"),
        0x100001000,
        0x40,
        section_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    blob = header + segment + section
    return blob + (b"\x00" * max(0, section_offset + 0x40 - len(blob)))


def _wrap_fat_macho(slice_blob, *, fat64, slice_offset):
    """Wrap one thin slice in a FAT Mach-O container.

    FAT headers are written big-endian on disk. The only difference between the
    32-bit and 64-bit wrappers here is the width of the `offset` and `size`
    fields in the arch record.
    """
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    header = struct.pack(">II", magic, 1)
    if fat64:
        arch = struct.pack(">iiQQII", 0x01000007, 3, slice_offset, len(slice_blob), 0, 0)
    else:
        arch = struct.pack(">iiIII", 0x01000007, 3, slice_offset, len(slice_blob), 0)
    blob = bytearray(slice_offset + len(slice_blob))
    blob[:len(header)] = header
    blob[len(header):len(header) + len(arch)] = arch
    blob[slice_offset:slice_offset + len(slice_blob)] = slice_blob
    return bytes(blob)


class TestPclnTabParser:
    """Document the byte-order assumptions behind symbol recovery."""

    def test_parse_gopclntab_blob_accepts_big_endian_layout(self):
        """Big-endian Go targets should parse exactly like little-endian ones.

        This synthetic table mirrors the fields consumed by the parser and makes
        the expected starts and inferred end address explicit.
        """
        entries, err = parse_gopclntab_blob(_make_minimal_gopclntab(">"), 0)
        assert err == ""
        assert [e["name"] for e in entries] == ["main.alpha", "main.beta"]
        assert [e["start"] for e in entries] == [0x1010, 0x1020]
        assert entries[0]["end"] == 0x1020

    def test_recover_go_symbols_scans_big_endian_magic_without_section_names(self, tmp_path):
        """Sectionless fallback scanning must find big-endian pclntab blobs.

        Stripped samples sometimes lose the `.gopclntab` section metadata. The
        fallback scanner must still find the table by raw magic bytes regardless
        of target endianness.
        """
        path = tmp_path / "be-pclntab.bin"
        path.write_bytes(b"\x00" * 19 + _make_minimal_gopclntab(">") + b"\x00" * 11)
        entries, err = recover_go_symbols_from_pclntab(path, [])
        assert err == ""
        assert [e["name"] for e in entries[:2]] == ["main.alpha", "main.beta"]

    def test_parse_gopclntab_blob_accepts_big_endian_ptr64_layout(self):
        """The header offset math must also work for 8-byte pointer fields.

        Big-endian 64-bit Go targets move the header fields that point to the
        name table and functab. This regression keeps the synthetic layout
        explicit so ptr-size handling stays documented and covered.
        """
        entries, err = parse_gopclntab_blob(_make_minimal_gopclntab(">", ptr_size=8), 0)
        assert err == ""
        assert [e["name"] for e in entries] == ["main.alpha", "main.beta"]
        assert [e["start"] for e in entries] == [0x1010, 0x1020]
        assert entries[0]["end"] == 0x1020


class TestMachOSectionParsing:
    """Document the offset contract that later string extraction depends on."""

    def test_fat32_macho_offsets_are_rebased_to_outer_file(self, tmp_path):
        """A FAT wrapper must not leave section offsets slice-relative.

        If `offset` stays at `0x100` instead of `slice_offset + 0x100`, later
        file reads land in the FAT header instead of the Mach-O slice contents.
        """
        path = tmp_path / "fat32.macho"
        path.write_bytes(_wrap_fat_macho(_make_macho64_slice(), fat64=False, slice_offset=0x1000))

        sections, err = parse_macho_sections(path)
        assert err == ""
        text = next(s for s in sections if s["sectname"] == "__text")
        assert text["addr"] == 0x100001000
        assert text["offset"] == 0x1100

    def test_fat64_macho_arch_records_are_supported_and_rebased(self, tmp_path):
        """FAT_MAGIC_64 uses 64-bit slice offsets and sizes.

        The parser used to treat these records like the 32-bit form, which makes
        the arch table the wrong size and breaks slice discovery entirely.
        """
        path = tmp_path / "fat64.macho"
        path.write_bytes(_wrap_fat_macho(_make_macho64_slice(), fat64=True, slice_offset=0x2000))

        sections, err = parse_macho_sections(path)
        assert err == ""
        text = next(s for s in sections if s["sectname"] == "__text")
        assert text["offset"] == 0x2100
        assert text["size"] == 0x40


class TestVaToOff:
    """Document how file-offset mapping handles PE RVA and VA forms."""

    def test_va_to_off_maps_pe_rva_directly(self):
        """PE callers sometimes already hold an RVA instead of an absolute VA.

        In that case `va_to_off()` should map the section directly without
        needing an image base. This is the simplest PE contract and keeps the
        helper usable from parsers that never materialize full image VAs.
        """
        sections = [{"addr": 0x1000, "offset": 0x400, "size": 0x200}]
        assert va_to_off(0x1018, sections) == 0x418

    def test_va_to_off_maps_absolute_pe_va_using_image_base(self):
        """Absolute PE VAs should normalize back to the section RVA.

        Some callsites emit `image_base + rva` while others emit the raw RVA.
        `va_to_off()` must accept both forms for the same section metadata so
        extraction stays stable across parsers and symbol sources.
        """
        image_base = 0x140000000
        sections = [{"addr": 0x1000, "offset": 0x400, "size": 0x200}]
        assert va_to_off(image_base + 0x1018, sections, image_base=image_base) == 0x418

    def test_va_to_off_prefers_existing_absolute_match_before_rva_math(self):
        """An already-absolute section address must win before subtraction.

        Mach-O slices and some recovered symbol flows already carry absolute
        addresses in `sections[i]["addr"]`. Passing an image base should not
        force a PE-style subtraction when the original VA already falls inside
        the section range.
        """
        image_base = 0x100000000
        sections = [{"addr": 0x100001000, "offset": 0x2100, "size": 0x40}]
        assert va_to_off(0x100001020, sections, image_base=image_base) == 0x2120

    def test_va_to_off_returns_minus_one_for_unmapped_va(self):
        """Unknown addresses should fail closed instead of guessing an offset."""
        sections = [{"addr": 0x1000, "offset": 0x400, "size": 0x200}]
        assert va_to_off(0x3000, sections, image_base=0x140000000) == -1
