"""Quality regressions for extracted strings.

These tests pin down outputs that were technically printable but not semantically
useful. The extractor should prefer dropping pointer fragments and redundant
endpoint overreads once the canonical signal is already present.
"""

from go_strings_extractor import analyze_binary
from conftest import fixture_path


class TestNoiseRegressions:
    """Document known false-positive modes so they stay fixed."""

    def test_windows_amd64_drops_pointer_fragments_and_redundant_endpoint_overread(self):
        """PE x86_64 should keep the network strings and drop pointer-cell junk.

        This fixture used to leak short strings like `l[` and a control-character
        fragment because the bytes were actually little-endian pointers inside a
        table, not string bytes. It also emitted a glued host token even though
        the canonical endpoint literal was already present elsewhere.
        """
        result = analyze_binary(fixture_path("network_windows_amd64.out"))
        got = {rec["string"] for rec in result["user_strings"]}

        assert "windows" in got
        assert "Got OS info %s\n" in got
        assert "connected to: %s\n" in got
        assert "doesthispersonexist.com:80" in got
        assert "[2606:4700:3035::ac43:cf7b]:443" in got

        assert "l[" not in got
        assert "z[" not in got
        assert all(not any(ord(ch) < 32 and ch not in "\n\r\t" for ch in s) for s in got)
        assert not any(s.startswith("typeExpandEnvironmentStringsW") for s in got)
