"""Fallback-pattern regressions.

These tests are intentionally example-driven. They document what the fallback
extractor should recover when native disassembly is unavailable or too sparse.
The goal is to keep the fallback path useful across architectures without
turning it into a noisy generic strings pass.
"""

from go_strings_extractor.fallback import fallback_strings_basic


def _strings(blob):
    return [rec["string"] for rec in fallback_strings_basic(blob)]


class TestFallbackPatterns:
    """Executable documentation for the regex-based fallback extractor."""

    def test_extracts_http_requests_with_lf_and_crlf_line_endings(self):
        """HTTP request literals should survive both common newline forms.

        Some fixtures embed bare LF request scaffolds while others may carry the
        more realistic CRLF form. The fallback path should recover both without
        needing architecture-specific decoding.
        """
        got = _strings(
            b"xx GET /foo HTTP/1.1\n\n yy POST /submit HTTP/1.0\r\n\r\n zz"
        )
        assert "GET /foo HTTP/1.1\n\n" in got
        assert "POST /submit HTTP/1.0\r\n\r\n" in got

    def test_extracts_uppercase_and_glued_host_port_endpoints(self):
        """Endpoint recovery should handle both clean and glued host strings.

        Real blobs sometimes contain a standalone host:port token and sometimes
        only a larger glued token around it. The fallback path should recover a
        useful signal in both cases, even if the glued form is not canonicalized
        yet.
        """
        got = _strings(b"EXAMPLE.COM:443 .. ticketdoesthispersonexist.com:80 ..")
        assert "EXAMPLE.COM:443" in got
        assert any("doesthispersonexist.com:80" in s for s in got)

    def test_extracts_ipv6_protocols_and_os_tokens_once(self):
        """Endpoint and platform hints should be present but deduplicated.

        These short tokens are useful context for sparse binaries, but repeated
        occurrences should not spam the result list.
        """
        got = _strings(
            b"[2606:4700:3035::ac43:cf7b]:443 tcp6 tcp6 tcp windows windows udp"
        )
        assert "[2606:4700:3035::ac43:cf7b]:443" in got
        assert got.count("tcp6") == 1
        assert got.count("tcp") == 1
        assert got.count("windows") == 1
        assert got.count("udp") == 1

    def test_error_prefix_pattern_stops_at_colon_boundary(self):
        """Error labels should capture the semantic prefix, not trailing noise.

        The fallback extractor uses these strings as likely user-facing context,
        so the boundary should stop once the message prefix ends.
        """
        got = _strings(b"Error connecting baz: dial tcp 10.0.0.1:80")
        assert "Error connecting baz:" in got
        assert all(not s.startswith("Error connecting baz: dial") for s in got)
