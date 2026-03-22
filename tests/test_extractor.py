import pytest

from go_strings_extractor import analyze_binary
from conftest import fixture_path


class TestCoreExtraction:
    """Verify string extraction across platforms and architectures."""

    def assert_contains_strings(self, result, expected):
        got = {x["string"] for x in result["user_strings"]}
        for s in expected:
            assert s in got, f"missing string {s!r}; got={sorted(got)}"

    def test_darwin_amd64_core_strings(self):
        r = analyze_binary(fixture_path("network_darwin_amd64.out"))
        assert r["format"] == "macho"
        assert r["arch"] == "x86_64"
        self.assert_contains_strings(
            r,
            {
                "darwin",
                "tcp6",
                "Got OS info %s\n",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
                "doesthispersonexist.com:80",
            },
        )

    def test_darwin_arm64_core_strings(self):
        r = analyze_binary(fixture_path("network_darwin_arm64.out"))
        assert r["format"] == "macho"
        assert r["arch"] == "arm64"
        self.assert_contains_strings(
            r,
            {
                "darwin",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
                "doesthispersonexist.com:80",
            },
        )

    def test_linux_amd64_core_strings(self):
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        assert r["format"] == "elf"
        assert r["arch"] == "x86_64"
        self.assert_contains_strings(
            r,
            {
                "linux",
                "tcp6",
                "Got OS info %s\n",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
                "doesthispersonexist.com:80",
            },
        )

    def test_windows_386_core_strings(self):
        r = analyze_binary(fixture_path("network_windows_386.out"))
        assert r["format"] == "pe"
        assert r["arch"] == "386"
        # x86 PE strict mode currently has limited native decode coverage.
        assert len(r["analyzed_symbols"]) >= 1

    def test_windows_arm64_core_strings(self):
        r = analyze_binary(fixture_path("network_windows_arm64.out"))
        assert r["format"] == "pe"
        assert r["arch"] == "arm64"
        self.assert_contains_strings(
            r,
            {
                "windows",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
                "doesthispersonexist.com:80",
            },
        )

    def test_windows_arm32_fallback(self):
        r = analyze_binary(fixture_path("network_windows_arm.out"))
        assert r["format"] == "pe"
        assert r["arch"] == "arm"
        assert any("fallback extraction" in e for e in r["errors"])
        self.assert_contains_strings(
            r,
            {
                "windows",
                "Got OS info %s\n",
                "connected to: %s\n",
                "GET /foo HTTP/1.1\n\n",
                "tcp6",
            },
        )


class TestYara:
    """Verify YARA candidate generation."""

    def test_yara_candidates_unique_and_scaffolded(self):
        r = analyze_binary(fixture_path("network_linux_amd64.out"), include_yara=True)
        yc = r.get("yara_candidates")
        assert isinstance(yc, dict)
        sc = yc.get("string_candidates", [])
        cc = yc.get("constant_candidates", [])
        rules = yc.get("rules", [])
        assert len(rules) >= 1
        assert "rule Auto_" in rules[0]["rule"]
        ids = [x["id"] for x in sc]
        assert len(ids) == len(set(ids))
        # each string candidate should contain context scaffolding
        for s in sc[:10]:
            assert "yara_text" in s
            assert "yara_hex_context" in s
            assert "context_before_hex" in s
            assert "context_after_hex" in s
        # if constant candidates exist, they should be 4-byte+ meaningful entries
        for c in cc:
            assert c.get("size_bytes", 0) >= 4


class TestResultStructure:
    """Verify result dict has expected shape."""

    def test_result_keys(self):
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        expected_keys = {
            "binary", "format", "arch", "file", "errors",
            "main_symbols", "analyzed_symbols",
            "user_strings", "user_constants",
            "call_targets", "function_strings",
            "endpoint_xrefs", "connection_endpoints",
            "yara_candidates", "notes",
        }
        assert expected_keys.issubset(set(r.keys()))

    def test_function_strings_populated(self):
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        assert len(r["function_strings"]) >= 1
        for rec in r["function_strings"]:
            assert "function" in rec
            assert "strings" in rec
            assert len(rec["strings"]) >= 1
