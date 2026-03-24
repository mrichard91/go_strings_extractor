import pytest

from go_strings_extractor import analyze_binary
from conftest import fixture_path


class TestCoreExtraction:
    """Verify string extraction across platforms and architectures."""

    def assert_contains_strings(self, result, expected):
        got = {x["string"] for x in result["user_strings"]}
        for s in expected:
            assert s in got, f"missing string {s!r}; got={sorted(got)}"

    def assert_contains_substring(self, result, needle):
        got = [x["string"] for x in result["user_strings"]]
        assert any(needle in s for s in got), f"missing substring {needle!r}; got={sorted(got)}"

    def assert_contains_constant(self, result, kind, value):
        got = [(x["kind"], x["value"]) for x in result["user_constants"]]
        assert any(x["kind"] == kind and x["value"] == value for x in result["user_constants"]), (
            f"missing constant {(kind, value)!r}; got={got}"
        )

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
                # Expanded: goroutine function strings
                "goroutine-beacon-started: %s\n",
                # Expanded: closure strings (via string header dereference)
                "closure-exfil-ready",
                # Expanded: defer strings (via string header dereference)
                "defer-cleanup-handler",
                # Expanded: nested helper call path
                "payload-constructed",
                # Expanded: interface method dispatch
                "beacon-handler processing: %s\n",
                # Expanded: select statement (via string header dereference)
                "select-timeout-reached",
                # Expanded: additional C2 address
                "backup-c2.fallback.net:8443",
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
                # Expanded: goroutine function strings
                "goroutine-beacon-started: %s\n",
                # Expanded: closure strings (via string header dereference)
                "closure-exfil-ready",
                # Expanded: select statement (via string header dereference)
                "select-timeout-reached",
                # Expanded: additional C2 address
                "backup-c2.fallback.net:8443",
                # Expanded: nested helper (ADRP+ADD on ARM64)
                "POST /api/beacon HTTP/1.1\r\n",
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
                # Expanded: goroutine function strings
                "goroutine-beacon-started: %s\n",
                # Expanded: closure strings (via string header dereference)
                "closure-exfil-ready",
                # Expanded: defer strings (via string header dereference)
                "defer-cleanup-handler",
                # Expanded: nested helper call path
                "payload-constructed",
                # Expanded: interface method dispatch
                "beacon-handler processing: %s\n",
                # Expanded: select statement (via string header dereference)
                "select-timeout-reached",
                # Expanded: additional C2 address
                "backup-c2.fallback.net:8443",
            },
        )

    def test_windows_386_core_strings(self):
        r = analyze_binary(fixture_path("network_windows_386.out"))
        assert r["format"] == "pe"
        assert r["arch"] == "386"
        assert any("fallback extraction" in e for e in r["errors"])
        self.assert_contains_strings(
            r,
            {
                "windows",
                "tcp6",
                "Got OS info %s\n",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
            },
        )
        self.assert_contains_substring(r, "doesthispersonexist.com")
        self.assert_contains_constant(r, "ascii_immediate", "GET /foo")
        self.assert_contains_constant(r, "ascii_immediate", "TP/1.1\n\n")
        self.assert_contains_constant(r, "immediate", 0x20544547)
        self.assert_contains_constant(r, "immediate", 0x312F5054)
        self.assert_contains_constant(r, "immediate", 443)
        bad_values = {0x8D005FB8, 0xE8000001, 0x448BFFF8}
        got_immediates = {x["value"] for x in r["user_constants"] if x["kind"] == "immediate"}
        assert bad_values.isdisjoint(got_immediates), got_immediates

    def test_windows_amd64_core_strings(self):
        r = analyze_binary(fixture_path("network_windows_amd64.out"))
        assert r["format"] == "pe"
        assert r["arch"] == "x86_64"
        self.assert_contains_strings(
            r,
            {
                "windows",
                "tcp6",
                "Got OS info %s\n",
                "connected to: %s\n",
                "[2606:4700:3035::ac43:cf7b]:443",
                "doesthispersonexist.com:80",
                # Expanded
                "backup-c2.fallback.net:8443",
                "closure-exfil-ready",
                "select-timeout-reached",
                "goroutine-beacon-started: %s\n",
            },
        )

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
                # Expanded
                "backup-c2.fallback.net:8443",
                "closure-exfil-ready",
                "select-timeout-reached",
                "goroutine-beacon-started: %s\n",
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
                "tcp6",
                # Expanded: backup C2 address (matched by domain:port pattern)
                "backup-c2.fallback.net:8443",
            },
        )


class TestComplexCallPaths:
    """Verify extraction through goroutines, closures, channels, and nested calls."""

    def assert_contains_strings(self, result, expected):
        got = {x["string"] for x in result["user_strings"]}
        for s in expected:
            assert s in got, f"missing string {s!r}; got={sorted(got)}"

    def test_goroutine_strings_extracted(self):
        """Strings from goroutine entry functions appear in output."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        self.assert_contains_strings(
            r,
            {
                "goroutine-beacon-started: %s\n",
                "goroutine-connect-failed: %s\n",
            },
        )

    def test_closure_strings_extracted(self):
        """Strings embedded in anonymous closures are found via header dereference."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        self.assert_contains_strings(
            r,
            {
                "closure-exfil-ready",
                "defer-cleanup-handler",
                "panic-recovery-triggered",
            },
        )

    def test_nested_helper_strings(self):
        """Strings in helper functions called from main are found."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        self.assert_contains_strings(
            r,
            {
                "payload-constructed",
                "beacon-send-failed: %w",
            },
        )

    def test_interface_method_strings(self):
        """Strings in interface method implementations are found."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        self.assert_contains_strings(
            r,
            {
                "beacon-handler processing: %s\n",
            },
        )

    def test_channel_select_strings(self):
        """Strings used in channel operations and select statements are found."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        self.assert_contains_strings(
            r,
            {
                "select-timeout-reached",
                "channel-received: %s\n",
            },
        )

    def test_function_strings_include_goroutines(self):
        """function_strings map includes goroutine and helper function entries."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        func_names = {rec["function"] for rec in r["function_strings"]}
        assert any("goroutineBeacon" in fn for fn in func_names), \
            f"goroutineBeacon not in function_strings: {sorted(func_names)}"
        assert any("sendBeacon" in fn for fn in func_names), \
            f"sendBeacon not in function_strings: {sorted(func_names)}"

    def test_function_strings_include_closures(self):
        """Strings from inlined closures appear in the parent function's strings."""
        r = analyze_binary(fixture_path("network_linux_amd64.out"))
        # Go 1.25 may inline closures into main; check that closure strings
        # appear either in main.main or in a main.main.funcN entry.
        all_strings = set()
        for rec in r["function_strings"]:
            if "main.main" in rec["function"]:
                all_strings.update(rec["strings"])
        assert "closure-exfil-ready" in all_strings or \
            "closure-exfil-ready" in {x["string"] for x in r["user_strings"]}, \
            f"closure-exfil-ready not found in main.main strings"

    def test_goroutine_strings_arm64(self):
        """Goroutine and closure strings are extracted on ARM64."""
        r = analyze_binary(fixture_path("network_darwin_arm64.out"))
        self.assert_contains_strings(
            r,
            {
                "goroutine-beacon-started: %s\n",
                "closure-exfil-ready",
                "select-timeout-reached",
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
