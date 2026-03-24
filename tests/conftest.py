import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# (GOOS, GOARCH, filename)
REQUIRED_FIXTURES = [
    ("darwin", "amd64", "network_darwin_amd64.out"),
    ("darwin", "arm64", "network_darwin_arm64.out"),
    ("linux", "amd64", "network_linux_amd64.out"),
    ("windows", "amd64", "network_windows_amd64.out"),
    ("windows", "386", "network_windows_386.out"),
    ("windows", "arm64", "network_windows_arm64.out"),
    ("windows", "arm", "network_windows_arm.out"),
]


def _go_available():
    try:
        subprocess.run(["go", "version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _build_fixture(goos, goarch, filename):
    import os
    src = FIXTURES_DIR / "network.go"
    out = FIXTURES_DIR / filename
    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    env["CGO_ENABLED"] = "0"
    subprocess.run(
        ["go", "build", "-o", str(out), str(src)],
        env=env, check=True, capture_output=True,
    )


def _fixture_is_stale(name):
    """Check if a fixture binary is missing or older than the Go source."""
    src = FIXTURES_DIR / "network.go"
    out = FIXTURES_DIR / name
    if not out.exists():
        return True
    return src.stat().st_mtime > out.stat().st_mtime


def pytest_configure(config):
    """Auto-build test fixture binaries if Go is available."""
    missing = [
        (goos, goarch, name)
        for goos, goarch, name in REQUIRED_FIXTURES
        if _fixture_is_stale(name)
    ]
    if not missing:
        return

    if not _go_available():
        return  # tests will skip via fixture_path

    print(f"\nBuilding {len(missing)} test fixture(s)...", file=sys.stderr)
    for goos, goarch, name in missing:
        try:
            _build_fixture(goos, goarch, name)
            print(f"  built {name}", file=sys.stderr)
        except subprocess.CalledProcessError as e:
            print(f"  FAILED {name}: {e.stderr}", file=sys.stderr)


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


def fixture_path(name):
    """Return the path to a fixture binary, or skip the test if unavailable."""
    p = FIXTURES_DIR / name
    if not p.exists():
        pytest.skip(f"fixture {name} not built (need Go toolchain)")
    return str(p)
