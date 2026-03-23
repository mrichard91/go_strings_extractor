#!/usr/bin/env python3
"""Build Go test fixture binaries for multiple platforms.

Requires the Go toolchain to be installed. Cross-compilation is handled by
setting GOOS/GOARCH environment variables — no additional toolchains needed.

Usage:
    python tests/fixtures/build_samples.py          # build all targets
    python tests/fixtures/build_samples.py --quick   # build only the targets used by the core test suite
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent

# (GOOS, GOARCH, output suffix)
CORE_TARGETS = [
    ("darwin", "amd64", "network_darwin_amd64.out"),
    ("darwin", "arm64", "network_darwin_arm64.out"),
    ("linux", "amd64", "network_linux_amd64.out"),
    ("windows", "386", "network_windows_386.out"),
    ("windows", "amd64", "network_windows_amd64.out"),
    ("windows", "arm64", "network_windows_arm64.out"),
    ("windows", "arm", "network_windows_arm.out"),
]

EXTENDED_TARGETS = [
    ("linux", "386", "network_linux_386.out"),
    ("linux", "arm", "network_linux_arm.out"),
    ("linux", "arm64", "network_linux_arm64.out"),
    ("freebsd", "amd64", "network_freebsd_amd64.out"),
    ("freebsd", "arm64", "network_freebsd_arm64.out"),
    ("openbsd", "amd64", "network_openbsd_amd64.out"),
    ("netbsd", "amd64", "network_netbsd_amd64.out"),
]


def build_target(goos, goarch, output_name, src_path, out_dir):
    out_path = out_dir / output_name
    if out_path.exists():
        print(f"  skip {output_name} (already exists)")
        return True

    env = os.environ.copy()
    env["GOOS"] = goos
    env["GOARCH"] = goarch
    env["CGO_ENABLED"] = "0"

    cmd = ["go", "build", "-o", str(out_path), str(src_path)]
    print(f"  build {goos}/{goarch} -> {output_name}")
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  FAIL {output_name}: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description="Build Go test fixture binaries")
    ap.add_argument("--quick", action="store_true", help="build only core targets needed by the test suite")
    ap.add_argument("--force", action="store_true", help="rebuild even if binaries already exist")
    args = ap.parse_args()

    src_path = FIXTURES_DIR / "network.go"
    if not src_path.exists():
        print(f"error: source not found: {src_path}", file=sys.stderr)
        sys.exit(1)

    # Check Go is available
    try:
        subprocess.run(["go", "version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("error: Go toolchain not found. Install Go from https://go.dev/dl/", file=sys.stderr)
        sys.exit(1)

    targets = list(CORE_TARGETS)
    if not args.quick:
        targets.extend(EXTENDED_TARGETS)

    if args.force:
        for _, _, name in targets:
            p = FIXTURES_DIR / name
            if p.exists():
                p.unlink()

    print(f"Building {len(targets)} targets from {src_path}")
    ok = 0
    fail = 0
    for goos, goarch, name in targets:
        if build_target(goos, goarch, name, src_path, FIXTURES_DIR):
            ok += 1
        else:
            fail += 1

    print(f"\nDone: {ok} built, {fail} failed")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
