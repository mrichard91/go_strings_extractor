import argparse
import json

from .core import analyze_binary


def main():
    ap = argparse.ArgumentParser(description="Extract likely user-authored strings/constants from Go binaries")
    ap.add_argument("binary", help="path to binary")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument(
        "--include-rodata-fallback",
        action="store_true",
        help="include broader rodata domain/endpoint scan (more coverage, more noise)",
    )
    ap.add_argument(
        "--yara",
        action="store_true",
        help="emit YARA candidate signatures with context scaffolding",
    )
    args = ap.parse_args()

    result = analyze_binary(
        args.binary,
        include_rodata_fallback=args.include_rodata_fallback,
        include_yara=args.yara,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"binary: {result['binary']}")
    print(f"format: {result['format']}")
    print(f"arch: {result['arch']}")
    print("main symbols:")
    for s in result["main_symbols"]:
        print(f"  {s['addr']} {s['name']}")
    print("analyzed symbols:")
    for s in result["analyzed_symbols"]:
        print(f"  {s['addr']} {s['name']}")

    print("\nlikely user strings:")
    for s in result["user_strings"]:
        print(f"  {s['string']}  [va={s['va']}]")

    print("\nlikely user constants:")
    for c in result["user_constants"]:
        if c["kind"] == "ascii_immediate":
            print(f"  {c['hex']} -> {c['value']!r}")
        else:
            print(f"  {c['hex']} -> {c['value']}")

    if result.get("connection_endpoints"):
        print("\nlikely connection endpoints:")
        for ep in result["connection_endpoints"]:
            print(f"  {ep}")
    if result.get("endpoint_xrefs"):
        print("\nendpoint xrefs:")
        for x in result["endpoint_xrefs"]:
            print(f"  {x['endpoint']} <- {x['function']} @ {x['xref_va']} (str {x['string_va']})")

    if result.get("yara_candidates"):
        yc = result["yara_candidates"]
        print("\nyara candidate rules:")
        for rr in yc.get("rules", []):
            print(rr["rule"])

    if result.get("function_strings"):
        print("\nfunction -> strings:")
        for rec in result["function_strings"]:
            print(f"  {rec['function']}:")
            for s in rec["strings"]:
                print(f"    - {s}")

    if result["errors"]:
        print("\nerrors/warnings:")
        for e in result["errors"]:
            print(f"  - {e}")
