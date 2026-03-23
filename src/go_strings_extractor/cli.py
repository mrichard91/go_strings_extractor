import argparse
import json

from .core import analyze_binary


def _ascii_hint_for_immediate(value):
    if not isinstance(value, int):
        return None
    if value < 0 or value > 0xFFFFFFFF:
        return None
    bs = value.to_bytes(4, "little", signed=False)
    if sum(32 <= b <= 126 for b in bs) < 3:
        return None
    if any(b not in (9, 10, 13) and not (32 <= b <= 126) for b in bs):
        return None
    return bs.decode("ascii", errors="ignore")


def _render_constant_value(const):
    if const["kind"] == "ascii_immediate":
        return repr(const["value"]), ""
    value_text = str(const["value"])
    ascii_hint = _ascii_hint_for_immediate(const["value"])
    if ascii_hint:
        return value_text, f"  ascii={ascii_hint!r}"
    return value_text, ""


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
    constants = result["user_constants"]
    if constants:
        hex_w = max(len(c["hex"]) for c in constants)
        value_parts = [_render_constant_value(c) for c in constants]
        value_w = max(len(v) for v, _ in value_parts)
        for c, (value_text, extra) in zip(constants, value_parts):
            print(f"  {c['hex']:<{hex_w}} -> {value_text:<{value_w}}{extra}")

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
