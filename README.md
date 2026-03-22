# go-strings-extractor

Extract user-authored strings and constants from compiled Go binaries using static analysis.

Analyzes `main.*` package functions to extract meaningful strings while filtering out Go runtime noise. Works across ELF, Mach-O, and PE formats on x86, x86-64, ARM64, and ARM32 architectures — no external disassembler required.

## Install

```bash
pip install go-strings-extractor
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Usage

### CLI

```bash
# Human-readable output
go-strings-extractor path/to/binary

# JSON output
go-strings-extractor path/to/binary --json

# Include YARA rule scaffolding
go-strings-extractor path/to/binary --json --yara

# Broader rodata domain/endpoint scan (more coverage, more noise)
go-strings-extractor path/to/binary --include-rodata-fallback
```

### Library

```python
from go_strings_extractor import analyze_binary

result = analyze_binary("path/to/binary")

for s in result["user_strings"]:
    print(s["string"])

for c in result["user_constants"]:
    print(c["hex"], c["value"])
```

## Features

- Pure Python — no external tools or disassemblers needed
- Parses ELF, Mach-O (including FAT/Universal), and PE formats
- Native instruction decoding for x86-64, x86, ARM64, with ARM32 fallback
- Recovers symbols from stripped binaries via `.gopclntab`
- Heuristic string length inference from calling conventions
- Optional YARA rule generation with context bytes
- Connection endpoint extraction and cross-referencing

## Output

The `analyze_binary()` function returns a dict with:

- `user_strings` — extracted strings with virtual addresses and offsets
- `user_constants` — immediate values and ASCII-encoded constants
- `function_strings` — strings grouped by originating function
- `connection_endpoints` — inferred network endpoints
- `endpoint_xrefs` — cross-references between endpoints and functions
- `yara_candidates` — (optional) YARA rule scaffolding

## Testing

```bash
# Requires Go toolchain for building test fixtures
pip install -e ".[dev]"
pytest
```
