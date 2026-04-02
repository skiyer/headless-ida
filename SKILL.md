---
name: headless-ida
description: Reverse engineer binaries using IDA Pro headlessly. Use when analyzing ELF/PE/Mach-O binaries, decompiling functions, listing imports/exports/strings, renaming symbols, or working with .i64 databases. Supports local IDA and remote server mode.
---

# Headless IDA

Analyze binaries and .i64 databases using IDA Pro without a GUI, via CLI or Python API.

## Prerequisites

- IDA Pro **9.1+** installed (e.g. `/Applications/IDA Professional 9.3.app/Contents/MacOS/ida`)
- `pip install git+https://github.com/skiyer/headless-ida.git`

## CLI Usage

All commands follow the pattern:

```
headless-ida <ida_or_server> <file> [script] [-c command] [-o output.i64]
```

### Run IDAPython commands

```bash
# One-liner
headless-ida /path/to/idat binary -c "import idautils; print(len(list(idautils.Functions())))"

# Multi-statement (semicolons supported)
headless-ida /path/to/idat binary -c "import idautils, ida_name; [print(hex(f), ida_name.get_ea_name(f)) for f in list(idautils.Functions())[:10]]"

# Run a script file
headless-ida /path/to/idat binary script.py

# Open pre-analyzed .i64 (fast, skips analysis)
headless-ida /path/to/idat database.i64 -c "..."
```

### Save database with modifications

```bash
# Analyze + run script + save modified .i64
headless-ida /path/to/idat binary -c "import ida_name; ida_name.set_name(0x1000, 'main')" -o output.i64

# Open .i64, annotate, save as new version
headless-ida /path/to/idat v1.i64 -c "..." -o v2.i64

# Download clean analysis result (no script)
headless-ida /path/to/idat binary -o output.i64
```

### Remote server mode

```bash
# Start server (once)
headless-ida-server /path/to/idat 0.0.0.0 18000

# Run commands against server
headless-ida server:18000 binary -c "..."
headless-ida server:18000 database.i64 -c "..."
headless-ida server:18000 binary -o output.i64
```

## Python API

```python
# Local
from headless_ida import HeadlessIda
ida = HeadlessIda("/path/to/idat", "/path/to/binary")

# Remote
from headless_ida import HeadlessIdaRemote
ida = HeadlessIdaRemote("server", 18000, "/path/to/local/binary")

# Then use IDA modules normally
import idautils, ida_name, ida_funcs, ida_hexrays

for func in idautils.Functions():
    print(hex(func), ida_name.get_ea_name(func))

# Decompile
cfunc = ida_hexrays.decompile(ea)
print(str(cfunc))

# Save database
i64_bytes = ida.conn.root.save_database()
with open("output.i64", "wb") as f:
    f.write(i64_bytes)

# Clean up when done
ida.clean_up()
```

## Common IDAPython Recipes

### List all functions

```bash
headless-ida $IDA binary -c "
import idautils, ida_name
for f in idautils.Functions():
    print(hex(f), ida_name.get_ea_name(f))
"
```

### Decompile a function by name

```bash
headless-ida $IDA binary -c "
import idautils, ida_funcs, ida_hexrays
for ea in idautils.Functions():
    if ida_funcs.get_func_name(ea) == 'main':
        print(str(ida_hexrays.decompile(ea)))
        break
"
```

### List strings

```bash
headless-ida $IDA binary -c "
import idautils
for s in idautils.Strings():
    print(hex(s.ea), str(s))
"
```

### Find cross-references to a string

```bash
headless-ida $IDA binary -c "
import idautils, ida_name
for s in idautils.Strings():
    if 'password' in str(s).lower():
        for xref in idautils.DataRefsTo(s.ea):
            print(f'{str(s)!r} referenced at {hex(xref)} ({ida_name.get_ea_name(xref)})')
"
```

### Rename a function and save

```bash
headless-ida $IDA binary \
  -c "import ida_name; ida_name.set_name(0x401000, 'decryption_routine')" \
  -o annotated.i64
```

### Batch decompile all functions

```bash
headless-ida $IDA binary -c "
import idautils, ida_funcs, ida_hexrays
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    try:
        cfunc = ida_hexrays.decompile(ea)
        print(f'// {name}')
        print(str(cfunc))
        print()
    except:
        print(f'// {name}: decompilation failed')
"
```

## Important Notes

- Use `import XXX` not `from XXX import *` (SWIG/RPyC limitation)
- `.i64` input skips analysis (~2s); raw binary requires full analysis (~15s+)
- `-o` saves **after** script execution, so modifications are preserved
- Server mode: each request starts a fresh IDA process
- Tested with **IDA 9.1** and **9.3**, expected to work on **IDA 9.1+**
- Large files are supported: local mode has no artificial analysis timeout; remote mode does the long analysis inside the server RPC before the final RPyC connect
- Quick regression coverage is available via `scripts/smoke-test.sh /path/to/idat /path/to/small/binary`
