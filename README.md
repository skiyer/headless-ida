<p align="center">
  <img alt="Headless IDA" src="https://raw.githubusercontent.com/skiyer/headless-ida/main/headless-ida.png" width="128">
</p>
<h1 align="center">Headless IDA</h1>

> Fork of [DennyDai/headless-ida](https://github.com/DennyDai/headless-ida) with server mode enhancements: direct RPyC connection, `.i64` support, and database export.

## Install

```bash
pip install git+https://github.com/skiyer/headless-ida.git
```

## Compatibility

- Tested with **IDA Pro 9.1** and **IDA Pro 9.3** on macOS
- Expected to work on **IDA 9.1+**
- Both `idat` (TUI) and `ida` (GUI) binaries are supported. If `idat` fails to start, try using `ida` instead

## Usage

### Command Line

```bash
# Run a script
headless-ida /path/to/idat /path/to/binary script.py

# One-liner
headless-ida /path/to/idat /path/to/binary -c "import idautils; print(list(idautils.Functions())[0:10])"

# Open a pre-analyzed .i64 (fast, skips analysis)
headless-ida /path/to/idat database.i64 -c "import idautils; print(len(list(idautils.Functions())))"

# Interactive console
headless-ida /path/to/idat /path/to/binary

# Save the database after running a script (-o), so all modifications (renamed functions, comments, etc.) are preserved.
headless-ida /path/to/idat /path/to/binary -c "import ida_name; ida_name.set_name(0x1000, 'main')" -o output.i64
```

### Python API

```python
from headless_ida import HeadlessIda

headlessida = HeadlessIda("/path/to/idat", "/path/to/binary")

import idautils
import ida_name

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

## Server Mode

Run IDA on a remote machine. The client sends a binary (or `.i64`), the server starts IDA, and the client connects directly to IDA via RPyC.

```
Client ──file data──→ Server ──starts IDA──→ IDA RPyC
Client ←──(host, port)──── Server
Client ═══════════════════════════════════→ IDA RPyC (direct connection)
```

### Start the Server

```bash
headless-ida-server /path/to/idat 0.0.0.0 18000
```

### Run Scripts Remotely

```bash
# Analyze a binary and run a script
headless-ida server:18000 /path/to/binary -c "import idautils; print(len(list(idautils.Functions())))"

# Open a .i64 on the server (skips analysis, ~2s)
headless-ida server:18000 database.i64 -c "import idautils; print(len(list(idautils.Functions())))"

# Interactive console
headless-ida server:18000 /path/to/binary
```

### Save & Export Databases (`-o`)

```bash
# Analyze and download the .i64 (no script execution)
headless-ida server:18000 /path/to/binary -o output.i64

# Run a script and save the modified database
headless-ida server:18000 /path/to/binary \
  -c "import ida_name; ida_name.set_name(0x1000, 'main')" \
  -o modified.i64

# Open a .i64, modify, save as new version
headless-ida server:18000 v1.i64 \
  -c "import ida_name; ida_name.set_name(0x1000, 'entry')" \
  -o v2.i64
```

### Python API (Remote)

```python
from headless_ida import HeadlessIdaRemote

headlessida = HeadlessIdaRemote("192.168.1.100", 18000, "/path/to/local/binary")

import idautils
import ida_hexrays

for func in idautils.Functions():
    cfunc = ida_hexrays.decompile(func)
    if cfunc:
        print(str(cfunc))
        break
```

## CLI Reference

```
headless-ida <ida_or_server> <file> [script] [-c command] [-o output.i64]
                                              [-f ftype] [-p processor]

Positional arguments:
  ida_or_server   Path to IDA executable, OR host:port of remote server
  file            Binary to analyze or .i64 database to open
  script          Python script to execute (optional)

Options:
  -c COMMAND      Python one-liner to execute
  -o OUTPUT       Save .i64 database to file (includes script modifications)
  -f FTYPE        File type for IDA (prefix from "load file" dialog)
  -p PROCESSOR    Processor type (e.g. arm:ARMv7-A, mips:R3000)
```

```
headless-ida-server <ida_path> <host> <port>
```

## Known Issues

- **`from XXX import *`** — Using `from XXX import *` with certain IDA modules (like `idaapi`, `ida_ua`) is unsupported due to SWIG/RPyC compatibility issues. Use `import XXX` or `from XXX import YYY` instead. The issue is that SWIG generates intermediary objects (SwigVarlink) that RPyC cannot serialize or transmit correctly.

## Resources

- [Upstream Repository](https://github.com/DennyDai/headless-ida)
- [IDAPython Documentation](https://docs.hex-rays.com/developer-guide/idapython)
- [IDAPython Examples](https://docs.hex-rays.com/developer-guide/idapython/idapython-examples)

## License

MIT — see [LICENSE](LICENSE).
