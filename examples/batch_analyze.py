"""Batch-analyze binaries using a headless-ida server.

Usage:
    python batch_analyze.py /path/to/firmware/*.so

Requires a running server:
    headless-ida-server /path/to/idat 0.0.0.0 18000
"""

import sys
from headless_ida import HeadlessIdaRemote

SERVER = "127.0.0.1"
PORT = 18000

for binary_path in sys.argv[1:]:
    print(f"\n{'='*60}")
    print(f"Analyzing: {binary_path}")
    print(f"{'='*60}")

    ida = HeadlessIdaRemote(SERVER, PORT, binary_path)

    idautils = ida.import_module("idautils")
    ida_funcs = ida.import_module("ida_funcs")

    funcs = list(idautils.Functions())
    print(f"Functions: {len(funcs)}")

    for ea in funcs[:5]:
        print(f"  {hex(ea)} {ida_funcs.get_func_name(ea)}")
    if len(funcs) > 5:
        print(f"  ... and {len(funcs) - 5} more")

    ida.clean_up()
