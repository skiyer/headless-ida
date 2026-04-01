import atexit
import builtins
import ctypes
import os
import shutil
import sys
import importlib
import tempfile
from typing import Optional

import rpyc

from .helpers import (
    ForwardIO, IDABackendType, resolve_ida_path,
    alloc_port, launch_ida, wait_and_connect,
)


class HeadlessIda:
    IDA_MODULES = [
        "ida_allins", "ida_auto", "ida_bitrange", "ida_bytes", "ida_dbg",
        "ida_dirtree", "ida_diskio", "ida_entry", "ida_enum", "ida_expr",
        "ida_fixup", "ida_fpro", "ida_frame", "ida_funcs", "ida_gdl",
        "ida_graph", "ida_hexrays", "ida_ida", "ida_idaapi", "ida_idc",
        "ida_idd", "ida_idp", "ida_ieee", "ida_kernwin", "ida_lines",
        "ida_loader", "ida_merge", "ida_mergemod", "ida_moves", "ida_nalt",
        "ida_name", "ida_netnode", "ida_offset", "ida_pro", "ida_problems",
        "ida_range", "ida_registry", "ida_search", "ida_segment",
        "ida_segregs", "ida_srclang", "ida_strlist", "ida_struct",
        "ida_tryblks", "ida_typeinf", "ida_ua", "ida_xref",
        "idc", "idautils", "idaapi",
    ]

    def __init__(
        self,
        ida_dir,
        binary_path,
        override_import=True,
        bits=64,
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
    ) -> None:
        self.backend_type, self.ida_path = resolve_ida_path(ida_dir, bits)
        self.cleaned_up = False
        atexit.register(self.clean_up)

        if self.backend_type == IDABackendType.IDALIB:
            self._idalib_backend(
                self.ida_path, binary_path, ftype=ftype, processor=processor,
            )
        elif self.backend_type in (IDABackendType.IDA, IDABackendType.IDAT):
            self._ida_backend(
                self.ida_path, binary_path, ftype=ftype, processor=processor,
            )

        if override_import:
            self.override_import()

    def _idalib_backend(self, idalib_path, binary_path, **kwargs):
        self.libida = ctypes.cdll.LoadLibrary(idalib_path)
        self.libida.init_library(0, None)

        if not hasattr(self.libida, "get_library_version"):
            major, minor = 9, 0
        else:
            major, minor, build = ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
            self.libida.get_library_version(
                ctypes.byref(major), ctypes.byref(minor), ctypes.byref(build),
            )
            major, minor = major.value, minor.value

        if major == 9 and minor == 0:
            sys.path.insert(0, os.path.join(os.path.dirname(idalib_path), "python/3/ida_64"))
            sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python/3"))
        else:
            sys.path.insert(0, os.path.join(os.path.dirname(idalib_path), "python/lib-dynload"))
            sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python"))

        tempdir = tempfile.mkdtemp()
        shutil.copy(binary_path, tempdir)
        target_file = os.path.join(tempdir, os.path.basename(binary_path))

        ida_args = []
        if kwargs.get("processor"):
            ida_args.append(f'-p{kwargs["processor"]}')
        if kwargs.get("ftype"):
            ida_args.append(f'-T{kwargs["ftype"]}')

        open_args = [str(target_file).encode(), True]
        if not (major == 9 and minor == 0):
            open_args.append(' '.join(ida_args).encode() if ida_args else None)
        self.libida.open_database(*open_args)

    def _ida_backend(self, idat_path, binary_path, **kwargs):
        port = alloc_port()
        is_idb = binary_path.endswith(".i64") or binary_path.endswith(".idb")

        if is_idb:
            tempidb = tempfile.NamedTemporaryFile(suffix=binary_path[-4:])
            with open(binary_path, "rb") as f:
                tempidb.write(f.read())
            tempidb.flush()
            self._tempidb = tempidb
            proc = launch_ida(idat_path, port, tempidb.name, pack=True, **kwargs)
        else:
            tempidb = tempfile.NamedTemporaryFile()
            self._tempidb = tempidb
            proc = launch_ida(idat_path, port, binary_path,
                              output=tempidb.name, **kwargs)

        self.conn = wait_and_connect(proc, "localhost", port)

    def override_import(self):
        self._original_import = builtins.__import__

        def ida_import(name, *args, **kwargs):
            if name in self.IDA_MODULES:
                return self.import_module(name)
            return self._original_import(name, *args, **kwargs)

        builtins.__import__ = ida_import

    def import_module(self, mod):
        if hasattr(self, "libida"):
            return importlib.import_module(mod)
        if hasattr(self, "conn"):
            return self.conn.root.import_module(mod)
        raise RuntimeError("No IDA backend initialized")

    def clean_up(self):
        if self.cleaned_up:
            return
        if hasattr(self, '_original_import'):
            builtins.__import__ = self._original_import
        if hasattr(self, "libida"):
            self.libida.close_database(True)
        if hasattr(self, "conn"):
            self.conn.close()
        self.cleaned_up = True

    def __del__(self):
        self.clean_up()


def download_i64(host, port, binary_path, output_path,
                 ftype=None, processor=None):
    """Send a binary to a headless-ida server for analysis, save the .i64.

    If binary_path is already a .i64/.idb, copies directly.
    """
    if binary_path.endswith('.i64') or binary_path.endswith('.idb'):
        shutil.copy2(binary_path, output_path)
        return

    # Reuse the normal remote-session flow so analyze/open logic stays
    # unified.  We immediately export the database and disconnect.
    ida = HeadlessIdaRemote(host, port, binary_path,
                            override_import=False,
                            ftype=ftype, processor=processor)
    try:
        i64_data = ida.conn.root.save_database()
        with open(output_path, "wb") as f:
            f.write(i64_data)
    finally:
        ida.clean_up()


class HeadlessIdaRemote(HeadlessIda):
    """Connect to a headless-ida server.

    Sends the file to the server, which starts IDA and returns a port.
    The client then connects directly to IDA's RPyC service.
    """

    def __init__(self, host, port, binary_path, override_import=True,
                 ftype=None, processor=None):
        self.cleaned_up = False
        atexit.register(self.clean_up)

        with open(binary_path, "rb") as f:
            file_data = f.read()

        self.conn = rpyc.connect(
            host, int(port), service=ForwardIO,
            config={"sync_request_timeout": 60 * 60 * 24},
        )

        result = self.conn.root.run(
            file_data, ftype=ftype, processor=processor,
        )

        _ida_host, ida_port = result
        self.conn.close()
        self.conn = wait_and_connect(None, host, ida_port, timeout=30)

        if override_import:
            self.override_import()
