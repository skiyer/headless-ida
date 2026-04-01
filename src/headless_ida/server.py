import atexit
import glob
import os
import signal
import shutil
import sys
import tempfile
import threading
import time

import rpyc

from .helpers import (
    IDABackendType, resolve_ida_path,
    alloc_port, launch_ida,
)

_TMP_DIR = os.path.join(tempfile.gettempdir(), "headless_ida_tmp")
os.makedirs(_TMP_DIR, exist_ok=True)


def _log(msg):
    try:
        sys.__stderr__.write(msg)
        sys.__stderr__.flush()
    except Exception:
        pass


def _cleanup_all_tmp():
    """Remove all temp files and dirs (for startup and graceful shutdown)."""
    for path in glob.glob(os.path.join(_TMP_DIR, "*")):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.unlink(path)
        except OSError:
            pass


def _dir_reaper(proc, work_dir):
    """Wait for IDA to exit, then remove the entire work directory."""
    try:
        proc.wait()
    except Exception:
        pass
    shutil.rmtree(work_dir, ignore_errors=True)


def _wait_ready(proc, ready_file):
    """Block until IDA writes the ready signal file, or raise on failure."""
    while not os.path.exists(ready_file):
        if proc.poll() is not None:
            raise RuntimeError(
                f"IDA exited before becoming ready (rc={proc.returncode})\n"
                f"STDOUT: {proc.stdout.read().decode(errors='replace')[:500]}\n"
                f"STDERR: {proc.stderr.read().decode(errors='replace')[:500]}"
            )
        time.sleep(0.1)
    os.unlink(ready_file)


def HeadlessIdaServer(idat_path):
    backend_type, ida_path = resolve_ida_path(idat_path)

    if backend_type == IDABackendType.IDALIB:
        raise RuntimeError(
            "idalib cannot be used with server mode. "
            "Use ida/idat instead: headless-ida-server /path/to/ida host port"
        )

    _cleanup_all_tmp()
    atexit.register(_cleanup_all_tmp)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    class _HeadlessIdaServer(rpyc.Service):

        def exposed_run(self, data, ftype=None, processor=None):
            """Open a binary or .i64, start IDA, return (host, port).

            Single IDA process: analyzes (if needed) and serves RPyC.
            Blocks until IDA is ready to accept client connections.
            """
            work_dir = tempfile.mkdtemp(dir=_TMP_DIR)
            port = alloc_port()
            ready_file = os.path.join(work_dir, "ready")

            if _is_i64(data):
                input_path = os.path.join(work_dir, "input.i64")
                with open(input_path, "wb") as f:
                    f.write(data)
                proc = launch_ida(ida_path, port, input_path,
                                  host="0.0.0.0", pack=True, ready=ready_file)
            else:
                input_path = os.path.join(work_dir, "input.bin")
                with open(input_path, "wb") as f:
                    f.write(data)
                proc = launch_ida(ida_path, port, input_path,
                                  host="0.0.0.0", ready=ready_file,
                                  ftype=ftype, processor=processor)

            threading.Thread(
                target=_dir_reaper, args=(proc, work_dir), daemon=True
            ).start()

            _log(f"[headless-ida-server] waiting for IDA on port {port}…\n")
            _wait_ready(proc, ready_file)
            _log(f"[headless-ida-server] IDA ready on port {port}\n")

            return ("0.0.0.0", port)

    return _HeadlessIdaServer


def _is_i64(data):
    """Check if data starts with an IDA database signature."""
    return data[:4] in (b'IDA1', b'IDA2', b'IDA0')
