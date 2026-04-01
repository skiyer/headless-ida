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
    alloc_port, launch_ida, terminate_process_tree,
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
    """Wait for IDA to exit, then remove the entire work directory.

    Used in server mode so that *normally-completed* jobs still get
    their temp dirs cleaned up (the job was claimed, so _cleanup_job
    won't touch it).
    """
    try:
        proc.wait()
    except Exception:
        pass
    shutil.rmtree(work_dir, ignore_errors=True)


def _cleanup_job(job, *, grace=0):
    """Terminate an unclaimed IDA job and clean up its temp dir."""
    claimed_file = job.get("claimed_file")
    if claimed_file and os.path.exists(claimed_file):
        return

    if grace > 0:
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if claimed_file and os.path.exists(claimed_file):
                return
            proc = job.get("proc")
            if proc is None or proc.poll() is not None:
                return
            time.sleep(0.1)

    proc = job.get("proc")
    if proc is not None and proc.poll() is None:
        terminate_process_tree(proc)

    work_dir = job.get("work_dir")
    if work_dir:
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

        def on_connect(self, conn):
            self._jobs = []

        def on_disconnect(self, conn):
            jobs = list(getattr(self, "_jobs", []))
            if jobs:
                threading.Thread(
                    target=lambda: [_cleanup_job(j, grace=3) for j in jobs],
                    daemon=True,
                ).start()

        def exposed_run(self, data, ftype=None, processor=None):
            """Open a binary or .i64, start IDA, return (host, port).

            Single IDA process: analyzes (if needed) and serves RPyC.
            Blocks until IDA is ready to accept client connections.
            """
            work_dir = tempfile.mkdtemp(dir=_TMP_DIR)
            port = alloc_port()
            ready_file = os.path.join(work_dir, "ready")
            claimed_file = os.path.join(work_dir, "claimed")

            if _is_i64(data):
                input_path = os.path.join(work_dir, "input.i64")
                with open(input_path, "wb") as f:
                    f.write(data)
                proc = launch_ida(
                    ida_path, port, input_path,
                    host="0.0.0.0", pack=True,
                    ready=ready_file, claimed=claimed_file,
                    new_session=True,
                )
            else:
                input_path = os.path.join(work_dir, "input.bin")
                with open(input_path, "wb") as f:
                    f.write(data)
                proc = launch_ida(
                    ida_path, port, input_path,
                    host="0.0.0.0", ready=ready_file, claimed=claimed_file,
                    ftype=ftype, processor=processor,
                    new_session=True,
                )

            job = {
                "proc": proc,
                "work_dir": work_dir,
                "claimed_file": claimed_file,
            }
            self._jobs.append(job)

            threading.Thread(
                target=_dir_reaper, args=(proc, work_dir), daemon=True
            ).start()

            _log(f"[headless-ida-server] waiting for IDA on port {port}…\n")
            try:
                _wait_ready(proc, ready_file)
            except Exception:
                _cleanup_job(job)
                raise
            _log(f"[headless-ida-server] IDA ready on port {port}\n")

            return ("0.0.0.0", port)

    return _HeadlessIdaServer


def _is_i64(data):
    """Check if data starts with an IDA database signature."""
    return data[:4] in (b'IDA1', b'IDA2', b'IDA0')
