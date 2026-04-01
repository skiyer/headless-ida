import os
import platform
import re
import signal
import site
import socket
import subprocess
import sys
import time
from enum import Enum, auto

import rpyc


class ForwardIO(rpyc.Service):
    def exposed_stdout_write(self, data):
        print(data, end="", file=sys.stdout)

    def exposed_stderr_write(self, data):
        print(data, end="", file=sys.stderr)


class IDABackendType(Enum):
    IDA = auto()
    IDAT = auto()
    IDALIB = auto()


def resolve_ida_path(path, bits=64):
    IDA_BINARIES = {
        "Windows": {
            "idalib": ["idalib64.dll", "idalib.dll"],
            "ida": ["ida64.exe", "ida.exe"],
            "idat": ["idat64.exe", "idat.exe"],
        },
        "Linux": {
            "idalib": ["libidalib64.so", "libidalib.so"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
        "Darwin": {
            "idalib": ["libidalib64.dylib", "libidalib.dylib"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
    }

    system = platform.system()
    if system not in IDA_BINARIES:
        raise ValueError(f"Unsupported platform: {system}")

    binaries = IDA_BINARIES[system]

    if os.path.isfile(path):
        filename = os.path.basename(path)
        if filename in binaries["idalib"]:
            return IDABackendType.IDALIB, path
        if filename in binaries["ida"]:
            return IDABackendType.IDA, path
        if filename in binaries["idat"]:
            return IDABackendType.IDAT, path

    elif os.path.isdir(path):
        for idalib_binary in binaries["idalib"]:
            idalib_path = os.path.join(path, idalib_binary)
            if os.path.exists(idalib_path):
                return IDABackendType.IDALIB, idalib_path

        idat_binary = binaries["idat"][0 if bits == 64 else 1]
        idat_path = os.path.join(path, idat_binary)
        if os.path.exists(idat_path):
            return IDABackendType.IDAT, idat_path

        ida_binary = binaries["ida"][0 if bits == 64 else 1]
        ida_path = os.path.join(path, ida_binary)
        if os.path.exists(ida_path):
            return IDABackendType.IDA, ida_path

    raise ValueError(f"Invalid IDA path: {path}")


# ---------------------------------------------------------------------------
# Shared IDA process helpers (used by both client and server)
# ---------------------------------------------------------------------------

_IDA_SCRIPT = os.path.join(
    os.path.realpath(os.path.dirname(__file__)), "ida_script.py"
)

_SAFE_ARG_RE = re.compile(r'^[a-zA-Z0-9_.:\-/]+$')


def _check_ida_arg(name, value):
    """Validate user-supplied IDA arguments (defense in depth)."""
    if not _SAFE_ARG_RE.match(value):
        raise ValueError(
            f"Invalid {name}: {value!r} "
            f"(only alphanumeric, dots, colons, dashes, slashes allowed)"
        )


def setup_pythonpath():
    """Ensure IDA's embedded Python can find rpyc and other site-packages."""
    os.environ["PYTHONPATH"] = (
        os.pathsep.join(site.getsitepackages() + [site.getusersitepackages()])
        + os.pathsep
        + os.environ.get("PYTHONPATH", "")
    )


def alloc_port():
    """Allocate a free TCP port."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def build_ida_command(ida_path, port, input_path, *,
                      host="localhost", ftype=None, processor=None,
                      ready=None, claimed=None, pack=False, output=None):
    """Build an IDA command as a list (safe for shell=False).

    Args:
        ida_path:   Path to ida/idat binary.
        port:       RPyC port for ida_script.py.
        input_path: Binary or .i64 to open.
        host:       RPyC bind host.
        ftype:      -T file type.
        processor:  -p processor type.
        ready:      Path for ready-signal file (server polls this).
        claimed:    Path touched once a client connects to the IDA RPyC port.
        pack:       If True, add -P+ (open packed .i64).
        output:     If set, add -o (output database path).
    """
    if ftype is not None:
        _check_ida_arg("ftype", ftype)
    if processor is not None:
        _check_ida_arg("processor", processor)

    # -S value: IDA parses this internally (quotes handle spaces in path)
    s_value = f'"{_IDA_SCRIPT}" {port} {host}'
    if ready:
        s_value += f" ready:{ready}"
    if claimed:
        s_value += f" claimed:{claimed}"

    cmd = [ida_path]
    if output:
        cmd.append(f'-o{output}')
    cmd.extend(['-A', f'-S{s_value}'])
    if pack:
        cmd.append('-P+')
    if ftype is not None:
        cmd.extend(['-T', ftype])
    if processor is not None:
        cmd.append(f'-p{processor}')
    cmd.append(input_path)
    return cmd


def launch_ida(ida_path, port, input_path, *, new_session=False, **kwargs):
    """Build command, set up PYTHONPATH, and start IDA subprocess.

    Returns the Popen object.  Keyword args (except *new_session*) are
    forwarded to ``build_ida_command``.

    Args:
        new_session:  If True, start the process in a new session/group
                      so ``terminate_process_tree`` can kill it by pgid.
                      Only used by the server; local mode leaves it False
                      so Ctrl-C propagates naturally.
    """
    setup_pythonpath()
    env = os.environ.copy()
    env["IDA_NO_HISTORY"] = "1"
    command = build_ida_command(ida_path, port, input_path, **kwargs)

    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": env,
    }
    if new_session:
        if os.name == "nt":
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_kwargs["start_new_session"] = True

    return subprocess.Popen(command, **popen_kwargs)


def terminate_process_tree(proc, *, timeout=5):
    """Terminate an IDA subprocess and its children best-effort."""
    if proc is None or proc.poll() is not None:
        return

    try:
        if os.name == "nt":
            proc.terminate()
        else:
            os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass

    deadline = time.monotonic() + timeout
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.1)

    if proc.poll() is not None:
        return

    try:
        if os.name == "nt":
            proc.kill()
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def wait_and_connect(proc, host, port, *, service=ForwardIO, timeout=None):
    """Poll-connect to an IDA RPyC server that is still starting up.

    If *timeout* is None and *proc* is given, waits indefinitely as long
    as the process is alive (for local mode where analysis time is unknown).
    If *timeout* is set, gives up after that many seconds (for remote mode).
    Raises if the IDA process exits before we connect.
    """
    import time as _time
    deadline = _time.monotonic() + timeout if timeout else None
    last_exc = None
    while True:
        if proc is not None and proc.poll() is not None:
            raise Exception(
                f"IDA exited before RPyC was ready (rc={proc.returncode})\n"
                f"STDOUT: {proc.stdout.read().decode(errors='replace')[:500]}\n"
                f"STDERR: {proc.stderr.read().decode(errors='replace')[:500]}"
            )
        if deadline is not None and _time.monotonic() > deadline:
            msg = (
                f"Failed to connect to IDA RPyC at {host}:{port} "
                f"after {timeout}s"
            )
            if last_exc is not None:
                msg += f"\nLast error: {last_exc}"
            raise Exception(msg)
        try:
            return rpyc.connect(
                host, port, service=service,
                config={"sync_request_timeout": 60 * 60 * 24},
            )
        except Exception as exc:
            last_exc = exc
            _time.sleep(0.1)
