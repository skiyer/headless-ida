import importlib
import os
import sys
import threading

import ida_auto
import ida_loader
import ida_pro
import idc
import rpyc


if __name__ == "__main__":
    ida_auto.auto_wait()

    # Remove the current file from IDA's recent-files history.
    # Headless mode always uses temp paths; recording them pollutes
    # the history seen in the interactive GUI.
    if os.environ.get("IDA_NO_HISTORY"):
        try:
            import ida_registry
            current_file = idc.get_idb_path() or idc.get_input_file_path()
            if current_file:
                for key in ("History", "History64"):
                    items = list(ida_registry.reg_read_strlist(key) or [])
                    if current_file in items:
                        items.remove(current_file)
                        ida_registry.reg_delete_subkey(key)
                        for item in items:
                            ida_registry.reg_update_filestrlist(key, item, 100)
        except Exception:
            pass

    port = int(idc.ARGV[1])
    claimed_file = None
    for arg in idc.ARGV[3:]:
        if arg.startswith("claimed:"):
            claimed_file = arg[8:]
            break

    client_connected = threading.Event()

    # RPyC server mode: serve IDA API to a single client.
    class HeadlessIda(rpyc.Service):
        def on_connect(self, conn):
            client_connected.set()
            if claimed_file:
                try:
                    with open(claimed_file, "w") as f:
                        f.write("1")
                except Exception:
                    pass
            ida_loader.set_database_flag(ida_loader.DBFL_KILL)
            sys.stdout.write = conn.root.stdout_write
            sys.stderr.write = conn.root.stderr_write

        def on_disconnect(self, conn):
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            ida_pro.qexit(0)

        def exposed_import_module(self, mod):
            return importlib.import_module(mod)

        def exposed_save_database(self):
            """Save current database state and return .i64 bytes."""
            import tempfile, os
            fd, tmp = tempfile.mkstemp(suffix=".i64")
            os.close(fd)
            ida_loader.save_database(tmp, 0)
            with open(tmp, "rb") as f:
                data = f.read()
            os.unlink(tmp)
            return data

    bind_host = "localhost"
    if len(idc.ARGV) > 2:
        bind_host = idc.ARGV[2]

    t = rpyc.utils.server.OneShotServer(
        HeadlessIda, port=port, hostname=bind_host,
        protocol_config={"allow_all_attrs": True},
    )

    # Watchdog: if no client connects within 60s, force-close the listener
    # so that t.start() unblocks and the script exits normally.
    # Note: ida_pro.qexit() is unreliable from non-main threads, so we
    # close the server socket instead and fall through to os._exit.
    def _watchdog():
        import time
        time.sleep(60)
        if not client_connected.is_set():
            try:
                t.close()
            except Exception:
                pass
            os._exit(1)
    threading.Thread(target=_watchdog, daemon=True).start()

    # Signal readiness AFTER socket is bound, BEFORE .start() blocks on accept.
    for arg in idc.ARGV[3:]:
        if arg.startswith("ready:"):
            with open(arg[6:], "w") as f:
                f.write("1")
            break

    t.start()
