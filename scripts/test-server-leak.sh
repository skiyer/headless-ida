#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Process-leak regression tests for headless-ida server mode.
#
# Covers every scenario that was verified during the leak-fix work:
#   1. Remote -c normal exit
#   2. Interactive exit()
#   3. Interactive EOF (Ctrl+D)
#   4. Remote -c long command + kill -9
#   5. Interactive (FIFO) + kill -9
#   6. Control connection drop (never connect to IDA)
#   7. Remote -o export only
#   8. Remote -c + -o (modify + export)
#
# Each test checks that no IDA child processes remain after the client
# disconnects.
#
# Usage:
#   scripts/test-server-leak.sh <ida_path> <small_binary>
#
# Environment variables (optional):
#   VENV_BIN   — directory containing headless-ida, python, etc.
#                (default: the directory of headless-ida found in PATH,
#                 or $HOME/.idapro/venv/bin as last resort)
#   LEAK_WAIT  — max seconds to wait for IDA cleanup (default: 12)
# ---------------------------------------------------------------------------
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'EOF'
Usage:
  scripts/test-server-leak.sh <ida_path> <small_binary>

Examples:
  scripts/test-server-leak.sh \
    "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat" \
    "/bin/ls"
EOF
  exit 1
fi

IDA="$1"
BIN="$2"

# --- locate venv ---
if [[ -z "${VENV_BIN:-}" ]]; then
  _hida="$(command -v headless-ida-server 2>/dev/null || true)"
  if [[ -n "$_hida" ]]; then
    VENV_BIN="$(dirname "$_hida")"
  else
    VENV_BIN="$HOME/.idapro/venv/bin"
  fi
fi
PYTHON="${PYTHON:-$VENV_BIN/python}"
LEAK_WAIT="${LEAK_WAIT:-12}"

# --- temp dir & server ---
WORKDIR="$(mktemp -d /tmp/headless-ida-leak-test.XXXXXX)"
PORT="$("$PYTHON" -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")"
SERVER_PID=""
PASS=0
FAIL=0

cleanup() {
  set +e
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
  # kill any straggling IDA processes spawned by this test
  pkill -f "idat.*-A.*ida_script" 2>/dev/null
  sleep 1
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

"$VENV_BIN/headless-ida-server" "$IDA" 127.0.0.1 "$PORT" \
  >"$WORKDIR/server.log" 2>&1 &
SERVER_PID="$!"
sleep 2

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "FATAL: server failed to start"
  cat "$WORKDIR/server.log"
  exit 1
fi

SERVER="127.0.0.1:$PORT"
echo "=== headless-ida server leak tests ==="
echo "server pid: $SERVER_PID  port: $PORT"
echo "ida:        $IDA"
echo "binary:     $BIN"
echo "venv:       $VENV_BIN"
echo ""

# --- helpers ---

# Wait until no IDA child processes remain (or timeout).
assert_no_leak() {
  local label="$1"
  local deadline=$((SECONDS + LEAK_WAIT))
  while (( SECONDS < deadline )); do
    local n
    n=$(ps -axo pid,command 2>/dev/null \
        | grep 'idat.*-A.*ida_script' | grep -v grep | wc -l | tr -d ' ')
    if [[ "$n" -eq 0 ]]; then
      echo "  ✅ $label"
      PASS=$((PASS + 1))
      return 0
    fi
    sleep 1
  done
  echo "  ❌ $label — IDA process still alive after ${LEAK_WAIT}s"
  ps -axo pid,ppid,etime,command | grep 'idat.*-A.*ida_script' | grep -v grep || true
  FAIL=$((FAIL + 1))
  # kill leftovers so they don't affect the next test
  pkill -f "idat.*-A.*ida_script" 2>/dev/null; sleep 2
  return 1
}

# ---------------------------------------------------------------------------
# 1. Remote -c (normal exit)
# ---------------------------------------------------------------------------
echo "--- 1. Remote -c (normal exit) ---"
out=$("$VENV_BIN/headless-ida" "$SERVER" "$BIN" \
  -c "import idautils; print('fns', len(list(idautils.Functions())))" 2>&1)
echo "  output: $out"
assert_no_leak "remote -c" || true

# ---------------------------------------------------------------------------
# 2. Interactive exit()
# ---------------------------------------------------------------------------
echo "--- 2. Interactive exit() ---"
printf "print('interactive ok')\\nexit()\\n" \
  | "$VENV_BIN/headless-ida" "$SERVER" "$BIN" >/dev/null 2>&1
assert_no_leak "interactive exit()" || true

# ---------------------------------------------------------------------------
# 3. Interactive EOF (Ctrl+D)
# ---------------------------------------------------------------------------
echo "--- 3. Interactive EOF ---"
echo "" | "$VENV_BIN/headless-ida" "$SERVER" "$BIN" >/dev/null 2>&1
assert_no_leak "interactive EOF" || true

# ---------------------------------------------------------------------------
# 4. Remote -c long command + kill -9
# ---------------------------------------------------------------------------
echo "--- 4. Remote -c + kill -9 ---"
"$VENV_BIN/headless-ida" "$SERVER" "$BIN" \
  -c "import time; time.sleep(600)" >/dev/null 2>&1 &
_pid=$!
sleep 4
kill -9 "$_pid" 2>/dev/null || true
wait "$_pid" 2>/dev/null || true
assert_no_leak "kill -9 (running -c)" || true

# ---------------------------------------------------------------------------
# 5. Interactive (FIFO) + kill -9
# ---------------------------------------------------------------------------
echo "--- 5. Interactive FIFO + kill -9 ---"
mkfifo "$WORKDIR/fifo"
"$VENV_BIN/headless-ida" "$SERVER" "$BIN" \
  <"$WORKDIR/fifo" >/dev/null 2>&1 &
_pid=$!
exec 7>"$WORKDIR/fifo"   # keep write-end open so interactive blocks
sleep 4
kill -9 "$_pid" 2>/dev/null || true
exec 7>&-                # close write-end
wait "$_pid" 2>/dev/null || true
assert_no_leak "kill -9 (interactive FIFO)" || true

# ---------------------------------------------------------------------------
# 6. Control connection drop (never connect to IDA)
# ---------------------------------------------------------------------------
echo "--- 6. Control connection drop ---"
"$PYTHON" - <<PY
import rpyc, sys
from headless_ida.helpers import ForwardIO
with open(r'''$BIN''', 'rb') as f:
    data = f.read()
conn = rpyc.connect('127.0.0.1', $PORT, service=ForwardIO,
                     config={'sync_request_timeout': 86400})
conn.root.run(data)
conn.close()
PY
assert_no_leak "control disconnect (unclaimed)" || true

# ---------------------------------------------------------------------------
# 7. Remote -o (export only, no script)
# ---------------------------------------------------------------------------
echo "--- 7. Remote -o ---"
"$VENV_BIN/headless-ida" "$SERVER" "$BIN" \
  -o "$WORKDIR/export.i64" >/dev/null 2>&1
if [[ -f "$WORKDIR/export.i64" ]]; then
  echo "  .i64 written: $(wc -c < "$WORKDIR/export.i64") bytes"
else
  echo "  ❌ export.i64 not created"
  FAIL=$((FAIL + 1))
fi
assert_no_leak "remote -o" || true

# ---------------------------------------------------------------------------
# 8. Remote -c + -o (modify + export)
# ---------------------------------------------------------------------------
echo "--- 8. Remote -c + -o ---"
out=$("$VENV_BIN/headless-ida" "$SERVER" "$WORKDIR/export.i64" \
  -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; ida_name.set_name(ea, 'LEAK_TEST'); print('renamed')" \
  -o "$WORKDIR/modified.i64" 2>&1)
echo "  output: $out"
if [[ -f "$WORKDIR/modified.i64" ]]; then
  echo "  modified .i64 written"
else
  echo "  ❌ modified.i64 not created"
  FAIL=$((FAIL + 1))
fi
assert_no_leak "remote -c + -o" || true

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "==============================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "==============================="

if [[ "$FAIL" -gt 0 ]]; then
  echo ""
  echo "--- server.log ---"
  tail -50 "$WORKDIR/server.log" 2>/dev/null || true
  exit 1
fi

echo ""
echo "✅ All server-mode leak tests passed."
