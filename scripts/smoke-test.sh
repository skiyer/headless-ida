#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'EOF'
Usage:
  scripts/smoke-test.sh <ida_path> <small_binary>

Examples:
  scripts/smoke-test.sh \
    "/Applications/IDA Professional 9.3.app/Contents/MacOS/ida" \
    "/bin/ls"
EOF
  exit 1
fi

IDA="$1"
BIN="$2"

WORKDIR="$(mktemp -d /tmp/headless-ida-smoke.XXXXXX)"
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()
PY
)"
SERVER_PID=""

cleanup() {
  set +e
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

run_and_check() {
  local title="$1"
  local expected="$2"
  shift 2
  echo ""
  echo "=== $title ==="
  local out
  if ! out="$("$@" 2>&1)"; then
    echo "$out"
    echo "[FAIL] $title"
    exit 1
  fi
  echo "$out"
  if [[ -n "$expected" ]] && ! grep -Fq "$expected" <<<"$out"; then
    echo "[FAIL] Expected output to contain: $expected"
    exit 1
  fi
}

SMALL_I64="$WORKDIR/seed.i64"
LOCAL_MOD_I64="$WORKDIR/local-mod.i64"
REMOTE_CLEAN_I64="$WORKDIR/remote-v1.i64"
REMOTE_MOD_I64="$WORKDIR/remote-v2.i64"
SCRIPT_FILE="$WORKDIR/test_script.py"

cat > "$SCRIPT_FILE" <<'PY'
import idautils
print("script functions:", len(list(idautils.Functions())))
PY

echo "=== Smoke test target ==="
ls -lh "$BIN"
file "$BIN"
echo "IDA: $IDA"
echo "idalib: not covered by this smoke test (undocumented/experimental)"

# ---------------------------------------------------------------------------
# Local mode (README: Command Line + Python API + -o)
# ---------------------------------------------------------------------------

run_and_check "Local CLI: script file" "script functions:" \
  headless-ida "$IDA" "$BIN" "$SCRIPT_FILE"

run_and_check "Local CLI: one-liner" "one-liner functions:" \
  headless-ida "$IDA" "$BIN" -c "import idautils; print('one-liner functions:', len(list(idautils.Functions())))"

run_and_check "Local CLI: interactive console" "interactive local ok" \
  bash -lc "printf \"print('interactive local ok')\\nexit()\\n\" | headless-ida '$IDA' '$BIN'"

run_and_check "Local CLI: save .i64 with -o" "Saved to $SMALL_I64" \
  headless-ida "$IDA" "$BIN" -c "print('seed build')" -o "$SMALL_I64"

test -f "$SMALL_I64" || { echo "[FAIL] Missing $SMALL_I64"; exit 1; }

run_and_check "Local CLI: open pre-analyzed .i64" "local i64 functions:" \
  headless-ida "$IDA" "$SMALL_I64" -c "import idautils; print('local i64 functions:', len(list(idautils.Functions())))"

run_and_check "Local CLI: modify and save new .i64" "Saved to $LOCAL_MOD_I64" \
  headless-ida "$IDA" "$SMALL_I64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; ida_name.set_name(ea, 'LOCAL_SMOKE'); print('renamed')" -o "$LOCAL_MOD_I64"

run_and_check "Local CLI: verify saved modification" "verify: LOCAL_SMOKE" \
  headless-ida "$IDA" "$LOCAL_MOD_I64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; print('verify:', ida_name.get_ea_name(ea))"

run_and_check "Local Python API" "python api local functions:" \
  python3 - <<PY
from headless_ida import HeadlessIda
ida = HeadlessIda(r'''$IDA''', r'''$SMALL_I64''')
import idautils
print('python api local functions:', len(list(idautils.Functions())))
ida.clean_up()
PY

# ---------------------------------------------------------------------------
# Remote mode (README: Server Mode + Save & Export + Python API Remote)
# ---------------------------------------------------------------------------

echo ""
echo "=== Start server ==="
headless-ida-server "$IDA" 0.0.0.0 "$PORT" >"$WORKDIR/server.log" 2>&1 &
SERVER_PID="$!"
sleep 2
SERVER="127.0.0.1:$PORT"

test -n "$SERVER_PID"

run_and_check "Remote CLI: analyze binary and run" "remote binary functions:" \
  headless-ida "$SERVER" "$BIN" -c "import idautils; print('remote binary functions:', len(list(idautils.Functions())))"

run_and_check "Remote CLI: open .i64" "remote i64 functions:" \
  headless-ida "$SERVER" "$SMALL_I64" -c "import idautils; print('remote i64 functions:', len(list(idautils.Functions())))"

run_and_check "Remote CLI: interactive console" "interactive remote ok" \
  bash -lc "printf \"print('interactive remote ok')\\nexit()\\n\" | headless-ida '$SERVER' '$SMALL_I64'"

run_and_check "Remote CLI: download clean .i64 (-o only)" "Saved to $REMOTE_CLEAN_I64" \
  headless-ida "$SERVER" "$BIN" -o "$REMOTE_CLEAN_I64"

test -f "$REMOTE_CLEAN_I64" || { echo "[FAIL] Missing $REMOTE_CLEAN_I64"; exit 1; }

run_and_check "Remote CLI: modify and save .i64 (-c + -o)" "Saved to $REMOTE_MOD_I64" \
  headless-ida "$SERVER" "$REMOTE_CLEAN_I64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; ida_name.set_name(ea, 'REMOTE_SMOKE'); print('renamed')" -o "$REMOTE_MOD_I64"

run_and_check "Remote CLI: verify saved modification" "verify: REMOTE_SMOKE" \
  headless-ida "$SERVER" "$REMOTE_MOD_I64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; print('verify:', ida_name.get_ea_name(ea))"

run_and_check "Remote Python API" "python api remote functions:" \
  python3 - <<PY
from headless_ida import HeadlessIdaRemote
ida = HeadlessIdaRemote('127.0.0.1', $PORT, r'''$SMALL_I64''')
import idautils
print('python api remote functions:', len(list(idautils.Functions())))
ida.clean_up()
PY

# ---------------------------------------------------------------------------
# Version management workflow from README
# ---------------------------------------------------------------------------

run_and_check "Workflow: step 1 analyze and download" "Saved to $WORKDIR/workflow-v1.i64" \
  headless-ida "$SERVER" "$BIN" -o "$WORKDIR/workflow-v1.i64"

run_and_check "Workflow: step 2 annotate and save v2" "Saved to $WORKDIR/workflow-v2.i64" \
  headless-ida "$SERVER" "$WORKDIR/workflow-v1.i64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; ida_name.set_name(ea, 'WORKFLOW_ENTRY'); print('annotated')" -o "$WORKDIR/workflow-v2.i64"

run_and_check "Workflow: step 3 use locally" "workflow verify: WORKFLOW_ENTRY" \
  headless-ida "$IDA" "$WORKDIR/workflow-v2.i64" -c "import ida_name, idautils; ea=list(idautils.Functions())[0]; print('workflow verify:', ida_name.get_ea_name(ea))"

# ---------------------------------------------------------------------------
# History pollution guard
# ---------------------------------------------------------------------------

run_and_check "History pollution check" "tmp history entries: 0" \
  headless-ida "$IDA" "$SMALL_I64" -c "import ida_registry; h=list(ida_registry.reg_read_strlist('History') or []); h64=list(ida_registry.reg_read_strlist('History64') or []); tmp=[x for x in h+h64 if 'headless_ida_tmp' in x or '/var/folders' in x or 'input.bin' in x or 'input.i64' in x]; print('tmp history entries:', len(tmp))"

echo ""
echo "✅ Smoke test passed: documented local, remote, export, workflow, and Python API features all work on a small binary."
