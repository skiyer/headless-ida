#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  cat <<'EOF'
Usage:
  scripts/test-server-disconnect-cleanup.sh <ida_path> <small_binary>

Examples:
  scripts/test-server-disconnect-cleanup.sh \
    "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat" \
    "/bin/ls"
EOF
  exit 1
fi

IDA="$1"
BIN="$2"
VENV_BIN="${VENV_BIN:-$HOME/.idapro/venv/bin}"
PYTHON="${PYTHON:-$VENV_BIN/python}"
SERVER_PORT="$($PYTHON - <<'PY'
import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()
PY
)"
WORKDIR="$(mktemp -d /tmp/headless-ida-disconnect.XXXXXX)"
SERVER_PID=""
IDA_PORT=""

cleanup() {
  set +e
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

"$VENV_BIN/headless-ida-server" "$IDA" 127.0.0.1 "$SERVER_PORT" \
  >"$WORKDIR/server.log" 2>&1 &
SERVER_PID="$!"
sleep 2

echo "=== Start leaked-session regression ==="
echo "server pid: $SERVER_PID"
echo "server port: $SERVER_PORT"

IDA_PORT="$($PYTHON - <<PY
import rpyc
from headless_ida.helpers import ForwardIO
with open(r'''$BIN''', 'rb') as f:
    data = f.read()
conn = rpyc.connect('127.0.0.1', int($SERVER_PORT), service=ForwardIO,
                    config={'sync_request_timeout': 60 * 60 * 24})
_host, port = conn.root.run(data)
print(port)
conn.close()
PY
)"

IDA_PORT="$(echo "$IDA_PORT" | tail -n1 | tr -d '[:space:]')"
echo "spawned ida port: $IDA_PORT"
echo "dropped control connection before connecting to ida"

deadline=$((SECONDS + 20))
matched=0
while (( SECONDS < deadline )); do
  if ps -axo pid,command | grep -F "ida_script.py\" $IDA_PORT " | grep -v grep >/dev/null; then
    matched=1
    sleep 1
    continue
  fi
  echo "✅ leaked ida process was cleaned up"
  exit 0
done

echo "❌ ida process still alive after disconnect timeout"
ps -axo pid,ppid,etime,command | grep -F "ida_script.py\" $IDA_PORT " | grep -v grep || true
echo "--- server.log ---"
tail -100 "$WORKDIR/server.log" || true
exit 1
