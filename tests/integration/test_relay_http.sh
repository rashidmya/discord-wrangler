#!/usr/bin/env bash
# tests/integration/test_relay_http.sh
# Unprivileged: HTTP CONNECT proxy round-trip.
set -euo pipefail

if ! command -v tinyproxy >/dev/null 2>&1; then
    echo "SKIP: tinyproxy not installed"
    exit 0
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/discord-wranglerd"
test -x "$BIN" || { echo "FAIL: $BIN missing"; exit 1; }

PROXY_PORT=$((23000 + RANDOM % 1000))
RELAY_PORT=$((24000 + RANDOM % 1000))

CONF=$(mktemp)
cat > "$CONF" <<EOF
Port $PROXY_PORT
Listen 127.0.0.1
Timeout 5
LogLevel Warning
DisableViaHeader Yes
ConnectPort 1-65535
EOF
tinyproxy -d -c "$CONF" &
PROXY_PID=$!
cleanup() {
    kill $PROXY_PID 2>/dev/null || true
    [ -n "${WRG_PID:-}" ] && kill $WRG_PID 2>/dev/null || true
    rm -f "$CONF" /tmp/relay_http_response 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.3

# FORCE_DST must live in the daemon's environment so handle_conn's getenv()
# sees it. The client-side nc has no effect.
WRANGLER_PROXY="http://127.0.0.1:$PROXY_PORT" \
WRANGLER_RELAY_PORT=$RELAY_PORT \
WRANGLER_RELAY_FORCE_DST="93.184.216.34:80" \
WRANGLER_CONF_FILE=/dev/null \
"$BIN" --no-rules &
WRG_PID=$!
sleep 0.5

# Try to fetch example.com via the relay -> tinyproxy -> upstream.
# Skip if no internet egress is available.
if ! timeout 5 bash -c 'echo -e "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n" | nc 127.0.0.1 '"$RELAY_PORT" \
     > /tmp/relay_http_response 2>&1; then
    echo "SKIP: no internet egress (relay HTTP test needs example.com reachable)"
    exit 0
fi

grep -q "HTTP/1\.[01] 200" /tmp/relay_http_response || {
    echo "FAIL: expected 200 OK"
    head -20 /tmp/relay_http_response >&2
    exit 1
}

echo "PASS: relay -> tinyproxy -> example.com"
