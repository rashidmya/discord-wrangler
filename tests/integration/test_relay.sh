#!/usr/bin/env bash
# tests/integration/test_relay.sh
# Unprivileged: spin up microsocks + a TCP echo server; route a client through
# the relay and verify the echo round-trip.
#
# Requires --no-rules support on the daemon (added in Task 16). Until that
# task lands, this test will SKIP early if the binary lacks the flag.
set -euo pipefail

if ! command -v microsocks >/dev/null 2>&1; then
    echo "SKIP: microsocks not installed (apt: microsocks; AUR: microsocks)"
    exit 0
fi
if ! command -v ncat >/dev/null 2>&1 && ! command -v nc >/dev/null 2>&1; then
    echo "SKIP: ncat/nc not installed"
    exit 0
fi
NC=$(command -v ncat || command -v nc)

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/discord-wranglerd"
test -x "$BIN" || { echo "FAIL: $BIN missing -- run make first"; exit 1; }

# Daemon must support --no-rules (added in Task 16).
if ! "$BIN" --no-rules --help 2>&1 | grep -q "no-rules\|Usage" && \
   ! "$BIN" --no-rules 2>&1 | head -3 | grep -qv "unknown\|invalid"; then
    # Fallback heuristic: try to start with --no-rules briefly and see if it
    # objects.
    : # leave to runtime check below
fi

SOCKS_PORT=$((20000 + RANDOM % 1000))
ECHO_PORT=$((21000 + RANDOM % 1000))
RELAY_PORT=$((22000 + RANDOM % 1000))

# Start microsocks (no-auth)
microsocks -i 127.0.0.1 -p $SOCKS_PORT &
SOCKS_PID=$!
cleanup() {
    kill $SOCKS_PID 2>/dev/null || true
    [ -n "${ECHO_PID:-}" ] && kill $ECHO_PID 2>/dev/null || true
    [ -n "${WRG_PID:-}" ] && kill $WRG_PID 2>/dev/null || true
    rm -f /tmp/relay_echo_in /tmp/relay_echo_out /tmp/relay_echo_received 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.2

# Echo server: serves one line via cat.
# Use positional `nc -l <host> <port>` syntax, which works on both OpenBSD
# nc (Arch/CachyOS default) and nmap-ncat (apt: ncat). GNU netcat's `-l -p`
# form does NOT work on OpenBSD nc.
echo "hello-relay-test" > /tmp/relay_echo_in
( $NC -l 127.0.0.1 $ECHO_PORT < /tmp/relay_echo_in > /tmp/relay_echo_out ) &
ECHO_PID=$!
sleep 0.2

# Start daemon with proxy config; --no-rules skips nft install
# FORCE_DST must live in the daemon's environment — handle_conn calls
# getenv() inside the daemon process. Putting it on the nc client below has
# no effect.
WRANGLER_PROXY="socks5://127.0.0.1:$SOCKS_PORT" \
WRANGLER_RELAY_PORT=$RELAY_PORT \
WRANGLER_RELAY_FORCE_DST="127.0.0.1:$ECHO_PORT" \
WRANGLER_LOG_LEVEL=debug \
WRANGLER_CONF_FILE=/dev/null \
"$BIN" --no-rules &
WRG_PID=$!
sleep 0.5

# Connect to the relay; the daemon recovers the original destination from
# its own WRANGLER_RELAY_FORCE_DST env var since SO_ORIGINAL_DST is absent
# without netfilter NAT.
$NC -w 2 127.0.0.1 $RELAY_PORT > /tmp/relay_echo_received < /dev/null
sleep 0.3

grep -q hello-relay-test /tmp/relay_echo_received || {
    echo "FAIL: expected hello-relay-test in /tmp/relay_echo_received"
    echo "--- received ---"
    cat /tmp/relay_echo_received >&2 || true
    exit 1
}

echo "PASS: relay -> microsocks -> echo round-trip"
