#!/usr/bin/env bash
# tests/integration/test_cgroup_redirect.sh
# Requires sudo. End-to-end: cgroup match -> nftables redirect -> relay -> upstream.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This test requires root (sudo $0)"
    exit 1
fi
for cmd in microsocks systemd-run nc python3; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo "SKIP: $cmd not installed"; exit 0
    fi
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/discord-wranglerd"
test -x "$BIN" || { echo "FAIL: $BIN missing -- run make first"; exit 1; }

# Use a queue number that won't collide with the installed system service
# (which typically owns queue 0). Direct-mode probing isn't exercised by
# this test; we just need the daemon to not error out on init.
TEST_QUEUE=99

# Pick the invoking user for the cgroup (not root, since the launcher
# uses systemd --user). SUDO_USER falls back to the first non-root user.
USERNAME="${SUDO_USER:-$(getent passwd 1000 | cut -d: -f1)}"
USERID=$(id -u "$USERNAME")
test -n "$USERID" || { echo "FAIL: could not pick a user"; exit 1; }

SOCKS_PORT=$((25000 + RANDOM % 1000))
ECHO_PORT=$((26000 + RANDOM % 1000))
RELAY_PORT=$((27000 + RANDOM % 1000))

# Loopback echo server in Python (OpenBSD nc has no --exec equivalent).
# Reads bytes from a single connection and echoes them straight back.
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT))
s.listen(1)
s.settimeout(10)
try:
    c, _ = s.accept()
    while True:
        d = c.recv(4096)
        if not d: break
        c.sendall(d)
    c.close()
except socket.timeout:
    pass
" &
ECHO_PID=$!

microsocks -i 127.0.0.1 -p $SOCKS_PORT &
SOCKS_PID=$!

# Install template under /etc/nftables.d/ from the share/
mkdir -p /etc/nftables.d
install -m 0644 "$ROOT/share/discord-wrangler-proxy.nft.in" \
    /etc/nftables.d/discord-wrangler-proxy.nft.in

# Start the daemon (it installs the proxy rule once the launcher creates
# the scope). WRANGLER_QUEUE_NUM=$TEST_QUEUE keeps it off whatever queue
# the installed system service owns.
WRANGLER_PROXY="socks5://127.0.0.1:$SOCKS_PORT" \
WRANGLER_RELAY_PORT=$RELAY_PORT \
WRANGLER_DISCORD_UID=$USERID \
WRANGLER_QUEUE_NUM=$TEST_QUEUE \
WRANGLER_LOG_LEVEL=debug \
WRANGLER_CONF_FILE=/dev/null \
"$BIN" &
WRG_PID=$!

cleanup() {
    kill $WRG_PID 2>/dev/null || true
    kill $SOCKS_PID 2>/dev/null || true
    kill $ECHO_PID 2>/dev/null || true
    sudo -u "$USERNAME" XDG_RUNTIME_DIR=/run/user/$USERID \
        systemctl --user stop discord-wrangler-discord.scope 2>/dev/null || true
    nft delete table inet discord_wrangler_proxy 2>/dev/null || true
    rm -f /etc/nftables.d/discord-wrangler-proxy.nft.in
    rm -f /tmp/cgroup_redirect_result
}
trap cleanup EXIT

sleep 0.5

# Launch a TCP client inside the scope. Inject DISCORD_BIN via `env` AFTER
# sudo — sudo strips arbitrary env vars by default (no sudoers whitelist
# for DISCORD_BIN), so setting it before `sudo` fails silently and the
# launcher runs the real Discord binary, which exits as a singleton.
chmod +x "$ROOT/share/discord-wrangler-launch"
sudo -u "$USERNAME" \
    env XDG_RUNTIME_DIR=/run/user/$USERID DISCORD_BIN=/bin/sh \
    "$ROOT/share/discord-wrangler-launch" \
    -c "echo hello | nc -w 2 127.0.0.1 $ECHO_PORT" \
    > /tmp/cgroup_redirect_result 2>&1 || true

sleep 1.0

# The cgroup match should redirect to the relay; relay dials microsocks;
# microsocks connects to the destination (127.0.0.1:$ECHO_PORT, which is
# the Python echo server). The echo server echoes "hello" back. We expect
# "hello" to appear in the captured output.
grep -q hello /tmp/cgroup_redirect_result || {
    echo "FAIL: expected hello to round-trip through redirect/relay/socks5/echo"
    echo "--- captured ---"
    cat /tmp/cgroup_redirect_result >&2 || true
    echo "--- nft state ---"
    nft list table inet discord_wrangler_proxy >&2 || true
    exit 1
}

echo "PASS: cgroup redirect end-to-end"
