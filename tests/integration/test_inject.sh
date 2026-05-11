#!/usr/bin/env bash
# Sends one UDP packet via the daemon's inject path to localhost and verifies
# the receiver got it correctly. Requires CAP_NET_RAW (raw socket).
#
# Run with: sudo tests/integration/test_inject.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="$ROOT/build"

cc -O2 -Wall -o "$BUILD/udp_receiver" "$ROOT/tests/integration/udp_receiver.c"
make -C "$ROOT" build/inject_driver >/dev/null

PORT=$((40000 + RANDOM % 5000))
LOG="$BUILD/inject_test.log"
rm -f "$LOG"

"$BUILD/udp_receiver" "$PORT" 1 5 > "$LOG" &
RPID=$!
sleep 0.3

# Inject one 1-byte UDP packet (0xAA) from a spoofed src to localhost:$PORT
"$BUILD/inject_driver" 127.0.0.1 12345 127.0.0.1 "$PORT" "aa"

wait "$RPID"

mapfile -t lens < "$LOG"
if [[ "${#lens[@]}" -ne 1 ]] || [[ "${lens[0]}" != "1" ]]; then
    echo "FAIL: expected one 1-byte packet, got: ${lens[*]}"; exit 1
fi
echo "PASS: inject path produces correct UDP packet on the wire"
