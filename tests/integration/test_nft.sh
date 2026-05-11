#!/usr/bin/env bash
# Verify the nftables rule template parses, loads, and unloads atomically.
# Requires sudo (nft needs netfilter API permissions).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="$ROOT/share/discord-wrangler.nft.in"

if [[ ! -f "$TEMPLATE" ]]; then
    echo "FAIL: template missing: $TEMPLATE"; exit 1
fi

# Render with queue 0
TMP="$(mktemp)"
sed -e 's|@QUEUE_NUM@|0|g' "$TEMPLATE" > "$TMP"

# Syntax check
nft -c -f "$TMP" >/dev/null

# Load
nft -f "$TMP"

# Verify the table exists
nft list table inet discord_wrangler >/dev/null

# Unload
nft delete table inet discord_wrangler

# Verify removal
if nft list table inet discord_wrangler >/dev/null 2>&1; then
    echo "FAIL: table not removed"; exit 1
fi

rm -f "$TMP"
echo "PASS: nftables rule template parses, loads, and unloads cleanly"
