#!/usr/bin/env bash
# tests/integration/test_launch_gate.sh
# Unprivileged: verify discord-wrangler-launch refuses when no proxy is
# configured and proceeds when one is. Stubs systemctl/systemd-run/discord
# on PATH so we don't actually launch Discord.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAUNCH="$ROOT/share/discord-wrangler-launch"
test -x "$LAUNCH" || { echo "FAIL: $LAUNCH missing or not executable"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Stubs: systemctl always reports the user manager is healthy; systemd-run
# echoes a marker we grep for; discord is just a placeholder that never runs
# because systemd-run is stubbed out before the exec reaches it.
cat > "$TMP/systemctl" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$TMP/systemd-run" <<'EOF'
#!/bin/sh
echo "STUB_SYSTEMD_RUN_OK" >&2
exit 0
EOF
cat > "$TMP/discord"        <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$TMP/discord-ptb"    <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$TMP/discord-canary" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$TMP"/systemctl "$TMP"/systemd-run "$TMP"/discord "$TMP"/discord-ptb "$TMP"/discord-canary

run_launch() {
    # $1 = conf path (or empty for unset)
    # Captures combined stdout+stderr; returns the wrapper's exit code.
    local conf="$1"
    local out
    if [ -n "$conf" ]; then
        out=$(env -i HOME="$HOME" PATH="$TMP:/usr/bin:/bin" WRANGLER_CONF="$conf" \
            "$LAUNCH" 2>&1) && rc=0 || rc=$?
    else
        out=$(env -i HOME="$HOME" PATH="$TMP:/usr/bin:/bin" WRANGLER_CONF=/nonexistent/path \
            "$LAUNCH" 2>&1) && rc=0 || rc=$?
    fi
    printf '%s\n' "$out"
    return $rc
}

fail=0

# Case A: conf file is missing -> gate refuses.
out=$(run_launch "" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ] || ! printf '%s' "$out" | grep -q "No proxy configured"; then
    echo "FAIL case A (missing conf): rc=$rc output=$out"
    fail=1
fi

# Case B: conf has commented-out proxy line -> gate refuses.
echo "; proxy = socks5://example:1080" > "$TMP/conf_b"
out=$(run_launch "$TMP/conf_b" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ] || ! printf '%s' "$out" | grep -q "No proxy configured"; then
    echo "FAIL case B (commented proxy): rc=$rc output=$out"
    fail=1
fi

# Case C: conf has empty proxy value -> gate refuses.
printf 'proxy =\n' > "$TMP/conf_c"
out=$(run_launch "$TMP/conf_c" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ] || ! printf '%s' "$out" | grep -q "No proxy configured"; then
    echo "FAIL case C (empty proxy): rc=$rc output=$out"
    fail=1
fi

# Case D: conf has a real proxy value -> gate passes, reaches systemd-run stub.
printf 'proxy = socks5://127.0.0.1:1080\n' > "$TMP/conf_d"
out=$(run_launch "$TMP/conf_d" 2>&1) && rc=0 || rc=$?
if [ $rc -ne 0 ] || ! printf '%s' "$out" | grep -q "STUB_SYSTEMD_RUN_OK"; then
    echo "FAIL case D (proxy set): rc=$rc output=$out"
    fail=1
fi

# Case E: conf has whitespace-only proxy value -> gate refuses.
printf 'proxy =    \n' > "$TMP/conf_e"
out=$(run_launch "$TMP/conf_e" 2>&1) && rc=0 || rc=$?
if [ $rc -eq 0 ] || ! printf '%s' "$out" | grep -q "No proxy configured"; then
    echo "FAIL case E (whitespace-only proxy): rc=$rc output=$out"
    fail=1
fi

if [ $fail -ne 0 ]; then
    echo "FAIL"
    exit 1
fi
echo "OK"
