# Tests

## Unit

```sh
make test    # 16 cases, doctest
```

## Integration

```sh
sudo tests/integration/test_inject.sh     # raw-socket inject end-to-end
sudo tests/integration/test_nft.sh        # nftables rule lifecycle
```

These two need sudo (raw sockets and netfilter rules do).

### Proxy-mode tests

These use external proxy implementations as fixtures. Install on demand:

- Debian/Ubuntu: `sudo apt install tinyproxy microsocks`
- Arch/CachyOS: `sudo pacman -S tinyproxy`, `microsocks` via AUR
- SOCKS5 fallback: `ssh -D 1080 -N localhost` works when neither is installed.

```sh
bash tests/integration/test_launch_gate.sh             # unprivileged
bash tests/integration/test_relay.sh                   # unprivileged
bash tests/integration/test_relay_http.sh              # unprivileged
sudo bash tests/integration/test_cgroup_redirect.sh    # sudo (real netfilter)
```

## Manual checklist

The real proof point is running against a live Discord client on an affected network.

### 1. Pre-flight

- `sudo systemctl status discord-wrangler` → `active (running)`
- `sudo nft list table inet discord_wrangler` → shows the queue rule
- `sudo journalctl -u discord-wrangler | tail -5` → shows daemon startup log

### 2. Voice connect smoke test

- Quit any running Discord (`pkill -f ~/.config/discord/app-`).
- Open Discord normally (app menu or `discord` — **no** wrapper script) and join a voice channel.
- Watch `sudo journalctl -u discord-wrangler -f`. Expect one line like:
  ```
  [info]  manipulating: 5-tuple <localIP>/<localPort> -> <remoteIP>/<remotePort> udp_payload=74
  ```

### 3. Real-network voice test (the actual goal)

- On a network where Discord voice is DPI-blocked (UAE-style), confirm voice works both directions.
- Stop the daemon (`sudo systemctl stop discord-wrangler`) → voice should fail again on the same network. This confirms the daemon is doing the work.

### 4. Cleanup test

- `sudo make uninstall`
- `systemctl status discord-wrangler` → `not-found`
- `sudo nft list table inet discord_wrangler` → "No such file" (rule removed)
- Voice fails as before.

### Proxy mode

**Setup:**

1. Configure `sudo $EDITOR /etc/discord-wrangler/discord-wrangler.conf` — set `proxy`, `discord_uid`, `relay_port`. `sudo chmod 0600` if `proxy` includes `user:pass@`.
2. Start a SOCKS5 endpoint: `ssh -D 1080 -N your-external-host` (or a real proxy).
3. `sudo systemctl restart discord-wrangler`. Logs should show `relay: listening on 127.0.0.1:41080`.

**Test:** launch via `discord-wrangler-launch`, then verify Discord logs in (REST), messages send (gateway), and voice works (UDP bypass). `nft list table inet discord_wrangler_proxy` shows the redirect rule. Stop Discord → journal shows `cgroup: scope disappeared -- removing rules`.

**Failure modes:**

- Wrong proxy creds → `socks5: user/pass auth rejected` every 30s; Discord can't log in.
- Proxy down mid-session → rate-limited dial-failure warnings; Discord shows network errors.
- Wrong `discord_uid` → launcher works but the rule doesn't match Discord's cgroup, so TCP goes direct (UDP voice still works).
