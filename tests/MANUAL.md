# discord-wrangler — Manual Test Checklist

After build + sudo install, verify on a real Discord client.

## 1. Pre-flight

- `sudo systemctl status discord-wrangler` → `active (running)`
- `sudo nft list table inet discord_wrangler` → shows the queue rule
- `sudo journalctl -u discord-wrangler | tail -5` → shows daemon startup log

## 2. Voice connect smoke test

- Quit any running Discord instances (`pkill -f /home/buga/.config/discord/app-`).
- Open Discord normally (app menu or `discord` from terminal — **no** wrapper script).
- Join a voice channel.
- Watch the logs: `sudo journalctl -u discord-wrangler -f` while joining.
- Expected one log line like:
  ```
  [info]  manipulating: 5-tuple <localIP>/<localPort> -> <remoteIP>/<remotePort> udp_payload=74
  ```

## 3. Real-network voice test (the actual goal)

- On a network where Discord voice is blocked by DPI (UAE-style), confirm voice works in both directions.
- Without the daemon active (`sudo systemctl stop discord-wrangler`), voice should fail again on the same network. This confirms the daemon is doing the work.

## 4. Cleanup test

- `sudo make uninstall`
- Re-verify: `systemctl status discord-wrangler` → `not-found`
- `sudo nft list table inet discord_wrangler` → "No such file" (rule removed)
- Voice fails as before (no manipulation).

## Proxy mode (manual)

### Setup
1. Configure: `sudo $EDITOR /etc/discord-wrangler/discord-wrangler.conf`. Set `proxy`, `discord_uid`, `relay_port`.
2. If your `proxy` includes `user:pass@`, `sudo chmod 0600` the file.
3. Start a SOCKS5 endpoint: `ssh -D 1080 -N your-external-host` (or use a real proxy).
4. Restart the daemon: `sudo systemctl restart discord-wrangler`.
5. Check logs: `journalctl -u discord-wrangler -f`. Expect `relay: listening on 127.0.0.1:41080`.

### Test
1. Launch Discord via `discord-wrangler-launch`.
2. Verify:
   - Discord logs in (REST API works).
   - Messages send (gateway WebSocket works).
   - You can join a voice channel and hear/be-heard (UDP voice bypass still active).
3. Check `nft list table inet discord_wrangler_proxy` shows the redirect rule.
4. Stop Discord. Confirm the daemon journal shows `cgroup: scope disappeared -- removing rules`.

### Failure modes to verify
- Wrong proxy creds → journal shows `socks5: user/pass auth rejected` every 30s while Discord is open. Discord can't log in.
- Proxy down (kill the SSH tunnel mid-session) → journal shows rate-limited dial-failure warnings. Discord shows network errors.
- Wrong `discord_uid` → launcher works, but the daemon's rule doesn't match Discord's cgroup. The TCP redirect doesn't fire (Discord's TCP goes direct); the UDP voice bypass still works.
