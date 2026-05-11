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
