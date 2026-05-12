# discord-wrangler — proxy mode smoke test

Step-by-step manual procedure for verifying SOCKS5 and HTTP proxy modes against a real Discord client. Tests run end-to-end against your own SSH-accessible remote box.

For an end-to-end automated check (cgroup → relay → SOCKS5 → echo, no real Discord), use `tests/integration/test_cgroup_redirect.sh` instead.

---

## Common preamble (do once)

Build and reinstall the latest binary:

```sh
cd /home/buga/Dev/discord-rover
make clean && make
sudo make install
```

Keep two terminals open for the whole session:

- **Terminal A** — watch the daemon journal:
  ```sh
  journalctl -u discord-wrangler -f
  ```
- **Terminal B** — anywhere you'll run ad-hoc commands.

If Discord is already running, close it before any test:

```sh
pkill -f Discord
sleep 1
pgrep -f Discord    # should print nothing
```

Confirm your UID:

```sh
id -u    # probably 1000
```

---

## Test 1 — SOCKS5 proxy

### 1.1 Stand up a SOCKS5 endpoint

Open a third terminal and leave it running for the whole SOCKS5 test:

```sh
# Terminal C
ssh -D 1080 -N your-vps
```

`-D 1080` makes ssh listen on `localhost:1080` and forward SOCKS5 through the remote box. `-N` = no remote command.

Verify it's live from Terminal B:

```sh
curl --socks5 127.0.0.1:1080 https://api.discord.com/api/v9/gateway
```

You should see a JSON response. If not, fix the tunnel before continuing.

### 1.2 Configure the daemon

```sh
sudo $EDITOR /etc/discord-wrangler/discord-wrangler.conf
```

Set:

```ini
[wrangler]
proxy        = socks5://127.0.0.1:1080
relay_port   = 41080
discord_uid  = 1000
```

If you ever add `user:password@` to the URL, also:

```sh
sudo chmod 0600 /etc/discord-wrangler/discord-wrangler.conf
```

### 1.3 Restart and verify

```sh
sudo systemctl daemon-reload
sudo systemctl restart discord-wrangler
```

Terminal A should show:

```
discord-wranglerd starting: queue=0 ... proxy=enabled
relay: upstream proxy = socks5://127.0.0.1:1080
relay: listening on 127.0.0.1:41080 and [::1]
nfqueue 0 attached
```

### 1.4 Launch Discord through the wrapper

```sh
discord-wrangler-launch
```

Within a second, Terminal A should show:

```
cgroup: scope appeared -- installing rules
nft: installing proxy rules (cgroup=user.slice/user-1000.slice/...)
```

### 1.5 Verify the redirect is active

In Terminal B, while Discord is open:

```sh
sudo nft list table inet discord_wrangler_proxy     # rule should be present
sudo ss -tnp 'sport = :41080'                        # active connections to the relay
```

You should see one or more `ESTAB` connections to `:41080`.

### 1.6 Exercise the path inside Discord

| Action | What it verifies |
|---|---|
| Open a server | REST API works (TCP → SOCKS5) |
| Send a message | Gateway WebSocket works (TCP → SOCKS5) |
| Join a voice channel and speak | UDP voice bypass works (Direct mode, *not* via SOCKS5) |

If all three work: **SOCKS5 PASS**.

### 1.7 Clean up

Close Discord (File → Quit). Stop the SSH tunnel:

```sh
# Terminal C
Ctrl-C
```

Terminal A should show:

```
cgroup: scope disappeared -- removing rules
```

---

## Test 2 — HTTP proxy

You need an HTTP CONNECT proxy somewhere reachable. Easiest: run `tinyproxy` on the same VPS you used in Test 1.

### 2.1 Set up tinyproxy on your VPS

```sh
ssh your-vps
sudo apt install tinyproxy      # or pacman -S / dnf install
sudo $EDITOR /etc/tinyproxy/tinyproxy.conf
```

Edit:

```
Port 8888
Listen 0.0.0.0
Allow 0.0.0.0/0           # or restrict to your IP
ConnectPort 443
ConnectPort 80
DisableViaHeader Yes
```

Then:

```sh
sudo systemctl restart tinyproxy
sudo ufw allow 8888/tcp   # or however your firewall is set up
```

Verify from your local box, Terminal B:

```sh
curl -x http://your-vps-ip:8888 https://api.discord.com/api/v9/gateway
```

You should see a JSON response.

### 2.2 Configure the daemon

```sh
sudo $EDITOR /etc/discord-wrangler/discord-wrangler.conf
```

Change `proxy` to point at your tinyproxy:

```ini
proxy = http://your-vps-ip:8888
```

If you set up tinyproxy with username/password, use `http://user:pass@your-vps-ip:8888` and `sudo chmod 0600` the conf.

### 2.3 Restart and verify

```sh
sudo systemctl restart discord-wrangler
```

Terminal A should now show:

```
relay: upstream proxy = http://your-vps-ip:8888
```

### 2.4 Launch and exercise

```sh
pkill -f Discord ; sleep 1
discord-wrangler-launch
```

Same checks as in 1.5–1.6. If REST + messaging + voice all work: **HTTP PASS**.

If you get errors in Terminal A:

| Log line | Means |
|---|---|
| `http_connect: rejected with status 407` | Wrong credentials |
| `http_connect: rejected with status 5xx` | tinyproxy can't reach upstream (open `ConnectPort` for the right ports?) |
| `relay: dial http://… failed: Connection refused` | tinyproxy isn't listening / firewall is blocking |

### 2.5 Clean up

Close Discord. tinyproxy can stay running on the VPS for next time.

---

## Switching back to Direct mode

Direct mode is the original behavior — UDP voice probes only, no TCP redirection.

```sh
sudo $EDITOR /etc/discord-wrangler/discord-wrangler.conf
```

Comment out (or delete) the `proxy` line:

```ini
[wrangler]
# proxy        = socks5://127.0.0.1:1080
relay_port   = 41080
discord_uid  = 1000
```

`relay_port` and `discord_uid` can stay — they're ignored when `proxy` is unset.

Restart:

```sh
sudo systemctl restart discord-wrangler
```

Terminal A should show:

```
discord-wranglerd starting: queue=0 ... proxy=disabled
```

Note: no `relay: listening` line, no `cgroup: scope appeared`. The daemon is back to pure Direct mode.

Now launch Discord **without** the wrapper:

```sh
discord       # or click the desktop entry
```

UDP voice bypass still works. To confirm the proxy side is off:

```sh
sudo nft list ruleset | grep discord_wrangler
```

You should only see the UDP-side `discord_wrangler` table. The TCP-side `discord_wrangler_proxy` table should be absent.

You can toggle freely from now on by editing the `proxy` line and running `sudo systemctl restart discord-wrangler`.

---

## Troubleshooting cheatsheet

| Symptom | First place to look |
|---|---|
| Discord fails to log in (with proxy enabled) | Terminal A — look for `socks5: ...` or `http_connect: ...` errors |
| Voice fails, TCP works | Direct mode is broken — check NFQUEUE rule with `sudo nft list table inet discord_wrangler` |
| Nothing happens when you click stuff in Discord | `sudo systemctl status discord-wrangler` — daemon may have crashed |
| `cgroup: scope appeared` but no `nft: installing` | Probably a cgroup-path issue — see `tests/integration/test_cgroup_redirect.sh` for the diagnostic procedure |
| Daemon won't start | `journalctl -u discord-wrangler -n 50` — look for the exact exit reason |
