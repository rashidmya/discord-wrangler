# discord-wrangler

discord-wrangler is a Linux daemon that can force Discord to use a specified proxy server (HTTP or SOCKS5) for its TCP connections (chat, REST API, gateway, voice control). This may be necessary because the Discord client lacks proxy settings and ignores the system-wide proxy.

Additionally, the daemon slightly modifies Discord's outgoing UDP traffic, which helps bypass some local restrictions on voice chats — UAE residential ISPs being the canonical case.

The two pieces are independent. The UDP voice fix runs always. The TCP proxy redirect is opt-in via the conf file. If your network only DPI-blocks voice (the common case), no proxy is needed; if it also blocks Discord's TCP, configure a proxy and the daemon handles both.

Linux equivalent of [hdrover/discord-drover](https://github.com/hdrover/discord-drover). The Windows version hooks Winsock in-process via DLL detours. That doesn't translate to Linux because Discord's voice runtime (Chromium WebRTC, libuv, and increasingly Rust crates like rustix doing direct syscalls and io_uring) bypasses libc — so LD_PRELOAD can't see the relevant packets. This implementation runs in kernel space via nftables NFQUEUE plus a small loopback TCP relay instead.

## How it works

Two independent subsystems run inside the daemon. Both can be active at the same time.

### UDP voice bypass (always on)

Discord sends an outgoing UDP packet. An nftables rule on the OUTPUT chain matches "first packet of a new flow, UDP, payload exactly 74 bytes" and hands it off to the daemon. The daemon forges two small UDP packets with the same 5-tuple (so they look like part of the same flow), sends them via raw socket, waits 50 ms, then tells the kernel to release Discord's original packet.

From the DPI's perspective, the first packet of the flow is now a 1-byte garbage packet instead of the recognizable IP-discovery one, and it lets the rest of the connection through.

No kernel module. The daemon runs as a dedicated system user with `CAP_NET_ADMIN` and `CAP_NET_RAW` and no other privileges. If the daemon stops or crashes, the nftables rule has a `bypass` flag, so packets just pass through normally — Discord still works for everything except voice on a blocked network.

### TCP proxy redirect (opt-in, when `proxy =` is set)

When the conf file has `proxy = socks5://…` or `proxy = http://…`, the daemon also stands up an in-process TCP relay on loopback and installs a second nftables rule that matches a specific cgroup. Discord is placed inside that cgroup by the `discord-wrangler-launch` wrapper; from inside the cgroup, all outgoing TCP gets redirected to the relay, which then tunnels each connection through the upstream proxy via SOCKS5 (RFC 1928/1929) or HTTP CONNECT.

UDP voice does not go through the proxy — HTTP CONNECT is TCP-only by spec, and the SOCKS5 UDP path (`UDP ASSOCIATE`) is not implemented. The UDP probe trick above is the only thing handling UDP voice, with or without a proxy configured. The two subsystems handle different blocks: probes defeat the signature-match on the UDP IP-discovery packet; the proxy moves TCP through a server outside the blocked network.

## Install

### 1. Prerequisites

Arch / CachyOS:

```sh
sudo pacman -S libnetfilter_queue libnfnetlink nftables
```

Ubuntu / Debian:

```sh
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev libmnl-dev nftables
```

You also need a C++17 compiler (`g++` 7+ or `clang++` 5+, included in `build-essential` on Debian/Ubuntu and present by default on Arch).

### 2. Get the source

Clone the repo:

```sh
git clone https://github.com/rashidmya/discord-wrangler.git
cd discord-wrangler
```

Or grab a release tarball (replace `v0.1` with the latest tag from [Releases](https://github.com/rashidmya/discord-wrangler/releases)):

```sh
curl -L https://github.com/rashidmya/discord-wrangler/archive/refs/tags/v0.1.tar.gz | tar xz
cd discord-wrangler-0.1
```

### 3. Build and install

```sh
make
sudo make install
```

`make install` puts the daemon in `/usr/local/sbin/`, installs the systemd unit and nftables rule, creates a `discord-wrangler` system user, and enables the service. Check it's running:

```sh
systemctl status discord-wrangler
journalctl -u discord-wrangler -f
```

Then just launch Discord like normal.

After `sudo make install`, Discord Wrangler shows up in your app launcher — same effect as `discord-wrangler-launch` from a terminal (requires `proxy` to be set in the conf).

## Configuration

Override the defaults with `sudo systemctl edit discord-wrangler` (creates a drop-in override file).

| Variable | Default | Purpose |
|---|---|---|
| `WRANGLER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `WRANGLER_PACKET_FILE` | unset | Path to a custom probe payload, sent before the 0x00/0x01 probes. Useful if your network's DPI needs more aggressive cover traffic than two single-byte probes. |
| `WRANGLER_FIRST_LEN` | `74` | UDP payload length to match on. Bump this if Discord changes the protocol. |
| `WRANGLER_HOLD_MS` | `50` | How long to delay Discord's original packet after sending the probes. |
| `WRANGLER_QUEUE_NUM` | `0` | NFQUEUE queue number. Has to match the nftables rule. |

## Configuring the TCP proxy

Out of the box, only the UDP voice bypass is active and Discord's TCP goes direct. If your network also DPI-blocks Discord's TCP endpoints — chat, REST API, gateway, voice control — configure a proxy in the conf file and the daemon will tunnel Discord's TCP through it. The UDP voice bypass keeps running alongside, unchanged.

### 1. Configure

Edit `/etc/discord-wrangler/discord-wrangler.conf`:

```ini
[wrangler]
proxy       = socks5://user:password@your-proxy:1080
relay_port  = 41080
discord_uid = 1000   ; run `id -u` to find your UID
```

If `proxy` contains credentials, chmod the file:

```sh
sudo chmod 0600 /etc/discord-wrangler/discord-wrangler.conf
```

Then restart the daemon:

```sh
sudo systemctl restart discord-wrangler
```

### 2. Launch Discord via the wrapper

```sh
discord-wrangler-launch    # instead of `discord`
```

This places Discord inside a known cgroup v2 scope. The daemon's nftables rule matches that cgroup and redirects all of Discord's TCP to the in-daemon relay, which tunnels it through the configured upstream proxy.

If you launch Discord without the wrapper, it ends up outside the cgroup and the TCP redirect doesn't apply. The UDP voice bypass still works — that's based on packet shape, not cgroup membership.

### Supported proxy schemes

| Scheme | Auth |
|---|---|
| `socks5://host:port` | none |
| `socks5://user:pass@host:port` | username/password (RFC 1929) |
| `http://host:port` | none (HTTP/1.1 CONNECT) |
| `http://user:pass@host:port` | Basic |

## Uninstall

```sh
sudo make uninstall
```

Removes the binary, systemd unit, nftables rule, and sysusers config. The `discord-wrangler` user is left behind in case you want to reinstall later; remove it with `sudo userdel discord-wrangler` if you really want it gone.

## Tests

```sh
make test                          # unit tests (16 cases)
sudo tests/integration/test_inject.sh   # raw-socket inject end-to-end
sudo tests/integration/test_nft.sh      # nftables rule lifecycle
```

The two integration tests need sudo because raw sockets and netfilter rules do. The actual proof point is `tests/MANUAL.md` — running it against real Discord on the affected network.

### Optional integration test fixtures

The proxy-mode integration tests use external proxy implementations as fixtures.
Install on demand:

- Debian/Ubuntu: `sudo apt install tinyproxy microsocks`
- Arch/CachyOS:  `sudo pacman -S tinyproxy`, `microsocks` via AUR
- Fallback for SOCKS5: `ssh -D 1080 -N localhost` works when neither is available.

Run them:

```sh
bash tests/integration/test_relay.sh                   # unprivileged
bash tests/integration/test_relay_http.sh              # unprivileged
sudo bash tests/integration/test_cgroup_redirect.sh    # sudo (real netfilter)
```

## Credits

Both the UDP-probe trick (with the specific 0x00 / 0x01 byte sequence) and the TCP-through-proxy idea are from [hdrover/discord-drover](https://github.com/hdrover/discord-drover). All credit for figuring out the probe pattern against this kind of DPI goes there.

doctest is vendored at `tests/unit/doctest.h` (MIT, by Viktor Kirilov).
