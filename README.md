# Discord Wrangler

A Linux daemon that does two independent things for Discord:

- **UDP voice bypass** (always on) — defeats DPI that blocks Discord voice by signature-matching its IP-discovery packet. The canonical case is UAE residential ISPs.
- **TCP proxy redirect** (opt-in) — routes Discord's TCP (chat, REST, gateway, voice control) through an HTTP or SOCKS5 proxy. Discord has no proxy setting and ignores the system one, so this is the only way.

If your network only blocks voice, you don't need a proxy. If it also blocks Discord's TCP, configure one and the daemon handles both.

## How it works

**UDP voice bypass.** An nftables OUTPUT rule matches the first packet of a new UDP flow with a 74-byte payload and hands it to the daemon. The daemon forges two single-byte probes on the same 5-tuple via raw socket, waits 50 ms, then releases Discord's original packet. To the DPI the flow now opens with garbage instead of the recognizable IP-discovery packet, so it passes. No kernel module; the daemon runs as a dedicated user with only `CAP_NET_ADMIN` and `CAP_NET_RAW`. If it crashes, a `bypass` flag on the rule lets packets through normally.

**TCP proxy redirect.** When `proxy =` is set, the daemon runs a loopback TCP relay and adds a second nftables rule matching a cgroup. The `discord-wrangler-launch` wrapper puts Discord in that cgroup, so its TCP gets redirected to the relay and tunneled upstream via SOCKS5 (RFC 1928/1929) or HTTP CONNECT. UDP voice never goes through the proxy — it's handled by the probe trick above, with or without a proxy.

## Install

**Prerequisites** — a C++17 compiler (`g++` 7+ / `clang++` 5+) plus:

```sh
# Arch / CachyOS
sudo pacman -S libnetfilter_queue libnfnetlink nftables
# Ubuntu / Debian
sudo apt install build-essential libnetfilter-queue-dev libmnl-dev nftables
```

**Build:**

```sh
git clone https://github.com/rashidmya/discord-wrangler.git
cd discord-wrangler
make
sudo make install
```

`make install` installs the daemon to `/usr/local/sbin/`, sets up the systemd unit, nftables rule, and `discord-wrangler` system user, and enables the service. Check it with `systemctl status discord-wrangler`, then launch Discord as normal.

Or grab a [release tarball](https://github.com/rashidmya/discord-wrangler/releases) instead of cloning.

## Enabling the TCP proxy

Edit `/etc/discord-wrangler/discord-wrangler.conf`:

```ini
[wrangler]
proxy       = socks5://user:password@your-proxy:1080
relay_port  = 41080
discord_uid = 1000   ; run `id -u` to find your UID
```

`sudo chmod 0600` the file if it holds credentials, then `sudo systemctl restart discord-wrangler`.

Launch Discord via **Discord Wrangler** (or **PTB** / **Canary**) from your app launcher, or `discord-wrangler-launch` from a terminal. Only these routes drop Discord into the cgroup that triggers the TCP redirect — launching any other way leaves TCP direct (UDP voice still works, since that's packet-shape based).

Supported schemes: `socks5://`, `socks5://user:pass@` (RFC 1929), `http://`, `http://user:pass@` (Basic).

## Uninstall

```sh
sudo make uninstall
```

Removes the binary, systemd unit, nftables rule, and sysusers config. The `discord-wrangler` user is left behind; remove with `sudo userdel discord-wrangler`.

## Tests

```sh
make test    # unit tests (16 cases)
```

Integration tests, proxy-mode fixtures, and the real-network manual checklist are in [`tests/README.md`](tests/README.md).

## Credits

The UDP-probe trick (0x00 / 0x01 sequence) and the TCP-through-proxy idea are from [hdrover/discord-drover](https://github.com/hdrover/discord-drover). 

doctest is vendored at `tests/unit/doctest.h` (MIT, Viktor Kirilov).
