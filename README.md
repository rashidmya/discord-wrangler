# discord-wrangler

Fixes Discord voice chat on networks that block it (UAE residential ISPs, mainly), without a VPN or proxy.

It's a small daemon. When you join a voice channel, it injects two throwaway UDP packets onto the wire before Discord's first real voice packet goes out. That's enough to confuse the DPI box that signature-matches the 74-byte voice IP-discovery packet, so the connection completes and audio actually flows.

Linux port of the Direct mode in [hdrover/discord-drover](https://github.com/hdrover/discord-drover) (Windows DLL). The Windows version hooks Winsock in-process via DLL detours. That doesn't translate to Linux because Discord's voice runtime (Chromium WebRTC, libuv, and increasingly Rust crates like rustix doing direct syscalls and io_uring) bypasses libc — so LD_PRELOAD can't see the relevant packets. This implementation runs in kernel space via nftables NFQUEUE instead, which catches the packet after it's been handed off no matter how it was submitted.

## How it works

Discord sends an outgoing UDP packet. An nftables rule on the OUTPUT chain matches "first packet of a new flow, UDP, payload exactly 74 bytes" and hands it off to the daemon. The daemon forges two small UDP packets with the same 5-tuple (so they look like part of the same flow), sends them via raw socket, waits 50 ms, then tells the kernel to release Discord's original packet.

From the DPI's perspective, the first packet of the flow is now a 1-byte garbage packet instead of the recognizable IP-discovery one, and it lets the rest of the connection through.

Nothing else changes. No proxy. No VPN. No kernel module. The daemon runs as a dedicated system user with `CAP_NET_ADMIN` and `CAP_NET_RAW` and no other privileges. If the daemon stops or crashes, the nftables rule has a `bypass` flag, so packets just pass through normally — Discord still works (voice will fail again on a blocked network, but nothing else breaks).

## Build and install

### Arch / CachyOS

```sh
sudo pacman -S libnetfilter_queue libnfnetlink nftables
make
sudo make install
```

### Ubuntu / Debian

```sh
sudo apt update
sudo apt install build-essential libnetfilter-queue-dev libmnl-dev nftables
make
sudo make install
```

`make install` puts the daemon in `/usr/local/sbin/`, installs the systemd unit and nftables rule, creates a `discord-wrangler` system user, and enables the service. Check it's running:

```sh
systemctl status discord-wrangler
journalctl -u discord-wrangler -f
```

Then just launch Discord like normal.

## Configuration

Override the defaults with `sudo systemctl edit discord-wrangler` (creates a drop-in override file).

| Variable | Default | Purpose |
|---|---|---|
| `WRANGLER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `WRANGLER_PACKET_FILE` | unset | Path to a custom probe payload, sent before the 0x00/0x01 probes. Useful if your network's DPI needs more aggressive cover traffic than two single-byte probes. |
| `WRANGLER_FIRST_LEN` | `74` | UDP payload length to match on. Bump this if Discord changes the protocol. |
| `WRANGLER_HOLD_MS` | `50` | How long to delay Discord's original packet after sending the probes. |
| `WRANGLER_QUEUE_NUM` | `0` | NFQUEUE queue number. Has to match the nftables rule. |

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

## Credits

The Direct-mode concept and the specific 0x00 / 0x01 probe sequence are from [hdrover/discord-drover](https://github.com/hdrover/discord-drover). All credit for figuring out that the probe pattern works against this kind of DPI goes there.

doctest is vendored at `tests/unit/doctest.h` (MIT, by Viktor Kirilov).
