// discord-wranglerd — NFQUEUE daemon entry.
// Direct mode: UDP voice bypass.
// Proxy mode: TCP through HTTP/SOCKS5.

#include "config.hpp"
#include "direct/flow_table.hpp"
#include "direct/inject.hpp"
#include "direct/nfq_loop.hpp"
#include "direct/packet_file.hpp"
#include "log.hpp"
#include "proxy/cgroup.hpp"
#include "proxy/nft.hpp"
#include "proxy/relay.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <signal.h>
#include <string>
#include <thread>

#ifndef DISCORD_WRANGLER_SYSCONFDIR
#define DISCORD_WRANGLER_SYSCONFDIR "/etc"
#endif

namespace {

// Bundles the state needed by the cgroup-watcher's appear/disappear callbacks.
// Only the boolean is touched concurrently (the watcher fires the callbacks
// serialized in a worker thread); the strings/port are written once before
// the watcher starts.
struct NftRuleCtx {
    std::string         template_path;
    std::string         cgroup_path;
    uint16_t            relay_port = 0;
    std::atomic<bool>   installed{false};
};

// One global pointer used solely to bridge the C signal handler back into
// the NfqLoop instance owned by main(). The signal handler's only action is
// `loop->shutdown()`, which is async-signal-safe (a single self-pipe write).
std::atomic<wrangler::direct::NfqLoop*> g_signal_loop{nullptr};

void on_signal(int) {
    if (auto* loop = g_signal_loop.load(std::memory_order_acquire)) {
        loop->shutdown();
    }
}

void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
}

} // namespace

int main(int argc, char** argv) {
    bool no_rules = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-rules") == 0) no_rules = true;
    }

    wrangler::log::set_level_from_env();
    wrangler::config::Config cfg;
    try {
        cfg = wrangler::config::from_env();
    } catch (const std::exception& e) {
        // config::from_env throws on the 0600-mismatch path. Translate to a
        // clean exit-1 rather than std::terminate.
        WLOG_ERROR("config: %s", e.what());
        return 1;
    }

    const bool proxy_mode = !cfg.proxy.empty();

    WLOG_INFO("discord-wranglerd starting: queue=%u first_len=%u hold_ms=%u packet_file=%s proxy=%s",
              cfg.queue_num, cfg.first_len, cfg.hold_ms,
              cfg.packet_file.empty() ? "(none)" : cfg.packet_file.c_str(),
              proxy_mode ? "enabled" : "disabled");

    install_signal_handlers();

    // --- Direct mode ---
    wrangler::direct::RawInjector injector;
    if (int r = injector.open(); r < 0) {
        WLOG_ERROR("inject open failed (%d); exiting", r);
        return 1;
    }
    wrangler::direct::FlowTable flows;

    // --- Proxy mode ---
    wrangler::proxy::Relay relay;
    NftRuleCtx                                       nft_ctx;
    std::unique_ptr<wrangler::proxy::cgroup::Watcher> watcher;
    if (proxy_mode) {
        if (cfg.discord_uid == 0) {
            WLOG_ERROR("proxy mode requires discord_uid to be set in config or "
                       "WRANGLER_DISCORD_UID env var; exiting");
            return 1;
        }
        if (int r = relay.start(cfg); r != 0) {
            WLOG_ERROR("relay start failed: %s; exiting", std::strerror(-r));
            return 1;
        }
        if (!no_rules) {
            nft_ctx.template_path = std::string(DISCORD_WRANGLER_SYSCONFDIR) +
                                    "/nftables.d/discord-wrangler-proxy.nft.in";
            nft_ctx.cgroup_path   = wrangler::proxy::cgroup::path_for_uid(cfg.discord_uid);
            nft_ctx.relay_port    = cfg.relay_port;

            auto on_appear = [&nft_ctx] {
                if (nft_ctx.installed.load(std::memory_order_acquire)) return;
                int r = wrangler::proxy::nft::install(
                    nft_ctx.template_path, nft_ctx.cgroup_path, nft_ctx.relay_port);
                if (r == 0) {
                    nft_ctx.installed.store(true, std::memory_order_release);
                } else {
                    WLOG_ERROR("nft install failed: %s -- will retry on next scope appearance",
                               std::strerror(-r));
                }
            };
            auto on_disappear = [&nft_ctx] {
                if (!nft_ctx.installed.load(std::memory_order_acquire)) return;
                wrangler::proxy::nft::remove();
                nft_ctx.installed.store(false, std::memory_order_release);
            };

            watcher = std::make_unique<wrangler::proxy::cgroup::Watcher>(
                wrangler::proxy::cgroup::parent_dir(nft_ctx.cgroup_path),
                wrangler::proxy::cgroup::scope_basename(),
                std::move(on_appear),
                std::move(on_disappear));
            if (int r = watcher->start(); r != 0) {
                WLOG_ERROR("cgroup watcher start failed: %s; exiting", std::strerror(-r));
                relay.stop();
                return 1;
            }
        } else {
            WLOG_INFO("relay started without nftables rule install (--no-rules)");
        }
    }

    wrangler::direct::NfqLoop nfq;
    g_signal_loop.store(&nfq, std::memory_order_release);

    auto handler = [&cfg, &flows, &injector](wrangler::direct::PacketEvent&& ev) {
        bool should_manipulate = (ev.udp_payload_len == cfg.first_len);
        if (should_manipulate) {
            wrangler::direct::FlowTable::Tuple t{
                IPPROTO_UDP, ev.src_addr, ev.src_port, ev.dst_addr, ev.dst_port};
            should_manipulate = flows.consume_first(t);
        }
        if (!should_manipulate) { ev.release(); return; }

        WLOG_INFO("manipulating: 5-tuple %u/%u -> %u/%u udp_payload=%u",
                  ntohl(ev.src_addr), ntohs(ev.src_port),
                  ntohl(ev.dst_addr), ntohs(ev.dst_port),
                  ev.udp_payload_len);

        if (!cfg.packet_file.empty()) {
            auto bytes = wrangler::direct::packet_file::read(cfg.packet_file);
            if (!bytes.empty()) {
                int r = injector.send_udp(ev.src_addr, ev.src_port,
                                          ev.dst_addr, ev.dst_port,
                                          bytes.data(), bytes.size());
                WLOG_DEBUG("packet-file probe (%zu B) -> %d", bytes.size(), r);
            }
        }
        const uint8_t p0 = 0x00, p1 = 0x01;
        int r0 = injector.send_udp(ev.src_addr, ev.src_port,
                                   ev.dst_addr, ev.dst_port, &p0, 1);
        int r1 = injector.send_udp(ev.src_addr, ev.src_port,
                                   ev.dst_addr, ev.dst_port, &p1, 1);
        WLOG_DEBUG("probe 0x00 -> %d, 0x01 -> %d", r0, r1);

        std::thread([release = std::move(ev.release), hold_ms = cfg.hold_ms] {
            std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
            release();
        }).detach();
    };

    if (int r = nfq.init(cfg.queue_num, handler); r < 0) {
        WLOG_ERROR("nfq init failed: %d", r);
        g_signal_loop.store(nullptr, std::memory_order_release);
        if (watcher) watcher->stop();
        if (proxy_mode) {
            relay.stop();
            if (nft_ctx.installed.load(std::memory_order_acquire)) {
                wrangler::proxy::nft::remove();
            }
        }
        return 1;
    }

    int rc = nfq.run();

    WLOG_INFO("shutting down");
    g_signal_loop.store(nullptr, std::memory_order_release);
    if (watcher) watcher->stop();
    if (proxy_mode) {
        relay.stop();
        if (nft_ctx.installed.load(std::memory_order_acquire)) {
            wrangler::proxy::nft::remove();
        }
    }
    return rc == 0 ? 0 : 1;
}
