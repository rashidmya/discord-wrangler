// discord-wranglerd — NFQUEUE daemon entry.
// Direct mode: UDP voice bypass (existing).
// Proxy mode: TCP through HTTP/SOCKS5 (added in proxy-mode plan).

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
#include <thread>

namespace {

std::atomic<bool> g_terminate{false};
std::atomic<bool> g_rules_installed{false};
std::string g_template_path = "/etc/nftables.d/discord-wrangler-proxy.nft.in";
std::string g_cgroup_path;
uint16_t    g_relay_port = 0;

void on_signal(int) {
    g_terminate.store(true);
    wrangler::direct::nfq::shutdown();
}

void install_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
}

void on_scope_appear() {
    if (g_rules_installed.load(std::memory_order_acquire)) return;
    int r = wrangler::proxy::nft::install(g_template_path, g_cgroup_path, g_relay_port);
    if (r == 0) g_rules_installed.store(true, std::memory_order_release);
    else WLOG_ERROR("nft install failed: %s -- will retry on next scope appearance",
                    strerror(-r));
}

void on_scope_disappear() {
    if (!g_rules_installed.load(std::memory_order_acquire)) return;
    wrangler::proxy::nft::remove();
    g_rules_installed.store(false, std::memory_order_release);
}

} // namespace

int main(int argc, char** argv) {
    bool no_rules = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--no-rules") == 0) no_rules = true;
    }

    wrangler::log::set_level_from_env();
    auto cfg = wrangler::config::from_env();

    bool proxy_mode = !cfg.proxy.empty();

    WLOG_INFO("discord-wranglerd starting: queue=%u first_len=%u hold_ms=%u packet_file=%s proxy=%s",
              cfg.queue_num, cfg.first_len, cfg.hold_ms,
              cfg.packet_file.empty() ? "(none)" : cfg.packet_file.c_str(),
              proxy_mode ? "enabled" : "disabled");

    install_signal_handlers();

    // --- Direct mode (existing) ---
    if (int r = wrangler::direct::inject::init(); r < 0) {
        WLOG_ERROR("inject init failed (%d); exiting", r);
        return 1;
    }
    wrangler::direct::FlowTable flows;

    // --- Proxy mode (new) ---
    std::unique_ptr<wrangler::proxy::cgroup::Watcher> watcher;
    if (proxy_mode) {
        if (cfg.discord_uid == 0) {
            WLOG_ERROR("proxy mode requires discord_uid to be set in config or "
                       "WRANGLER_DISCORD_UID env var; exiting");
            wrangler::direct::inject::shutdown();
            return 1;
        }
        if (int r = wrangler::proxy::relay::start(cfg); r != 0) {
            WLOG_ERROR("relay start failed: %s; exiting", strerror(-r));
            wrangler::direct::inject::shutdown();
            return 1;
        }
        if (!no_rules) {
            g_cgroup_path = wrangler::proxy::cgroup::path_for_uid(cfg.discord_uid);
            g_relay_port  = cfg.relay_port;
            watcher = std::make_unique<wrangler::proxy::cgroup::Watcher>(
                wrangler::proxy::cgroup::parent_dir(g_cgroup_path),
                wrangler::proxy::cgroup::scope_basename(),
                on_scope_appear,
                on_scope_disappear);
            if (int r = watcher->start(); r != 0) {
                WLOG_ERROR("cgroup watcher start failed: %s; exiting", strerror(-r));
                wrangler::proxy::relay::stop();
                wrangler::direct::inject::shutdown();
                return 1;
            }
        } else {
            WLOG_INFO("relay started without nftables rule install (--no-rules)");
        }
    }

    auto handler = [&cfg, &flows](wrangler::direct::nfq::PacketEvent&& ev) {
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
                int r = wrangler::direct::inject::send_udp(
                    ev.src_addr, ev.src_port, ev.dst_addr, ev.dst_port,
                    bytes.data(), bytes.size());
                WLOG_DEBUG("packet-file probe (%zu B) -> %d", bytes.size(), r);
            }
        }
        const uint8_t p0 = 0x00, p1 = 0x01;
        int r0 = wrangler::direct::inject::send_udp(ev.src_addr, ev.src_port,
                                                    ev.dst_addr, ev.dst_port, &p0, 1);
        int r1 = wrangler::direct::inject::send_udp(ev.src_addr, ev.src_port,
                                                    ev.dst_addr, ev.dst_port, &p1, 1);
        WLOG_DEBUG("probe 0x00 -> %d, 0x01 -> %d", r0, r1);

        std::thread([release = std::move(ev.release), hold_ms = cfg.hold_ms] {
            std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
            release();
        }).detach();
    };

    if (int r = wrangler::direct::nfq::init(cfg.queue_num, handler); r < 0) {
        WLOG_ERROR("nfq init failed: %d", r);
        if (watcher) watcher->stop();
        if (proxy_mode) {
            wrangler::proxy::relay::stop();
            // The watcher's start() may have fired on_scope_appear synchronously
            // and installed rules before we got here — clean them up.
            if (g_rules_installed.load(std::memory_order_acquire)) {
                wrangler::proxy::nft::remove();
            }
        }
        wrangler::direct::inject::shutdown();
        return 1;
    }

    int rc = wrangler::direct::nfq::run();

    WLOG_INFO("shutting down");
    if (watcher) watcher->stop();
    if (proxy_mode) {
        wrangler::proxy::relay::stop();
        if (g_rules_installed.load(std::memory_order_acquire)) {
            wrangler::proxy::nft::remove();
        }
    }
    wrangler::direct::inject::shutdown();
    return rc == 0 ? 0 : 1;
}
