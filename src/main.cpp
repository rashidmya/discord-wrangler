// discord-wranglerd — NFQUEUE daemon entry.

#include "config.hpp"
#include "direct/flow_table.hpp"
#include "direct/inject.hpp"
#include "log.hpp"
#include "direct/nfq_loop.hpp"
#include "direct/packet_file.hpp"

#include <arpa/inet.h>      // ntohl, ntohs
#include <netinet/in.h>     // IPPROTO_UDP
#include <atomic>
#include <chrono>
#include <signal.h>
#include <thread>

namespace {

std::atomic<bool> g_terminate{false};

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
    // Ignore SIGPIPE — we never want it to kill us.
    signal(SIGPIPE, SIG_IGN);
}

} // namespace

int main(int /*argc*/, char** /*argv*/) {
    wrangler::log::set_level_from_env();
    auto cfg = wrangler::config::from_env();

    WLOG_INFO("discord-wranglerd starting: queue=%u first_len=%u hold_ms=%u packet_file=%s",
              cfg.queue_num, cfg.first_len, cfg.hold_ms,
              cfg.packet_file.empty() ? "(none)" : cfg.packet_file.c_str());

    install_signal_handlers();

    if (int r = wrangler::direct::inject::init(); r < 0) {
        WLOG_ERROR("inject init failed (%d) — daemon cannot manipulate; exiting", r);
        return 1;
    }

    wrangler::direct::FlowTable flows;

    auto handler = [&cfg, &flows](wrangler::direct::nfq::PacketEvent&& ev) {
        // Only manipulate when:
        //   - UDP payload length matches our target
        //   - first time we've seen this 5-tuple
        bool should_manipulate = (ev.udp_payload_len == cfg.first_len);
        if (should_manipulate) {
            wrangler::direct::FlowTable::Tuple t{
                IPPROTO_UDP, ev.src_addr, ev.src_port, ev.dst_addr, ev.dst_port};
            should_manipulate = flows.consume_first(t);
        }

        if (!should_manipulate) {
            ev.release();
            return;
        }

        WLOG_INFO("manipulating: 5-tuple %u/%u -> %u/%u udp_payload=%u",
                  ntohl(ev.src_addr), ntohs(ev.src_port),
                  ntohl(ev.dst_addr), ntohs(ev.dst_port),
                  ev.udp_payload_len);

        // Optional packet-file payload first
        if (!cfg.packet_file.empty()) {
            auto bytes = wrangler::direct::packet_file::read(cfg.packet_file);
            if (!bytes.empty()) {
                int r = wrangler::direct::inject::send_udp(
                    ev.src_addr, ev.src_port, ev.dst_addr, ev.dst_port,
                    bytes.data(), bytes.size());
                WLOG_DEBUG("packet-file probe (%zu B) -> %d", bytes.size(), r);
            }
        }

        // 0x00 probe, then 0x01 probe
        const uint8_t p0 = 0x00, p1 = 0x01;
        int r0 = wrangler::direct::inject::send_udp(ev.src_addr, ev.src_port,
                                            ev.dst_addr, ev.dst_port, &p0, 1);
        int r1 = wrangler::direct::inject::send_udp(ev.src_addr, ev.src_port,
                                            ev.dst_addr, ev.dst_port, &p1, 1);
        WLOG_DEBUG("probe 0x00 -> %d, 0x01 -> %d", r0, r1);

        // Hold the original packet for `hold_ms` then release.
        // We hand this off to a detached thread so the nfq_loop callback can keep
        // draining the netlink socket without blocking.
        std::thread([release = std::move(ev.release), hold_ms = cfg.hold_ms] {
            std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
            release();
        }).detach();
    };

    if (int r = wrangler::direct::nfq::init(cfg.queue_num, handler); r < 0) {
        WLOG_ERROR("nfq init failed: %d", r);
        wrangler::direct::inject::shutdown();
        return 1;
    }

    int rc = wrangler::direct::nfq::run();

    WLOG_INFO("shutting down");
    wrangler::direct::inject::shutdown();
    return rc == 0 ? 0 : 1;
}
