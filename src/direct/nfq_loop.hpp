#pragma once

#include <cstdint>
#include <functional>

// Forward-declare libmnl/libnetfilter_queue types so the public header doesn't
// drag those system headers into every translation unit that includes it.
struct mnl_socket;
struct nlmsghdr;
struct nlattr;

namespace wrangler::direct {

// Parsed first-packet event delivered to the user-provided handler. The
// handler must call `release()` exactly once (any thread) to ACK the packet
// to the kernel.
struct PacketEvent {
    uint32_t src_addr;        // network byte order
    uint16_t src_port;
    uint32_t dst_addr;
    uint16_t dst_port;
    uint16_t udp_payload_len;
    uint32_t packet_id;       // for verdict accounting
    std::function<void()> release;
};

class NfqLoop {
public:
    using Handler = std::function<void(PacketEvent&&)>;

    NfqLoop() = default;
    ~NfqLoop();

    NfqLoop(const NfqLoop&) = delete;
    NfqLoop& operator=(const NfqLoop&) = delete;
    NfqLoop(NfqLoop&&) = delete;
    NfqLoop& operator=(NfqLoop&&) = delete;

    // Open netlink, bind queue, copy packet payloads. Returns 0 on success,
    // -errno on failure.
    int init(uint16_t queue_num, Handler handler);

    // Blocking loop: reads packets from the netlink socket and dispatches to
    // the handler. Returns 0 when shutdown() is called, -errno on fatal
    // read/parse failure.
    int run();

    // Wake the loop and arrange for run() to return. Safe to call from a
    // signal handler — only a single byte is written to an internal pipe.
    void shutdown() noexcept;

private:
    // Per-packet attribute parsing callback (static; reads/writes only through
    // the captured NfqLoop* in `data`).
    int dispatch(const nlmsghdr* nlh);

    // Send NF_ACCEPT for `packet_id`. Called from PacketEvent::release().
    void send_verdict(uint32_t packet_id, uint32_t verdict);

    mnl_socket* nl_         = nullptr;
    uint16_t    queue_num_  = 0;
    uint32_t    portid_     = 0;
    Handler     handler_;
    int         wake_rfd_   = -1;   // self-pipe read end
    int         wake_wfd_   = -1;   // self-pipe write end
};

} // namespace wrangler::direct
