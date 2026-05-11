#pragma once

#include <cstdint>
#include <functional>

namespace wrangler::direct::nfq {

// Callback receives a parsed IPv4 UDP first-packet of a new flow. Implementation
// must call `release()` exactly once (any thread) to ACK the packet to the kernel.
struct PacketEvent {
    uint32_t src_addr;   // network byte order
    uint16_t src_port;
    uint32_t dst_addr;
    uint16_t dst_port;
    uint16_t udp_payload_len;
    uint32_t packet_id;  // for verdict accounting
    std::function<void()> release;  // call once to NF_ACCEPT
};

using Handler = std::function<void(PacketEvent&&)>;

// Initialize NFQUEUE on `queue_num`, register the handler, return 0 or -errno.
int init(uint16_t queue_num, Handler handler);

// Blocking loop: reads packets, dispatches to handler. Returns when shutdown() is called.
int run();

// Wake the loop and exit. Safe from a signal handler.
void shutdown();

} // namespace wrangler::direct::nfq
