#pragma once

#include <cstddef>
#include <cstdint>

namespace wrangler::inject {

// Initializes the raw socket. Returns 0 on success, negative errno on failure.
// Must be called once at daemon start. Requires CAP_NET_RAW.
int init();

// Sends one UDP datagram with the given (src, sport, dst, dport, payload).
// IP header is constructed by us (we set IP_HDRINCL). Returns bytes sent, or -errno.
// Thread-safe: serializes on a single raw socket.
int send_udp(uint32_t src_addr, uint16_t src_port,
             uint32_t dst_addr, uint16_t dst_port,
             const void* payload, size_t payload_len);

void shutdown();

} // namespace wrangler::inject
