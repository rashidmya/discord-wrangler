#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace wrangler::direct {

// Sends forged UDP datagrams via a raw socket (IP_HDRINCL). Daemon needs
// CAP_NET_RAW. The class owns one raw socket and serializes sends on its
// own mutex, so a single instance is safe to share across threads.
class RawInjector {
public:
    static constexpr size_t MAX_UDP_PAYLOAD = 65507;  // IPv4 datagram limit

    RawInjector() = default;
    ~RawInjector();

    RawInjector(const RawInjector&) = delete;
    RawInjector& operator=(const RawInjector&) = delete;
    RawInjector(RawInjector&&) = delete;
    RawInjector& operator=(RawInjector&&) = delete;

    // Open the raw socket. Returns 0 on success, -errno on failure.
    // Idempotent: a second open() on an already-open instance returns 0.
    int open();

    // Close the raw socket. Idempotent.
    void close() noexcept;

    bool is_open() const noexcept { return fd_ >= 0; }

    // Build and send one UDP datagram with the given 5-tuple. Returns bytes
    // sent on success, or -errno on failure.
    int send_udp(uint32_t src_addr, uint16_t src_port,
                 uint32_t dst_addr, uint16_t dst_port,
                 const void* payload, size_t payload_len);

private:
    static constexpr size_t IP_HDR_LEN  = 20;
    static constexpr size_t UDP_HDR_LEN = 8;

    mutable std::mutex mu_;
    int                fd_ = -1;
    // Reusable IP+UDP datagram buffer; serialized with `mu_`.
    uint8_t            send_buf_[IP_HDR_LEN + UDP_HDR_LEN + MAX_UDP_PAYLOAD]{};
    // Reusable pseudo-header + UDP buffer for checksum computation.
    uint8_t            cksum_buf_[12 + 65535]{};
};

} // namespace wrangler::direct
