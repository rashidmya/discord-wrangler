#include "direct/inject.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace wrangler::direct {

namespace {

// One's-complement IP-style checksum.
uint16_t checksum_16(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += (uint32_t(p[0]) << 8) | p[1]; p += 2; len -= 2; }
    if (len) sum += uint32_t(p[0]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons(static_cast<uint16_t>(~sum & 0xffff));
}

// Build the pseudo-header + UDP datagram into `out` and return the checksum
// over the whole thing. `out` must have room for 12 + len bytes.
uint16_t udp_checksum_v4(uint32_t src, uint32_t dst,
                         const uint8_t* udp_hdr_and_payload, size_t len,
                         uint8_t* out) {
    uint8_t* p = out;
    auto put32 = [&](uint32_t v) { *p++ = (v >> 24); *p++ = (v >> 16); *p++ = (v >> 8); *p++ = v; };
    auto put16 = [&](uint16_t v) { *p++ = (v >> 8); *p++ = v; };
    put32(ntohl(src));
    put32(ntohl(dst));
    *p++ = 0;
    *p++ = IPPROTO_UDP;
    put16(static_cast<uint16_t>(len));
    std::memcpy(p, udp_hdr_and_payload, len);
    p += len;
    return checksum_16(out, p - out);
}

} // namespace

RawInjector::~RawInjector() { close(); }

int RawInjector::open() {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) return 0;
    int fd = ::socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) { int e = errno; WLOG_ERROR("raw socket: %s", std::strerror(e)); return -e; }
    int on = 1;
    if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        int e = errno;
        WLOG_ERROR("IP_HDRINCL: %s", std::strerror(e));
        ::close(fd);
        return -e;
    }
    fd_ = fd;
    WLOG_INFO("raw inject socket ready (fd=%d)", fd);
    return 0;
}

void RawInjector::close() noexcept {
    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

int RawInjector::send_udp(uint32_t src_addr, uint16_t src_port,
                          uint32_t dst_addr, uint16_t dst_port,
                          const void* payload, size_t payload_len) {
    if (payload_len > MAX_UDP_PAYLOAD) return -EMSGSIZE;

    std::lock_guard<std::mutex> lk(mu_);
    if (fd_ < 0) return -ENOTCONN;

    auto* ip   = reinterpret_cast<struct iphdr*>(send_buf_);
    auto* udp  = reinterpret_cast<struct udphdr*>(send_buf_ + IP_HDR_LEN);
    uint8_t* data = send_buf_ + IP_HDR_LEN + UDP_HDR_LEN;

    const size_t udp_len   = UDP_HDR_LEN + payload_len;
    const size_t total_len = IP_HDR_LEN + udp_len;

    std::memset(ip, 0, IP_HDR_LEN);
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(static_cast<uint16_t>(total_len));
    ip->id       = htons(0);
    ip->frag_off = htons(0x4000);  // DF set; we never fragment.
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check    = 0;
    ip->saddr    = src_addr;
    ip->daddr    = dst_addr;
    ip->check    = checksum_16(ip, IP_HDR_LEN);

    udp->source = src_port;
    udp->dest   = dst_port;
    udp->len    = htons(static_cast<uint16_t>(udp_len));
    udp->check  = 0;
    std::memcpy(data, payload, payload_len);
    udp->check  = udp_checksum_v4(src_addr, dst_addr,
                                  reinterpret_cast<const uint8_t*>(udp), udp_len,
                                  cksum_buf_);

    sockaddr_in to{};
    to.sin_family      = AF_INET;
    to.sin_port        = 0;  // ignored for raw
    to.sin_addr.s_addr = dst_addr;

    ssize_t r = ::sendto(fd_, send_buf_, total_len, 0,
                         reinterpret_cast<sockaddr*>(&to), sizeof(to));
    if (r < 0) { int e = errno; WLOG_WARN("raw sendto: %s", std::strerror(e)); return -e; }
    return static_cast<int>(r);
}

} // namespace wrangler::direct
