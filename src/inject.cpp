#include "inject.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <mutex>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace wrangler::inject {

namespace {
int s_raw_fd = -1;
std::mutex s_mu;

// One-complement IP-style checksum.
uint16_t checksum_16(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += (uint32_t(p[0]) << 8) | p[1]; p += 2; len -= 2; }
    if (len) sum += uint32_t(p[0]) << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons(static_cast<uint16_t>(~sum & 0xffff));
}

// UDP checksum with IPv4 pseudo-header.
uint16_t udp_checksum_v4(uint32_t src, uint32_t dst,
                         const uint8_t* udp_hdr_and_payload, size_t len) {
    // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + udp_len(2)
    uint8_t buf[12 + 65535];
    uint8_t* p = buf;
    auto put32 = [&](uint32_t v) { *p++ = (v >> 24); *p++ = (v >> 16); *p++ = (v >> 8); *p++ = v; };
    auto put16 = [&](uint16_t v) { *p++ = (v >> 8); *p++ = v; };
    put32(ntohl(src));
    put32(ntohl(dst));
    *p++ = 0;
    *p++ = IPPROTO_UDP;
    put16(static_cast<uint16_t>(len));
    memcpy(p, udp_hdr_and_payload, len);
    p += len;
    return checksum_16(buf, p - buf);
}

} // namespace

int init() {
    std::lock_guard<std::mutex> lk(s_mu);
    if (s_raw_fd >= 0) return 0;
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { int e = errno; WLOG_ERROR("raw socket: %s", strerror(e)); return -e; }
    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        int e = errno; WLOG_ERROR("IP_HDRINCL: %s", strerror(e));
        close(fd);
        return -e;
    }
    s_raw_fd = fd;
    WLOG_INFO("raw inject socket ready (fd=%d)", fd);
    return 0;
}

void shutdown() {
    std::lock_guard<std::mutex> lk(s_mu);
    if (s_raw_fd >= 0) { close(s_raw_fd); s_raw_fd = -1; }
}

int send_udp(uint32_t src_addr, uint16_t src_port,
             uint32_t dst_addr, uint16_t dst_port,
             const void* payload, size_t payload_len) {
    if (payload_len > 65507) return -EMSGSIZE;

    constexpr size_t IP_HDR_LEN  = 20;
    constexpr size_t UDP_HDR_LEN = 8;

    uint8_t buf[IP_HDR_LEN + UDP_HDR_LEN + 65507];
    auto* ip  = reinterpret_cast<struct iphdr*>(buf);
    auto* udp = reinterpret_cast<struct udphdr*>(buf + IP_HDR_LEN);
    uint8_t* data = buf + IP_HDR_LEN + UDP_HDR_LEN;

    size_t udp_len   = UDP_HDR_LEN + payload_len;
    size_t total_len = IP_HDR_LEN + udp_len;

    memset(ip, 0, IP_HDR_LEN);
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(static_cast<uint16_t>(total_len));
    ip->id       = htons(0);  // kernel will fill via IP_HDRINCL on most setups
    ip->frag_off = htons(0x4000);  // DF
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
    memcpy(data, payload, payload_len);
    udp->check  = udp_checksum_v4(src_addr, dst_addr,
                                  reinterpret_cast<const uint8_t*>(udp), udp_len);

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port   = 0;  // ignored for raw
    to.sin_addr.s_addr = dst_addr;

    std::lock_guard<std::mutex> lk(s_mu);
    if (s_raw_fd < 0) return -ENOTCONN;
    ssize_t r = sendto(s_raw_fd, buf, total_len, 0,
                       reinterpret_cast<sockaddr*>(&to), sizeof(to));
    if (r < 0) { int e = errno; WLOG_WARN("raw sendto: %s", strerror(e)); return -e; }
    return static_cast<int>(r);
}

} // namespace wrangler::inject
