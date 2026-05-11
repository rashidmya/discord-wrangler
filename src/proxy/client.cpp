#include "proxy/client.hpp"

#include "log.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>

namespace wrangler::proxy::client {

namespace {

int write_all(int fd, const void* buf, size_t n) {
    const auto* p = static_cast<const uint8_t*>(buf);
    while (n) {
        ssize_t r = ::write(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -errno; }
        if (r == 0) return -EPIPE;
        p += r; n -= static_cast<size_t>(r);
    }
    return 0;
}

int read_all(int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    while (n) {
        ssize_t r = ::read(fd, p, n);
        if (r < 0) { if (errno == EINTR) continue; return -errno; }
        if (r == 0) return -EPIPE;
        p += r; n -= static_cast<size_t>(r);
    }
    return 0;
}

} // namespace

std::string redact_url(const url::ProxyUrl& cfg) {
    std::ostringstream oss;
    oss << (cfg.scheme == url::Scheme::Socks5 ? "socks5" : "http") << "://";
    if (url::has_credentials(cfg)) oss << "***@";
    bool ipv6 = cfg.host.find(':') != std::string::npos;
    if (ipv6) oss << '[' << cfg.host << ']';
    else      oss << cfg.host;
    oss << ':' << cfg.port;
    return oss.str();
}

int handshake_socks5(int fd, const OrigDst& dst,
                     const std::string& user, const std::string& pass) {
    const bool with_auth = !user.empty() || !pass.empty();

    // 1. Greeting.
    if (with_auth) {
        uint8_t g[] = {0x05, 0x02, 0x00, 0x02};
        if (int r = write_all(fd, g, sizeof(g))) return r;
    } else {
        uint8_t g[] = {0x05, 0x01, 0x00};
        if (int r = write_all(fd, g, sizeof(g))) return r;
    }

    uint8_t method_reply[2];
    if (int r = read_all(fd, method_reply, 2)) return r;
    if (method_reply[0] != 0x05) {
        WLOG_WARN("socks5: bad version in method reply: 0x%02x", method_reply[0]);
        return -EPROTO;
    }
    if (method_reply[1] == 0xff) {
        WLOG_WARN("socks5: server rejects offered methods (no-auth%s)",
                  with_auth ? " or user/pass" : "");
        return -EACCES;
    }
    if (method_reply[1] == 0x02) {
        if (!with_auth) {
            WLOG_WARN("socks5: server demands user/pass but none configured");
            return -EACCES;
        }
        if (user.size() > 255 || pass.size() > 255) {
            WLOG_WARN("socks5: user or pass exceeds 255 bytes (RFC 1929 limit)");
            return -EINVAL;
        }
        std::vector<uint8_t> auth;
        auth.push_back(0x01);
        auth.push_back(static_cast<uint8_t>(user.size()));
        auth.insert(auth.end(), user.begin(), user.end());
        auth.push_back(static_cast<uint8_t>(pass.size()));
        auth.insert(auth.end(), pass.begin(), pass.end());
        if (int r = write_all(fd, auth.data(), auth.size())) return r;

        uint8_t auth_reply[2];
        if (int r = read_all(fd, auth_reply, 2)) return r;
        if (auth_reply[0] != 0x01 || auth_reply[1] != 0x00) {
            WLOG_ERROR("socks5: user/pass auth rejected (status=0x%02x)", auth_reply[1]);
            return -EACCES;
        }
    } else if (method_reply[1] != 0x00) {
        WLOG_WARN("socks5: unexpected method 0x%02x", method_reply[1]);
        return -EPROTO;
    }

    // 2. CONNECT request. Reserve max size (3 hdr + 1 atyp + 16 v6 addr + 2 port)
    // to avoid spurious -Warray-bounds in -O2 across initializer-list + push_back.
    std::vector<uint8_t> req;
    req.reserve(22);
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);
    if (dst.family == AF_INET) {
        req.push_back(0x01);
        req.insert(req.end(), dst.addr, dst.addr + 4);
    } else if (dst.family == AF_INET6) {
        req.push_back(0x04);
        req.insert(req.end(), dst.addr, dst.addr + 16);
    } else {
        return -EAFNOSUPPORT;
    }
    // dst.port is already network byte order; emit raw bytes high-byte first.
    req.push_back(reinterpret_cast<const uint8_t*>(&dst.port)[0]);
    req.push_back(reinterpret_cast<const uint8_t*>(&dst.port)[1]);
    if (int r = write_all(fd, req.data(), req.size())) return r;

    // 3. Reply.
    uint8_t hdr[4];
    if (int r = read_all(fd, hdr, 4)) return r;
    if (hdr[0] != 0x05) { WLOG_WARN("socks5: bad ver in reply: 0x%02x", hdr[0]); return -EPROTO; }
    if (hdr[1] != 0x00) {
        WLOG_WARN("socks5: CONNECT failed (rep=0x%02x)", hdr[1]);
        return -ECONNREFUSED;
    }
    // Drain BND.ADDR + BND.PORT based on atyp.
    size_t addr_len = 0;
    switch (hdr[3]) {
        case 0x01: addr_len = 4;  break;
        case 0x04: addr_len = 16; break;
        case 0x03: {
            uint8_t l = 0;
            if (int r = read_all(fd, &l, 1)) return r;
            addr_len = l;
            break;
        }
        default: WLOG_WARN("socks5: bad atyp in reply: 0x%02x", hdr[3]); return -EPROTO;
    }
    std::vector<uint8_t> tail(addr_len + 2);
    if (int r = read_all(fd, tail.data(), tail.size())) return r;
    return 0;
}

int handshake_http_connect(int, const OrigDst&, const std::string&, const std::string&) {
    return -ENOSYS;
}
int handshake(int, const OrigDst&, const url::ProxyUrl&) {
    return -ENOSYS;
}

} // namespace wrangler::proxy::client
