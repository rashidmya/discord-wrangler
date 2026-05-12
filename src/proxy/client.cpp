#include "proxy/client.hpp"

#include "log.hpp"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <vector>

namespace wrangler::proxy::client {

namespace {

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
constexpr uint8_t SOCKS5_VER             = 0x05;
constexpr uint8_t SOCKS5_METHOD_NO_AUTH  = 0x00;
constexpr uint8_t SOCKS5_METHOD_USER_PWD = 0x02;
constexpr uint8_t SOCKS5_METHOD_NONE     = 0xff;
constexpr uint8_t SOCKS5_CMD_CONNECT     = 0x01;
constexpr uint8_t SOCKS5_RSV             = 0x00;
constexpr uint8_t SOCKS5_ATYP_IPV4       = 0x01;
constexpr uint8_t SOCKS5_ATYP_DOMAIN     = 0x03;
constexpr uint8_t SOCKS5_ATYP_IPV6       = 0x04;
constexpr uint8_t SOCKS5_REP_OK          = 0x00;
constexpr uint8_t SOCKS5_AUTH_VER        = 0x01;
constexpr uint8_t SOCKS5_AUTH_OK         = 0x00;
constexpr size_t  SOCKS5_AUTH_FIELD_MAX  = 255;

constexpr size_t  HTTP_CONNECT_HEADERS_MAX = 8192;

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

std::string base64_encode(const std::string& in) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    for (size_t i = 0; i < in.size(); i += 3) {
        uint32_t v = static_cast<uint8_t>(in[i]) << 16;
        if (i + 1 < in.size()) v |= static_cast<uint8_t>(in[i+1]) << 8;
        if (i + 2 < in.size()) v |= static_cast<uint8_t>(in[i+2]);
        out += tbl[(v >> 18) & 0x3f];
        out += tbl[(v >> 12) & 0x3f];
        out += (i + 1 < in.size()) ? tbl[(v >> 6) & 0x3f] : '=';
        out += (i + 2 < in.size()) ? tbl[v & 0x3f]        : '=';
    }
    return out;
}

std::string format_dst(const OrigDst& d) {
    char buf[INET6_ADDRSTRLEN];
    if (d.family == AF_INET) {
        if (!::inet_ntop(AF_INET, d.addr, buf, sizeof(buf))) return "";
        return std::string(buf) + ":" + std::to_string(ntohs(d.port));
    }
    if (d.family == AF_INET6) {
        if (!::inet_ntop(AF_INET6, d.addr, buf, sizeof(buf))) return "";
        return std::string("[") + buf + "]:" + std::to_string(ntohs(d.port));
    }
    return "";
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
        uint8_t g[] = {SOCKS5_VER, 0x02, SOCKS5_METHOD_NO_AUTH, SOCKS5_METHOD_USER_PWD};
        if (int r = write_all(fd, g, sizeof(g))) return r;
    } else {
        uint8_t g[] = {SOCKS5_VER, 0x01, SOCKS5_METHOD_NO_AUTH};
        if (int r = write_all(fd, g, sizeof(g))) return r;
    }

    uint8_t method_reply[2];
    if (int r = read_all(fd, method_reply, 2)) return r;
    if (method_reply[0] != SOCKS5_VER) {
        WLOG_WARN("socks5: bad version in method reply: 0x%02x", method_reply[0]);
        return -EPROTO;
    }
    if (method_reply[1] == SOCKS5_METHOD_NONE) {
        WLOG_WARN("socks5: server rejects offered methods (no-auth%s)",
                  with_auth ? " or user/pass" : "");
        return -EACCES;
    }
    if (method_reply[1] == SOCKS5_METHOD_USER_PWD) {
        if (!with_auth) {
            WLOG_WARN("socks5: server demands user/pass but none configured");
            return -EACCES;
        }
        if (user.size() > SOCKS5_AUTH_FIELD_MAX || pass.size() > SOCKS5_AUTH_FIELD_MAX) {
            WLOG_WARN("socks5: user or pass exceeds %zu bytes (RFC 1929 limit)",
                      SOCKS5_AUTH_FIELD_MAX);
            return -EINVAL;
        }
        std::vector<uint8_t> auth;
        auth.push_back(SOCKS5_AUTH_VER);
        auth.push_back(static_cast<uint8_t>(user.size()));
        auth.insert(auth.end(), user.begin(), user.end());
        auth.push_back(static_cast<uint8_t>(pass.size()));
        auth.insert(auth.end(), pass.begin(), pass.end());
        if (int r = write_all(fd, auth.data(), auth.size())) return r;

        uint8_t auth_reply[2];
        if (int r = read_all(fd, auth_reply, 2)) return r;
        if (auth_reply[0] != SOCKS5_AUTH_VER || auth_reply[1] != SOCKS5_AUTH_OK) {
            WLOG_ERROR("socks5: user/pass auth rejected (status=0x%02x)", auth_reply[1]);
            return -EACCES;
        }
    } else if (method_reply[1] != SOCKS5_METHOD_NO_AUTH) {
        WLOG_WARN("socks5: unexpected method 0x%02x", method_reply[1]);
        return -EPROTO;
    }

    // 2. CONNECT request. Reserve max size (3 hdr + 1 atyp + 16 v6 addr + 2 port)
    // to avoid spurious -Warray-bounds in -O2 across initializer-list + push_back.
    std::vector<uint8_t> req;
    req.reserve(22);
    req.push_back(SOCKS5_VER);
    req.push_back(SOCKS5_CMD_CONNECT);
    req.push_back(SOCKS5_RSV);
    if (dst.family == AF_INET) {
        req.push_back(SOCKS5_ATYP_IPV4);
        req.insert(req.end(), dst.addr, dst.addr + 4);
    } else if (dst.family == AF_INET6) {
        req.push_back(SOCKS5_ATYP_IPV6);
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
    if (hdr[0] != SOCKS5_VER) {
        WLOG_WARN("socks5: bad ver in reply: 0x%02x", hdr[0]);
        return -EPROTO;
    }
    if (hdr[1] != SOCKS5_REP_OK) {
        WLOG_WARN("socks5: CONNECT failed (rep=0x%02x)", hdr[1]);
        return -ECONNREFUSED;
    }
    // Drain BND.ADDR + BND.PORT based on atyp.
    size_t addr_len = 0;
    switch (hdr[3]) {
        case SOCKS5_ATYP_IPV4:   addr_len = 4;  break;
        case SOCKS5_ATYP_IPV6:   addr_len = 16; break;
        case SOCKS5_ATYP_DOMAIN: {
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

int handshake_http_connect(int fd, const OrigDst& dst,
                           const std::string& user, const std::string& pass) {
    std::string target = format_dst(dst);
    if (target.empty()) return -EAFNOSUPPORT;

    std::string req;
    req.reserve(256);
    req += "CONNECT " + target + " HTTP/1.1\r\n";
    req += "Host: " + target + "\r\n";
    if (!user.empty() || !pass.empty()) {
        req += "Proxy-Authorization: Basic " + base64_encode(user + ":" + pass) + "\r\n";
    }
    req += "\r\n";
    if (int r = write_all(fd, req.data(), req.size())) return r;

    // Read response headers until "\r\n\r\n".
    std::string buf;
    buf.reserve(512);
    while (true) {
        char c;
        ssize_t r = ::read(fd, &c, 1);
        if (r < 0) { if (errno == EINTR) continue; return -errno; }
        if (r == 0) return -EPIPE;
        buf += c;
        if (buf.size() > HTTP_CONNECT_HEADERS_MAX) {
            WLOG_WARN("http_connect: response headers exceed %zu bytes; bailing",
                      HTTP_CONNECT_HEADERS_MAX);
            return -EMSGSIZE;
        }
        if (buf.size() >= 4 && buf.compare(buf.size()-4, 4, "\r\n\r\n") == 0) break;
    }

    // Parse status line: "HTTP/1.x SSS reason\r\n"
    if (buf.size() < 12 || buf.compare(0, 5, "HTTP/") != 0) {
        WLOG_WARN("http_connect: malformed status line");
        return -EPROTO;
    }
    auto sp = buf.find(' ');
    if (sp == std::string::npos || sp + 4 > buf.size()) return -EPROTO;
    // Require a digit immediately after the version-code separator. atoi would
    // otherwise treat non-numeric status (e.g. "HTTP/1.1 ??? Unknown") as 0
    // and route it through the ECONNREFUSED branch, masking the real cause.
    if (!std::isdigit(static_cast<unsigned char>(buf[sp + 1]))) {
        WLOG_WARN("http_connect: non-numeric status code");
        return -EPROTO;
    }
    int status = std::atoi(buf.c_str() + sp + 1);
    if (status < 200 || status > 299) {
        WLOG_ERROR("http_connect: rejected with status %d", status);
        if (status == 407) return -EACCES;
        return -ECONNREFUSED;
    }
    return 0;
}

int handshake(int fd, const OrigDst& dst, const url::ProxyUrl& cfg) {
    // Scheme is currently Socks5 | HttpConnect — these two branches are
    // exhaustive. If a third scheme is ever added, the URL parser should
    // reject it long before reaching here; adjust this dispatcher then.
    if (cfg.scheme == url::Scheme::Socks5) {
        return handshake_socks5(fd, dst, cfg.user, cfg.pass);
    }
    return handshake_http_connect(fd, dst, cfg.user, cfg.pass);
}

} // namespace wrangler::proxy::client
