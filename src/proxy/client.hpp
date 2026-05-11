#pragma once

#include "proxy/url.hpp"

#include <cstdint>
#include <string>

namespace wrangler::proxy::client {

// Original destination, recovered from getsockopt(SO_ORIGINAL_DST).
struct OrigDst {
    int family;            // AF_INET or AF_INET6
    uint8_t  addr[16];     // network byte order; first 4 bytes used for v4
    uint16_t port;         // network byte order
};

// Perform the SOCKS5 (RFC 1928 / 1929) handshake on `proxy_fd` to tunnel
// to `dst`. user/pass empty => no-auth (method 00); otherwise user/pass auth
// (method 02). Returns 0 on success, negative errno-style code on failure.
int handshake_socks5(int proxy_fd, const OrigDst& dst,
                     const std::string& user, const std::string& pass);

// Perform an HTTP/1.1 CONNECT handshake on `proxy_fd`. user/pass empty =>
// no auth; otherwise Proxy-Authorization: Basic. Returns 0 on success.
int handshake_http_connect(int proxy_fd, const OrigDst& dst,
                           const std::string& user, const std::string& pass);

// Top-level dispatch: picks SOCKS5 vs HTTP based on cfg.scheme.
int handshake(int proxy_fd, const OrigDst& dst, const url::ProxyUrl& cfg);

// Sanitize a proxy URL for logging (replace user:pass with "***").
std::string redact_url(const url::ProxyUrl& cfg);

} // namespace wrangler::proxy::client
