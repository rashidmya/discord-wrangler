#include "proxy/client.hpp"

#include <cerrno>
#include <sstream>

namespace wrangler::proxy::client {

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

// handshake_socks5, handshake_http_connect, handshake stubs come in
// subsequent tasks.
int handshake_socks5(int, const OrigDst&, const std::string&, const std::string&) {
    return -ENOSYS;
}
int handshake_http_connect(int, const OrigDst&, const std::string&, const std::string&) {
    return -ENOSYS;
}
int handshake(int, const OrigDst&, const url::ProxyUrl&) {
    return -ENOSYS;
}

} // namespace wrangler::proxy::client
