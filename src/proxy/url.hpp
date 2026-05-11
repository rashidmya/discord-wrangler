#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace wrangler::proxy::url {

enum class Scheme { Socks5, HttpConnect };

struct ProxyUrl {
    Scheme      scheme;
    std::string host;
    uint16_t    port;
    std::string user;   // empty = no auth
    std::string pass;
};

// Parse a URL like "socks5://user:pass@host:port" or "http://host[:port]".
// Supported schemes: socks5, socks5h (alias), http.
// Returns nullopt on any error; caller logs the diagnostic.
std::optional<ProxyUrl> parse(const std::string& raw);

inline bool has_credentials(const ProxyUrl& u) {
    return !u.user.empty() || !u.pass.empty();
}

} // namespace wrangler::proxy::url
