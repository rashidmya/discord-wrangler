#include "proxy/url.hpp"

#include <cctype>
#include <cstdlib>
#include <string>

namespace wrangler::proxy::url {
namespace {

// Reject embedded NUL anywhere in user/pass: the HTTP CONNECT path forms
// "user:pass" and base64-encodes it, so a smuggled NUL would silently mangle
// the auth header. SOCKS5 uses length-prefixed fields and would tolerate it,
// but uniform rejection keeps the parser predictable.
std::optional<std::string> percent_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\0') return std::nullopt;
        if (s[i] != '%') { out += s[i]; continue; }
        if (i + 2 >= s.size()) return std::nullopt;
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int hi = hex(s[i+1]), lo = hex(s[i+2]);
        if (hi < 0 || lo < 0) return std::nullopt;
        char decoded = static_cast<char>((hi << 4) | lo);
        if (decoded == '\0') return std::nullopt;
        out += decoded;
        i += 2;
    }
    return out;
}

bool parse_port(const std::string& s, uint16_t& out) {
    if (s.empty()) return false;
    for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    long v = std::strtol(s.c_str(), nullptr, 10);
    if (v < 1 || v > 65535) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

} // namespace

std::optional<ProxyUrl> parse(const std::string& raw) {
    if (raw.empty()) return std::nullopt;

    // 1. scheme
    auto sep = raw.find("://");
    if (sep == std::string::npos) return std::nullopt;
    std::string scheme_s = raw.substr(0, sep);
    Scheme scheme;
    uint16_t default_port;
    if      (scheme_s == "socks5")  { scheme = Scheme::Socks5;      default_port = 1080; }
    else if (scheme_s == "socks5h") { scheme = Scheme::Socks5;      default_port = 1080; }
    else if (scheme_s == "http")    { scheme = Scheme::HttpConnect; default_port = 8080; }
    else                            { return std::nullopt; }

    std::string rest = raw.substr(sep + 3);
    if (rest.empty()) return std::nullopt;

    // Reject malformed IPv6 literal up front: if the authority opens with `[`
    // it must have a matching `]`, otherwise the rfind('@') below would
    // happily consume the broken bracket as part of a fake userinfo.
    if (rest.front() == '[' && rest.find(']') == std::string::npos) {
        return std::nullopt;
    }

    // 2. optional creds (everything before the last '@')
    std::string creds;
    auto at = rest.rfind('@');
    if (at != std::string::npos) {
        creds = rest.substr(0, at);
        rest = rest.substr(at + 1);
    }

    // 3. host (bracketed IPv6 vs plain)
    std::string host;
    std::string portpart;
    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close == std::string::npos) return std::nullopt;
        host = rest.substr(1, close - 1);
        if (close + 1 < rest.size()) {
            if (rest[close + 1] != ':') return std::nullopt;
            portpart = rest.substr(close + 2);
        }
    } else {
        auto colon = rest.find(':');
        if (colon == std::string::npos) {
            host = rest;
        } else {
            host = rest.substr(0, colon);
            portpart = rest.substr(colon + 1);
        }
    }
    if (host.empty()) return std::nullopt;

    ProxyUrl out;
    out.scheme = scheme;
    out.host   = host;
    out.port   = default_port;
    if (!portpart.empty()) {
        if (!parse_port(portpart, out.port)) return std::nullopt;
    }

    if (!creds.empty()) {
        std::string u, p;
        auto colon = creds.find(':');
        if (colon == std::string::npos) {
            u = creds;
        } else {
            u = creds.substr(0, colon);
            p = creds.substr(colon + 1);
        }
        auto du = percent_decode(u);
        auto dp = percent_decode(p);
        if (!du || !dp) return std::nullopt;
        out.user = *du;
        out.pass = *dp;
    }

    return out;
}

} // namespace wrangler::proxy::url
