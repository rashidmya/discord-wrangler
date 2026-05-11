#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>

namespace wrangler::config {

struct Config {
    uint16_t    queue_num    = 0;
    uint16_t    first_len    = 74;   // matches Discord's IP-discovery
    uint32_t    hold_ms      = 50;   // matches upstream
    std::string packet_file;          // empty = disabled
};

inline uint32_t parse_u32(const char* v, uint32_t fallback) {
    if (!v || !*v) return fallback;
    char* end = nullptr;
    long x = std::strtol(v, &end, 10);
    if (end == v || x < 0) return fallback;
    return static_cast<uint32_t>(x);
}

inline Config from_env() {
    Config c;
    c.queue_num = static_cast<uint16_t>(parse_u32(std::getenv("WRANGLER_QUEUE_NUM"), c.queue_num));
    c.first_len = static_cast<uint16_t>(parse_u32(std::getenv("WRANGLER_FIRST_LEN"), c.first_len));
    c.hold_ms   = parse_u32(std::getenv("WRANGLER_HOLD_MS"), c.hold_ms);
    const char* pf = std::getenv("WRANGLER_PACKET_FILE");
    if (pf) c.packet_file = pf;
    return c;
}

} // namespace wrangler::config
