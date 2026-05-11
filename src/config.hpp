#pragma once

#include <cstdint>
#include <string>

namespace wrangler::config {

struct Config {
    // direct-mode (existing)
    uint16_t    queue_num    = 0;
    uint16_t    first_len    = 74;   // matches Discord's IP-discovery
    uint32_t    hold_ms      = 50;   // matches upstream
    std::string packet_file;          // empty = disabled
};

// Reads env vars only (legacy behavior).
// Task 3 expands this to read /etc/discord-wrangler/discord-wrangler.conf as well.
Config from_env();

} // namespace wrangler::config
