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

    // proxy-mode (Task 4)
    std::string proxy;            // empty => proxy mode disabled
    uint16_t    relay_port  = 41080;
    uint32_t    discord_uid = 0;  // 0 means "unset"; required if proxy is set
};

Config from_env();

} // namespace wrangler::config
