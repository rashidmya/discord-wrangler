#pragma once

#include <cstdint>
#include <string>

namespace wrangler::config {

struct Config {
    // Direct-mode UDP voice bypass.
    uint16_t    queue_num    = 0;
    uint16_t    first_len    = 74;   // Discord's IP-discovery payload length
    uint32_t    hold_ms      = 50;
    std::string packet_file;          // empty = disabled

    // Proxy-mode TCP relay.
    std::string proxy;            // empty => proxy mode disabled
    uint16_t    relay_port  = 41080;
    uint32_t    discord_uid = 0;  // 0 means "unset"; required if proxy is set
};

// Reads /etc/discord-wrangler/discord-wrangler.conf (or $WRANGLER_CONF_FILE)
// and overlays WRANGLER_* env vars. Throws std::runtime_error if the file
// holds proxy credentials but is not chmod 0600.
Config from_env();

} // namespace wrangler::config
