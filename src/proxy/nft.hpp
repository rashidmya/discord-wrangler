#pragma once

#include <cstdint>
#include <string>

namespace wrangler::proxy::nft {

// Substitute @CGROUP_PATH@ and @RELAY_PORT@ in the template file, then run
// `nft -f -` with the result. Returns 0 on success, negative errno on failure.
int install(const std::string& template_path,
            const std::string& cgroup_path,
            uint16_t relay_port);

// Run `nft delete table inet discord_wrangler_proxy`. Idempotent — silently
// succeeds if table is absent.
int remove();

} // namespace wrangler::proxy::nft
