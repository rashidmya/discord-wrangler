#pragma once

#include "config.hpp"

#include <cstdint>

namespace wrangler::proxy::relay {

// Start the relay. Binds 127.0.0.1:<relay_port> and [::1]:<relay_port>,
// then spawns an accept loop in a worker thread. Returns 0 on success,
// negative errno on bind/listen failure.
int start(const wrangler::config::Config& cfg);

// Stop the relay: close the listening sockets immediately, then wait up to
// `drain_timeout_ms` for in-flight handler threads to finish. If any are
// still running at the deadline, stop() returns anyway and logs a warning —
// the detached threads keep their own fds, and the OS reclaims them on
// process exit.
void stop(uint32_t drain_timeout_ms = 3000);

} // namespace wrangler::proxy::relay
