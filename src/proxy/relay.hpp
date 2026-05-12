#pragma once

#include "config.hpp"
#include "proxy/rate_limit.hpp"
#include "proxy/url.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

namespace wrangler::proxy {

// Localhost TCP relay that accepts redirected Discord connections, looks up
// the original destination via SO_ORIGINAL_DST, dials an upstream HTTP-CONNECT
// or SOCKS5 proxy, performs the handshake, and splice(2)s bytes both ways.
//
// One instance per daemon; the class is non-copy/non-move. The instance must
// outlive any handler thread it spawned — stop() drains in-flight connections
// with a deadline but does not forcibly cancel them.
class Relay {
public:
    Relay() = default;
    ~Relay();

    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;
    Relay(Relay&&) = delete;
    Relay& operator=(Relay&&) = delete;

    // Bind 127.0.0.1:<relay_port> (+ [::1] if available), parse cfg.proxy,
    // start the accept thread. Returns 0 on success, -errno on failure.
    int start(const wrangler::config::Config& cfg);

    // Close listening sockets, wait up to `drain_timeout_ms` for in-flight
    // connections to finish. Idempotent.
    void stop(uint32_t drain_timeout_ms = 3000);

private:
    void accept_loop();
    void handle_conn(int client_fd);

    int listen_v4_ = -1;
    int listen_v6_ = -1;
    int wake_rfd_  = -1;
    int wake_wfd_  = -1;
    std::atomic<bool>  running_{false};
    std::atomic<int>   inflight_{0};
    std::thread        accept_thread_;
    url::ProxyUrl      proxy_cfg_{};
    RateLimiter        log_limit_{std::chrono::seconds(30)};
};

} // namespace wrangler::proxy
