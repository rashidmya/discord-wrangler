#include "proxy/relay.hpp"
#include "proxy/client.hpp"
#include "proxy/url.hpp"
#include "proxy/rate_limit.hpp"
#include "log.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <system_error>
#include <thread>
#include <unistd.h>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <cstdlib>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

namespace wrangler::proxy::relay {
namespace {

std::atomic<bool> g_running{false};
int g_listen_v4 = -1;
int g_listen_v6 = -1;
std::thread g_accept_thread;
std::atomic<int> g_inflight{0};

int make_listener(int family, uint16_t port) {
    int fd = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -errno;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (family == AF_INET) {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port   = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
            int e = errno; ::close(fd); return -e;
        }
    } else {
        int v6only = 1;
        ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_port   = htons(port);
        a.sin6_addr   = in6addr_loopback;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) {
            int e = errno; ::close(fd); return -e;
        }
    }
    if (::listen(fd, 64) < 0) {
        int e = errno; ::close(fd); return -e;
    }
    return fd;
}

// Resolve the original destination for a client_fd. Falls back to
// WRANGLER_RELAY_FORCE_DST (test-only override; ignored if SO_ORIGINAL_DST
// already succeeded).
bool resolve_orig_dst(int client_fd, client::OrigDst& out) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);

    // Try v4 first.
    if (::getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &ss, &len) == 0) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        out.family = AF_INET;
        std::memcpy(out.addr, &a->sin_addr.s_addr, 4);
        out.port = a->sin_port;
        return true;
    }
    // Try v6.
    len = sizeof(ss);
    if (::getsockopt(client_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &ss, &len) == 0) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        out.family = AF_INET6;
        std::memcpy(out.addr, &a->sin6_addr, 16);
        out.port = a->sin6_port;
        return true;
    }
    // Test override.
    if (const char* force = std::getenv("WRANGLER_RELAY_FORCE_DST")) {
        std::string s = force;
        auto colon = s.rfind(':');
        if (colon == std::string::npos) return false;
        std::string h = s.substr(0, colon);
        uint16_t p = static_cast<uint16_t>(std::atoi(s.c_str() + colon + 1));
        if (!h.empty() && h.front() == '[' && h.back() == ']') {
            h = h.substr(1, h.size() - 2);
        }
        if (h.find(':') != std::string::npos) {
            out.family = AF_INET6;
            ::inet_pton(AF_INET6, h.c_str(), out.addr);
        } else {
            out.family = AF_INET;
            uint32_t ip = 0;
            ::inet_pton(AF_INET, h.c_str(), &ip);
            std::memcpy(out.addr, &ip, 4);
        }
        out.port = htons(p);
        return true;
    }
    return false;
}

int dial_upstream(const url::ProxyUrl& cfg) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(cfg.port);
    if (::getaddrinfo(cfg.host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        return -EHOSTUNREACH;
    }
    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    ::freeaddrinfo(res);
    return fd >= 0 ? fd : -ECONNREFUSED;
}

// Pipe-pair-based bidirectional splice. Returns when either side EOFs.
void splice_both(int a, int b) {
    int p1[2], p2[2];
    if (::pipe2(p1, O_CLOEXEC) < 0) return;
    if (::pipe2(p2, O_CLOEXEC) < 0) {
        ::close(p1[0]); ::close(p1[1]);
        return;
    }

    pollfd pfd[2];
    pfd[0].fd = a; pfd[0].events = POLLIN;
    pfd[1].fd = b; pfd[1].events = POLLIN;

    constexpr size_t CHUNK = 16384;
    while (true) {
        pfd[0].revents = 0; pfd[1].revents = 0;
        int n = ::poll(pfd, 2, -1);
        if (n <= 0) { if (errno == EINTR) continue; break; }
        bool eof = false;
        if (pfd[0].revents & POLLIN) {
            ssize_t r = ::splice(a, nullptr, p1[1], nullptr, CHUNK,
                                 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (r <= 0) { eof = true; }
            else {
                ssize_t w = ::splice(p1[0], nullptr, b, nullptr, r,
                                     SPLICE_F_MOVE);
                if (w <= 0) eof = true;
            }
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t r = ::splice(b, nullptr, p2[1], nullptr, CHUNK,
                                 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (r <= 0) { eof = true; }
            else {
                ssize_t w = ::splice(p2[0], nullptr, a, nullptr, r,
                                     SPLICE_F_MOVE);
                if (w <= 0) eof = true;
            }
        }
        if (pfd[0].revents & (POLLHUP|POLLERR)) eof = true;
        if (pfd[1].revents & (POLLHUP|POLLERR)) eof = true;
        if (eof) break;
    }
    ::close(p1[0]); ::close(p1[1]);
    ::close(p2[0]); ::close(p2[1]);
}

// Module-level state for the upstream URL + rate limiter.
url::ProxyUrl g_proxy_cfg{};
RateLimiter g_log_limit{std::chrono::seconds(30)};

void handle_conn(int client_fd) {
    auto on_exit = [&](int code) {
        ::close(client_fd);
        g_inflight.fetch_sub(1, std::memory_order_release);
        (void)code;
    };

    client::OrigDst dst{};
    if (!resolve_orig_dst(client_fd, dst)) {
        if (g_log_limit.allow("no-orig-dst")) {
            WLOG_WARN("relay: no SO_ORIGINAL_DST on connection -- dropping");
        }
        return on_exit(-1);
    }

    int up = dial_upstream(g_proxy_cfg);
    if (up < 0) {
        std::string key = "dial:" + g_proxy_cfg.host + ":" + std::to_string(g_proxy_cfg.port);
        if (g_log_limit.allow(key)) {
            WLOG_WARN("relay: dial %s failed: %s",
                      client::redact_url(g_proxy_cfg).c_str(), strerror(-up));
        }
        return on_exit(up);
    }

    if (int r = client::handshake(up, dst, g_proxy_cfg); r != 0) {
        if (g_log_limit.allow("handshake-err")) {
            WLOG_WARN("relay: handshake to %s failed: %s",
                      client::redact_url(g_proxy_cfg).c_str(), strerror(-r));
        }
        ::close(up);
        return on_exit(r);
    }

    splice_both(client_fd, up);
    ::close(up);
    on_exit(0);
}

void accept_loop() {
    while (g_running.load(std::memory_order_acquire)) {
        fd_set rs;
        FD_ZERO(&rs);
        int max = -1;
        if (g_listen_v4 >= 0) { FD_SET(g_listen_v4, &rs); max = std::max(max, g_listen_v4); }
        if (g_listen_v6 >= 0) { FD_SET(g_listen_v6, &rs); max = std::max(max, g_listen_v6); }
        timeval tv{0, 200000};  // 200ms wakeup so we can re-check g_running
        int r = ::select(max + 1, &rs, nullptr, nullptr, &tv);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) continue;
        for (int lf : {g_listen_v4, g_listen_v6}) {
            if (lf < 0 || !FD_ISSET(lf, &rs)) continue;
            while (true) {
                int c = ::accept4(lf, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (c < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    WLOG_DEBUG("relay: accept: %s", strerror(errno));
                    break;
                }
                g_inflight.fetch_add(1, std::memory_order_acq_rel);
                try {
                    std::thread(handle_conn, c).detach();
                } catch (const std::system_error& e) {
                    // pthread_create can fail under memory pressure or per-user
                    // thread caps. Recover the fd and the in-flight count
                    // rather than leaking either.
                    WLOG_WARN("relay: failed to spawn handler thread: %s", e.what());
                    ::close(c);
                    g_inflight.fetch_sub(1, std::memory_order_release);
                }
            }
        }
    }
}

} // namespace

int start(const wrangler::config::Config& cfg) {
    auto parsed = url::parse(cfg.proxy);
    if (!parsed) {
        // Don't log cfg.proxy here — an unparseable URL may still contain
        // a recognizable user:pass@ segment we'd leak to the journal.
        WLOG_ERROR("relay: WRANGLER_PROXY value is unparseable (check scheme/host/port)");
        return -EINVAL;
    }
    g_proxy_cfg = *parsed;
    WLOG_INFO("relay: upstream proxy = %s", client::redact_url(g_proxy_cfg).c_str());

    g_listen_v4 = make_listener(AF_INET,  cfg.relay_port);
    if (g_listen_v4 < 0) {
        WLOG_ERROR("relay: bind v4 :%u failed: %s",
                   cfg.relay_port, strerror(-g_listen_v4));
        return g_listen_v4;
    }
    g_listen_v6 = make_listener(AF_INET6, cfg.relay_port);
    if (g_listen_v6 < 0) {
        WLOG_WARN("relay: bind v6 :%u failed: %s (continuing with v4 only)",
                  cfg.relay_port, strerror(-g_listen_v6));
        g_listen_v6 = -1;
    }
    g_running.store(true, std::memory_order_release);
    g_accept_thread = std::thread(accept_loop);
    WLOG_INFO("relay: listening on 127.0.0.1:%u%s",
              cfg.relay_port, g_listen_v6 >= 0 ? " and [::1]" : "");
    return 0;
}

void stop(uint32_t drain_timeout_ms) {
    g_running.store(false, std::memory_order_release);
    if (g_listen_v4 >= 0) { ::shutdown(g_listen_v4, SHUT_RD); ::close(g_listen_v4); g_listen_v4 = -1; }
    if (g_listen_v6 >= 0) { ::shutdown(g_listen_v6, SHUT_RD); ::close(g_listen_v6); g_listen_v6 = -1; }
    if (g_accept_thread.joinable()) g_accept_thread.join();

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(drain_timeout_ms);
    while (g_inflight.load(std::memory_order_acquire) > 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    int rem = g_inflight.load(std::memory_order_acquire);
    if (rem > 0) {
        WLOG_WARN("relay: %d in-flight connection(s) still active after drain", rem);
    }
}

} // namespace wrangler::proxy::relay
