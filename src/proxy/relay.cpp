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

// Per-connection handler (this task: just close and count).
void handle_conn(int client_fd) {
    ::close(client_fd);
    g_inflight.fetch_sub(1, std::memory_order_release);
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
