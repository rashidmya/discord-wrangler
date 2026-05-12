#include "proxy/relay.hpp"
#include "proxy/client.hpp"
#include "log.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>

namespace wrangler::proxy {

namespace {

int make_listener(int family, uint16_t port) {
    int fd = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -errno;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (family == AF_INET) {
        sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_port        = htons(port);
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

// Resolve the original destination for `client_fd`. Falls back to
// $WRANGLER_RELAY_FORCE_DST (test-only override) if SO_ORIGINAL_DST is
// unavailable.
bool resolve_orig_dst(int client_fd, client::OrigDst& out) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);

    if (::getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &ss, &len) == 0) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        out.family = AF_INET;
        std::memcpy(out.addr, &a->sin_addr.s_addr, 4);
        out.port = a->sin_port;
        return true;
    }
    len = sizeof(ss);
    if (::getsockopt(client_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &ss, &len) == 0) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        out.family = AF_INET6;
        std::memcpy(out.addr, &a->sin6_addr, 16);
        out.port = a->sin6_port;
        return true;
    }
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
                ssize_t w = ::splice(p1[0], nullptr, b, nullptr, r, SPLICE_F_MOVE);
                if (w <= 0) eof = true;
            }
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t r = ::splice(b, nullptr, p2[1], nullptr, CHUNK,
                                 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            if (r <= 0) { eof = true; }
            else {
                ssize_t w = ::splice(p2[0], nullptr, a, nullptr, r, SPLICE_F_MOVE);
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

} // namespace

Relay::~Relay() {
    // Use a generous drain so detached handler threads aren't still touching
    // member state when the object is destroyed. If they really do dangle,
    // the OS reclaims fds on process exit; logging is best-effort.
    stop(/*drain_timeout_ms=*/10000);
}

void Relay::handle_conn(int client_fd) {
    auto on_exit = [&] {
        ::close(client_fd);
        inflight_.fetch_sub(1, std::memory_order_release);
    };

    client::OrigDst dst{};
    if (!resolve_orig_dst(client_fd, dst)) {
        if (log_limit_.allow("no-orig-dst")) {
            WLOG_WARN("relay: no SO_ORIGINAL_DST on connection -- dropping");
        }
        on_exit();
        return;
    }

    int up = dial_upstream(proxy_cfg_);
    if (up < 0) {
        std::string key = "dial:" + proxy_cfg_.host + ":" + std::to_string(proxy_cfg_.port);
        if (log_limit_.allow(key)) {
            WLOG_WARN("relay: dial %s failed: %s",
                      client::redact_url(proxy_cfg_).c_str(), std::strerror(-up));
        }
        on_exit();
        return;
    }

    if (int r = client::handshake(up, dst, proxy_cfg_); r != 0) {
        if (log_limit_.allow("handshake-err")) {
            WLOG_WARN("relay: handshake to %s failed: %s",
                      client::redact_url(proxy_cfg_).c_str(), std::strerror(-r));
        }
        ::close(up);
        on_exit();
        return;
    }

    splice_both(client_fd, up);
    ::close(up);
    on_exit();
}

void Relay::accept_loop() {
    pollfd pfds[3];
    nfds_t npfds = 0;
    if (listen_v4_ >= 0) { pfds[npfds++] = pollfd{listen_v4_, POLLIN, 0}; }
    if (listen_v6_ >= 0) { pfds[npfds++] = pollfd{listen_v6_, POLLIN, 0}; }
    pfds[npfds++] = pollfd{wake_rfd_, POLLIN, 0};

    while (running_.load(std::memory_order_acquire)) {
        for (nfds_t i = 0; i < npfds; ++i) pfds[i].revents = 0;
        int r = ::poll(pfds, npfds, -1);
        if (r < 0) { if (errno == EINTR) continue; break; }

        // Wake fd? Drain it and exit when running_ flips.
        if (pfds[npfds - 1].revents & POLLIN) {
            char tmp[16];
            while (::read(wake_rfd_, tmp, sizeof(tmp)) > 0) {}
            continue;
        }

        for (nfds_t i = 0; i < npfds - 1; ++i) {
            if (!(pfds[i].revents & POLLIN)) continue;
            int lf = pfds[i].fd;
            while (true) {
                int c = ::accept4(lf, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (c < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    if (errno == EINTR) continue;
                    WLOG_DEBUG("relay: accept: %s", std::strerror(errno));
                    break;
                }
                inflight_.fetch_add(1, std::memory_order_acq_rel);
                try {
                    std::thread([this, c] { handle_conn(c); }).detach();
                } catch (const std::system_error& e) {
                    WLOG_WARN("relay: failed to spawn handler thread: %s", e.what());
                    ::close(c);
                    inflight_.fetch_sub(1, std::memory_order_release);
                }
            }
        }
    }
}

int Relay::start(const wrangler::config::Config& cfg) {
    auto parsed = url::parse(cfg.proxy);
    if (!parsed) {
        WLOG_ERROR("relay: WRANGLER_PROXY value is unparseable (check scheme/host/port)");
        return -EINVAL;
    }
    proxy_cfg_ = *parsed;
    WLOG_INFO("relay: upstream proxy = %s", client::redact_url(proxy_cfg_).c_str());

    int wp[2];
    if (::pipe2(wp, O_CLOEXEC | O_NONBLOCK) < 0) {
        int e = errno;
        WLOG_ERROR("relay: self-pipe pipe2: %s", std::strerror(e));
        return -e;
    }
    wake_rfd_ = wp[0];
    wake_wfd_ = wp[1];

    listen_v4_ = make_listener(AF_INET, cfg.relay_port);
    if (listen_v4_ < 0) {
        int e = listen_v4_;
        WLOG_ERROR("relay: bind v4 :%u failed: %s",
                   cfg.relay_port, std::strerror(-e));
        ::close(wake_rfd_); ::close(wake_wfd_);
        wake_rfd_ = wake_wfd_ = -1;
        return e;
    }
    listen_v6_ = make_listener(AF_INET6, cfg.relay_port);
    if (listen_v6_ < 0) {
        WLOG_WARN("relay: bind v6 :%u failed: %s (continuing with v4 only)",
                  cfg.relay_port, std::strerror(-listen_v6_));
        listen_v6_ = -1;
    }
    running_.store(true, std::memory_order_release);
    accept_thread_ = std::thread([this] { accept_loop(); });
    WLOG_INFO("relay: listening on 127.0.0.1:%u%s",
              cfg.relay_port, listen_v6_ >= 0 ? " and [::1]" : "");
    return 0;
}

void Relay::stop(uint32_t drain_timeout_ms) {
    if (!running_.exchange(false, std::memory_order_acq_rel)) return;

    if (wake_wfd_ >= 0) {
        const char b = 'x';
        ssize_t n;
        do { n = ::write(wake_wfd_, &b, 1); } while (n < 0 && errno == EINTR);
    }
    if (listen_v4_ >= 0) { ::shutdown(listen_v4_, SHUT_RD); ::close(listen_v4_); listen_v4_ = -1; }
    if (listen_v6_ >= 0) { ::shutdown(listen_v6_, SHUT_RD); ::close(listen_v6_); listen_v6_ = -1; }
    if (accept_thread_.joinable()) accept_thread_.join();
    if (wake_rfd_ >= 0) { ::close(wake_rfd_); wake_rfd_ = -1; }
    if (wake_wfd_ >= 0) { ::close(wake_wfd_); wake_wfd_ = -1; }

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(drain_timeout_ms);
    while (inflight_.load(std::memory_order_acquire) > 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    int rem = inflight_.load(std::memory_order_acquire);
    if (rem > 0) {
        WLOG_WARN("relay: %d in-flight connection(s) still active after drain", rem);
    }
}

} // namespace wrangler::proxy
