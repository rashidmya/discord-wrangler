#include "doctest.h"
#include "proxy/client.hpp"
#include "proxy/url.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <cstring>
#include <unistd.h>

using namespace wrangler::proxy;

TEST_CASE("redact_url: no credentials -- preserved") {
    auto u = url::parse("socks5://host:1080").value();
    CHECK(client::redact_url(u) == "socks5://host:1080");
}

TEST_CASE("redact_url: credentials replaced with ***") {
    auto u = url::parse("socks5://alice:s3cret@host:1080").value();
    CHECK(client::redact_url(u) == "socks5://***@host:1080");
}

TEST_CASE("redact_url: http scheme preserved") {
    auto u = url::parse("http://corp-proxy:3128").value();
    CHECK(client::redact_url(u) == "http://corp-proxy:3128");
}

TEST_CASE("redact_url: IPv6 host bracketed in output") {
    auto u = url::parse("socks5://[::1]:1080").value();
    CHECK(client::redact_url(u) == "socks5://[::1]:1080");
}

namespace {
// Make an AF_UNIX socketpair. fds[0] is "ours" (handshake side), fds[1] is
// "the mock proxy server."
struct Pair {
    int ours, peer;
    Pair() {
        int s[2];
        REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
        ours = s[0]; peer = s[1];
    }
    ~Pair() { ::close(ours); ::close(peer); }
};

void write_all(int fd, const std::vector<uint8_t>& bytes) {
    size_t n = 0;
    while (n < bytes.size()) {
        ssize_t r = ::write(fd, bytes.data() + n, bytes.size() - n);
        REQUIRE(r > 0);
        n += static_cast<size_t>(r);
    }
}

std::vector<uint8_t> read_exact(int fd, size_t n) {
    std::vector<uint8_t> out(n);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, out.data() + got, n - got);
        REQUIRE(r > 0);
        got += static_cast<size_t>(r);
    }
    return out;
}

client::OrigDst v4_dst(uint32_t addr_be, uint16_t port_be) {
    client::OrigDst d{};
    d.family = AF_INET;
    std::memcpy(d.addr, &addr_be, 4);
    d.port = port_be;
    return d;
}
} // namespace

TEST_CASE("socks5: no-auth success path") {
    Pair p;
    int rc = -1;
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, v4_dst(htonl(0x7f000001), htons(443)), "", "");
    });

    // Expect greeting: ver=05 nmethods=01 methods=00
    auto greet = read_exact(p.peer, 3);
    CHECK(greet == std::vector<uint8_t>{0x05, 0x01, 0x00});
    write_all(p.peer, {0x05, 0x00}); // server picks no-auth

    // Expect CONNECT: 05 01 00 01 [4-byte v4] [2-byte port]
    auto req = read_exact(p.peer, 10);
    CHECK(req[0] == 0x05); CHECK(req[1] == 0x01);
    CHECK(req[2] == 0x00); CHECK(req[3] == 0x01);
    // Bytes 4-7 == 127.0.0.1 in network byte order
    CHECK(req[4] == 0x7f); CHECK(req[5] == 0x00);
    CHECK(req[6] == 0x00); CHECK(req[7] == 0x01);
    // Bytes 8-9 == 443 in network byte order
    CHECK(req[8] == 0x01); CHECK(req[9] == 0xbb);
    // Success reply: 05 00 00 01 [bnd.addr 4] [bnd.port 2]
    write_all(p.peer, {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0});

    t.join();
    CHECK(rc == 0);
}

TEST_CASE("socks5: user/pass success path") {
    Pair p;
    int rc = -1;
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, v4_dst(htonl(0x08080808), htons(80)),
                                      "alice", "s3cret");
    });

    // Expect greeting with methods including 02 (no-auth + user/pass)
    auto greet = read_exact(p.peer, 4);
    CHECK(greet[0] == 0x05);
    CHECK(greet[1] == 0x02);  // two methods
    CHECK(((greet[2] == 0x00 && greet[3] == 0x02) ||
           (greet[2] == 0x02 && greet[3] == 0x00)));
    write_all(p.peer, {0x05, 0x02}); // server picks user/pass

    // Expect sub-negotiation: 01 [ulen] alice [plen] s3cret
    auto subneg_hdr = read_exact(p.peer, 2);
    CHECK(subneg_hdr[0] == 0x01);
    CHECK(subneg_hdr[1] == 5);  // "alice"
    auto user_bytes = read_exact(p.peer, 5);
    CHECK(std::string(user_bytes.begin(), user_bytes.end()) == "alice");
    auto plen = read_exact(p.peer, 1);
    CHECK(plen[0] == 6);  // "s3cret"
    auto pass_bytes = read_exact(p.peer, 6);
    CHECK(std::string(pass_bytes.begin(), pass_bytes.end()) == "s3cret");
    write_all(p.peer, {0x01, 0x00});  // auth OK

    // CONNECT + reply (as before)
    (void)read_exact(p.peer, 10);
    write_all(p.peer, {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0});

    t.join();
    CHECK(rc == 0);
}

TEST_CASE("socks5: user/pass auth rejected") {
    Pair p;
    int rc = 0;
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, v4_dst(0, 0), "u", "p");
    });
    (void)read_exact(p.peer, 4);
    write_all(p.peer, {0x05, 0x02});
    (void)read_exact(p.peer, 5);  // 01 01 u 01 p
    write_all(p.peer, {0x01, 0x01});  // auth fail
    t.join();
    CHECK(rc < 0);
}

TEST_CASE("socks5: method-not-supported (server replies FF)") {
    Pair p;
    int rc = 0;
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, v4_dst(0, 0), "", "");
    });
    (void)read_exact(p.peer, 3);
    write_all(p.peer, {0x05, 0xff});
    t.join();
    CHECK(rc < 0);
}

TEST_CASE("socks5: CONNECT failure (rep != 0)") {
    Pair p;
    int rc = 0;
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, v4_dst(0, 0), "", "");
    });
    (void)read_exact(p.peer, 3);
    write_all(p.peer, {0x05, 0x00});
    (void)read_exact(p.peer, 10);
    write_all(p.peer, {0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0}); // rep=05 connection refused
    t.join();
    CHECK(rc < 0);
}

TEST_CASE("socks5: ipv6 dst") {
    Pair p;
    int rc = -1;
    client::OrigDst d{};
    d.family = AF_INET6;
    uint8_t loopback6[16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1};
    std::memcpy(d.addr, loopback6, 16);
    d.port = htons(8443);
    std::thread t([&]{
        rc = client::handshake_socks5(p.ours, d, "", "");
    });
    (void)read_exact(p.peer, 3);
    write_all(p.peer, {0x05, 0x00});
    // 05 01 00 04 [16 bytes ipv6] [2 bytes port]
    auto req = read_exact(p.peer, 22);
    CHECK(req[3] == 0x04);
    for (int i = 0; i < 16; ++i) CHECK(req[4 + i] == loopback6[i]);
    write_all(p.peer, {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0});
    t.join();
    CHECK(rc == 0);
}
