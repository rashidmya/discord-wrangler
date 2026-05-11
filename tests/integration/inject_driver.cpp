// Sends one UDP packet via the raw-socket inject path.
// Usage: inject_driver <src_addr> <src_port> <dst_addr> <dst_port> <payload_hex>
// Example: inject_driver 127.0.0.1 40000 127.0.0.1 50000 deadbeef

#include "direct/inject.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static std::vector<uint8_t> hex_to_bytes(const char* h) {
    std::vector<uint8_t> out;
    size_t n = std::strlen(h);
    for (size_t i = 0; i + 1 < n; i += 2) {
        unsigned v;
        std::sscanf(h + i, "%2x", &v);
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc != 6) { std::fprintf(stderr, "usage: %s src sport dst dport hex\n", argv[0]); return 2; }
    in_addr s, d;
    if (!inet_aton(argv[1], &s) || !inet_aton(argv[3], &d)) return 2;
    uint16_t sp = static_cast<uint16_t>(std::atoi(argv[2]));
    uint16_t dp = static_cast<uint16_t>(std::atoi(argv[4]));
    auto bytes = hex_to_bytes(argv[5]);

    if (wrangler::direct::inject::init() < 0) return 1;
    int r = wrangler::direct::inject::send_udp(s.s_addr, htons(sp), d.s_addr, htons(dp),
                                       bytes.data(), bytes.size());
    wrangler::direct::inject::shutdown();
    std::fprintf(stdout, "send_udp returned %d\n", r);
    return r > 0 ? 0 : 1;
}
