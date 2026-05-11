#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace wrangler::direct {

class FlowTable {
public:
    static constexpr int64_t GC_THRESHOLD_MS = 30'000;

    struct Tuple {
        uint8_t  proto;     // IPPROTO_UDP = 17
        uint32_t src_addr;  // network byte order
        uint16_t src_port;  // network byte order
        uint32_t dst_addr;  // network byte order
        uint16_t dst_port;  // network byte order

        bool operator==(const Tuple& o) const noexcept {
            return proto == o.proto
                && src_addr == o.src_addr && src_port == o.src_port
                && dst_addr == o.dst_addr && dst_port == o.dst_port;
        }
    };

    struct TupleHash {
        size_t operator()(const Tuple& t) const noexcept {
            // Mix all fields. proto is 1 byte but we pack into a single uint64 with both ports
            // and let two-step combine handle the addresses.
            uint64_t a = (uint64_t)t.src_addr << 32 | t.dst_addr;
            uint64_t b = (uint64_t)t.src_port << 16 | t.dst_port;
            b ^= t.proto * 0x9e3779b97f4a7c15ULL;
            uint64_t h = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
            return static_cast<size_t>(h);
        }
    };

    FlowTable();
    ~FlowTable();

    // Returns true iff this is the first time we've seen `tuple` (or we previously
    // saw it but its entry has been swept by GC). Always atomic w.r.t. concurrent callers.
    bool consume_first(const Tuple& tuple);

    // Testing seam — override "now" for deterministic GC tests.
    void set_test_clock_ms(int64_t fixed_ms_or_negative);

private:
    struct Entry {
        int64_t created_at_ms;
    };

    std::unordered_map<Tuple, Entry, TupleHash> entries_;
    std::mutex                                  mu_;
    int64_t                                     test_clock_ms_{-1};

    void    collect_garbage_locked(int64_t now);
    int64_t now_ms_locked() const;
    static int64_t real_now_ms();
};

} // namespace wrangler::direct
