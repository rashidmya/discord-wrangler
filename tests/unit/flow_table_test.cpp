#include "doctest.h"
#include "flow_table.hpp"

using namespace wrangler;

namespace {
FlowTable::Tuple t(uint8_t proto, uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport) {
    return FlowTable::Tuple{proto, src, sport, dst, dport};
}
}

TEST_CASE("consume_first: first call returns true") {
    FlowTable ft;
    auto k = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    CHECK(ft.consume_first(k) == true);
}

TEST_CASE("consume_first: second call returns false") {
    FlowTable ft;
    auto k = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    (void) ft.consume_first(k);
    CHECK(ft.consume_first(k) == false);
}

TEST_CASE("consume_first: different tuples are independent") {
    FlowTable ft;
    auto a = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    auto b = t(17, 0x0a000001, 12346, 0xc0a80101, 19297);   // different src port
    CHECK(ft.consume_first(a) == true);
    CHECK(ft.consume_first(b) == true);   // independent flow
}

#include <atomic>
#include <thread>
#include <vector>

TEST_CASE("consume_first is thread-safe: exactly one true across N threads") {
    FlowTable ft;
    auto k = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    constexpr int N = 8;
    std::atomic<int> winners{0};
    std::vector<std::thread> ts;
    ts.reserve(N);
    for (int i = 0; i < N; ++i) {
        ts.emplace_back([&] {
            if (ft.consume_first(k)) winners.fetch_add(1, std::memory_order_relaxed);
        });
    }
    for (auto& th : ts) th.join();
    CHECK(winners.load() == 1);
}

TEST_CASE("GC sweep on next consume_first removes entries older than 30s") {
    FlowTable ft;
    ft.set_test_clock_ms(1'000'000);
    auto k = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    CHECK(ft.consume_first(k) == true);

    // 31s later, the same tuple should count as a "new" flow (entry was swept).
    ft.set_test_clock_ms(1'031'000);
    CHECK(ft.consume_first(k) == true);
}

TEST_CASE("GC does NOT sweep entries inside the 30s window") {
    FlowTable ft;
    ft.set_test_clock_ms(1'000'000);
    auto k = t(17, 0x0a000001, 12345, 0xc0a80101, 19297);
    CHECK(ft.consume_first(k) == true);

    ft.set_test_clock_ms(1'029'999);   // 29.999s later — still inside window
    CHECK(ft.consume_first(k) == false);
}
