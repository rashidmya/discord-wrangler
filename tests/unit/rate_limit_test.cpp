#include "doctest.h"
#include "proxy/rate_limit.hpp"

#include <chrono>
#include <thread>

using namespace wrangler::proxy;
using namespace std::chrono_literals;

TEST_CASE("rate_limit: first call allowed") {
    RateLimiter r(1s);
    CHECK(r.allow("k"));
}

TEST_CASE("rate_limit: second call within window suppressed") {
    RateLimiter r(1s);
    CHECK(r.allow("k"));
    CHECK_FALSE(r.allow("k"));
}

TEST_CASE("rate_limit: call after window allowed again") {
    RateLimiter r(50ms);
    CHECK(r.allow("k"));
    std::this_thread::sleep_for(100ms);
    CHECK(r.allow("k"));
}

TEST_CASE("rate_limit: separate keys independent") {
    RateLimiter r(10s);
    CHECK(r.allow("a"));
    CHECK(r.allow("b"));
    CHECK_FALSE(r.allow("a"));
    CHECK_FALSE(r.allow("b"));
}
