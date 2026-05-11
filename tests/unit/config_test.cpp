#include "doctest.h"
#include "config.hpp"

#include <cstdlib>

namespace {
void unset_all_env() {
    unsetenv("WRANGLER_QUEUE_NUM");
    unsetenv("WRANGLER_FIRST_LEN");
    unsetenv("WRANGLER_HOLD_MS");
    unsetenv("WRANGLER_PACKET_FILE");
}
} // namespace

TEST_CASE("config: defaults when no env set") {
    unset_all_env();
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num   == 0u);
    CHECK(c.first_len   == 74u);
    CHECK(c.hold_ms     == 50u);
    CHECK(c.packet_file == "");
}

TEST_CASE("config: env overrides defaults") {
    unset_all_env();
    setenv("WRANGLER_QUEUE_NUM", "7",   1);
    setenv("WRANGLER_FIRST_LEN", "100", 1);
    setenv("WRANGLER_HOLD_MS",   "200", 1);
    setenv("WRANGLER_PACKET_FILE", "/tmp/x", 1);
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num   == 7u);
    CHECK(c.first_len   == 100u);
    CHECK(c.hold_ms     == 200u);
    CHECK(c.packet_file == "/tmp/x");
    unset_all_env();
}

TEST_CASE("config: garbage env values fall back to defaults") {
    unset_all_env();
    setenv("WRANGLER_QUEUE_NUM", "not-a-number", 1);
    setenv("WRANGLER_FIRST_LEN", "-5",           1);
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 0u);
    CHECK(c.first_len == 74u);
    unset_all_env();
}
