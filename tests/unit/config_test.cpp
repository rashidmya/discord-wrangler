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

#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

namespace {
struct TmpConfFile {
    std::string path;
    TmpConfFile(const std::string& contents) {
        char buf[] = "/tmp/wrangler_conf_XXXXXX";
        int fd = mkstemp(buf);
        REQUIRE(fd >= 0);
        write(fd, contents.data(), contents.size());
        close(fd);
        path = buf;
        setenv("WRANGLER_CONF_FILE", path.c_str(), 1);
    }
    ~TmpConfFile() {
        unlink(path.c_str());
        unsetenv("WRANGLER_CONF_FILE");
    }
};
} // namespace

TEST_CASE("config: file values override defaults") {
    unset_all_env();
    TmpConfFile f(
        "[wrangler]\n"
        "queue_num = 3\n"
        "first_len = 99\n"
        "hold_ms = 123\n"
        "packet_file = /tmp/probe.bin\n"
    );
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num   == 3u);
    CHECK(c.first_len   == 99u);
    CHECK(c.hold_ms     == 123u);
    CHECK(c.packet_file == "/tmp/probe.bin");
}

TEST_CASE("config: env overrides file") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nqueue_num = 3\n");
    setenv("WRANGLER_QUEUE_NUM", "9", 1);
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 9u);
    unsetenv("WRANGLER_QUEUE_NUM");
}

TEST_CASE("config: comments and blank lines ignored") {
    unset_all_env();
    TmpConfFile f(
        "# top comment\n"
        "\n"
        "[wrangler]\n"
        "; semicolon comment\n"
        "queue_num = 2   ; trailing comment\n"
        "\n"
        "first_len = 88\n"
    );
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 2u);
    CHECK(c.first_len == 88u);
}

TEST_CASE("config: unknown keys ignored (don't fail)") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nqueue_num = 1\nfuture_key = something\n");
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 1u);
}

TEST_CASE("config: duplicate keys -- last wins") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nqueue_num = 1\nqueue_num = 5\n");
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 5u);
}

TEST_CASE("config: missing file -- defaults used") {
    unset_all_env();
    setenv("WRANGLER_CONF_FILE", "/nonexistent/path", 1);
    auto c = wrangler::config::from_env();
    CHECK(c.queue_num == 0u);
    unsetenv("WRANGLER_CONF_FILE");
}
