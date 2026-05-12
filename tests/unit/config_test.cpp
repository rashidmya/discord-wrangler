#include "doctest.h"
#include "config.hpp"

#include <cstdlib>
#include <stdexcept>

namespace {
void unset_all_env() {
    unsetenv("WRANGLER_QUEUE_NUM");
    unsetenv("WRANGLER_FIRST_LEN");
    unsetenv("WRANGLER_HOLD_MS");
    unsetenv("WRANGLER_PACKET_FILE");
    unsetenv("WRANGLER_PROXY");
    unsetenv("WRANGLER_RELAY_PORT");
    unsetenv("WRANGLER_DISCORD_UID");
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

TEST_CASE("config: proxy fields from file") {
    unset_all_env();
    TmpConfFile f(
        "[wrangler]\n"
        "proxy = socks5://127.0.0.1:1080\n"
        "relay_port = 41080\n"
        "discord_uid = 1000\n"
    );
    auto c = wrangler::config::from_env();
    CHECK(c.proxy       == "socks5://127.0.0.1:1080");
    CHECK(c.relay_port  == 41080u);
    CHECK(c.discord_uid == 1000u);
}

TEST_CASE("config: proxy fields from env") {
    unset_all_env();
    setenv("WRANGLER_PROXY",       "http://example:8080", 1);
    setenv("WRANGLER_RELAY_PORT",  "42000",               1);
    setenv("WRANGLER_DISCORD_UID", "1234",                1);
    auto c = wrangler::config::from_env();
    CHECK(c.proxy       == "http://example:8080");
    CHECK(c.relay_port  == 42000u);
    CHECK(c.discord_uid == 1234u);
    unsetenv("WRANGLER_PROXY");
    unsetenv("WRANGLER_RELAY_PORT");
    unsetenv("WRANGLER_DISCORD_UID");
}

TEST_CASE("config: proxy mode disabled by default") {
    unset_all_env();
    auto c = wrangler::config::from_env();
    CHECK(c.proxy == "");
}

TEST_CASE("config: file with creds at mode 0600 is accepted") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nproxy = socks5://user:pass@host:1080\n");
    chmod(f.path.c_str(), 0600);
    auto c = wrangler::config::from_env();
    CHECK(c.proxy == "socks5://user:pass@host:1080");
}

TEST_CASE("config: file with creds at mode 0644 is rejected") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nproxy = socks5://user:pass@host:1080\n");
    chmod(f.path.c_str(), 0644);
    CHECK_THROWS_AS(wrangler::config::from_env(), std::runtime_error);
}

TEST_CASE("config: file at mode 0644 without creds is fine") {
    unset_all_env();
    TmpConfFile f("[wrangler]\nproxy = socks5://host:1080\n");
    chmod(f.path.c_str(), 0644);
    auto c = wrangler::config::from_env();
    CHECK(c.proxy == "socks5://host:1080");
}

TEST_CASE("config: file with empty userinfo at mode 0644 is rejected") {
    // Empty userinfo (scheme://@host) still has an `@` — the structural
    // signal that a credentials slot exists. The 0600 check applies.
    unset_all_env();
    TmpConfFile f("[wrangler]\nproxy = socks5://@host:1080\n");
    chmod(f.path.c_str(), 0644);
    CHECK_THROWS_AS(wrangler::config::from_env(), std::runtime_error);
}
