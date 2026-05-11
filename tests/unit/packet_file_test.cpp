#include "doctest.h"
#include "packet_file.hpp"

#include <stdlib.h>
#include <string>
#include <vector>

using namespace wrangler;

namespace {
// RAII helper: set env vars and restore on destruction.
class EnvScope {
public:
    void set(const char* name, const char* value) {
        const char* old = getenv(name);
        saved_.emplace_back(name, old ? std::string(old) : std::string());
        had_old_.push_back(old != nullptr);
        if (value) setenv(name, value, 1);
        else unsetenv(name);
    }
    ~EnvScope() {
        for (size_t i = 0; i < saved_.size(); ++i) {
            const auto& [name, val] = saved_[i];
            if (had_old_[i]) setenv(name.c_str(), val.c_str(), 1);
            else unsetenv(name.c_str());
        }
    }
private:
    std::vector<std::pair<std::string, std::string>> saved_;
    std::vector<bool> had_old_;
};
}

TEST_CASE("resolve_path: WRANGLER_PACKET_FILE wins over XDG and HOME") {
    EnvScope env;
    env.set("WRANGLER_PACKET_FILE", "/tmp/explicit.bin");
    env.set("XDG_CONFIG_HOME",      "/tmp/xdg");
    env.set("HOME",                 "/tmp/home");

    auto p = packet_file::resolve_path();
    REQUIRE(p.has_value());
    CHECK(*p == "/tmp/explicit.bin");
}

TEST_CASE("resolve_path: XDG_CONFIG_HOME used when set, no env var override") {
    EnvScope env;
    env.set("WRANGLER_PACKET_FILE", nullptr);
    env.set("XDG_CONFIG_HOME",      "/tmp/xdg");
    env.set("HOME",                 "/tmp/home");

    auto p = packet_file::resolve_path();
    REQUIRE(p.has_value());
    CHECK(*p == "/tmp/xdg/discord-wrangler/wrangler-packet.bin");
}

TEST_CASE("resolve_path: HOME fallback when XDG unset") {
    EnvScope env;
    env.set("WRANGLER_PACKET_FILE", nullptr);
    env.set("XDG_CONFIG_HOME",      nullptr);
    env.set("HOME",                 "/tmp/home");

    auto p = packet_file::resolve_path();
    REQUIRE(p.has_value());
    CHECK(*p == "/tmp/home/.config/discord-wrangler/wrangler-packet.bin");
}

TEST_CASE("resolve_path: empty WRANGLER_PACKET_FILE disables lookup") {
    EnvScope env;
    env.set("WRANGLER_PACKET_FILE", "");
    env.set("XDG_CONFIG_HOME",      "/tmp/xdg");
    env.set("HOME",                 "/tmp/home");

    auto p = packet_file::resolve_path();
    CHECK_FALSE(p.has_value());
}

TEST_CASE("resolve_path: no env vars at all → nullopt") {
    EnvScope env;
    env.set("WRANGLER_PACKET_FILE", nullptr);
    env.set("XDG_CONFIG_HOME",      nullptr);
    env.set("HOME",                 nullptr);

    auto p = packet_file::resolve_path();
    CHECK_FALSE(p.has_value());
}

#include <unistd.h>
#include <fcntl.h>

namespace {
std::string make_tmp_file(const std::vector<uint8_t>& bytes) {
    char tpl[] = "/tmp/discord-wrangler-test-XXXXXX";
    int fd = mkstemp(tpl);
    REQUIRE(fd >= 0);
    if (!bytes.empty()) {
        ssize_t w = write(fd, bytes.data(), bytes.size());
        REQUIRE(w == (ssize_t)bytes.size());
    }
    close(fd);
    return std::string(tpl);
}
}

TEST_CASE("read: returns file contents for a small file") {
    auto path = make_tmp_file({0xAA, 0xBB, 0xCC});
    auto bytes = packet_file::read(path);
    unlink(path.c_str());

    REQUIRE(bytes.size() == 3);
    CHECK(bytes[0] == 0xAA);
    CHECK(bytes[1] == 0xBB);
    CHECK(bytes[2] == 0xCC);
}

TEST_CASE("read: missing file returns empty") {
    auto bytes = packet_file::read("/tmp/discord-wrangler-test-does-not-exist-xxx");
    CHECK(bytes.empty());
}

TEST_CASE("read: empty file returns empty") {
    auto path = make_tmp_file({});
    auto bytes = packet_file::read(path);
    unlink(path.c_str());
    CHECK(bytes.empty());
}

TEST_CASE("read: oversized file (>MAX_BYTES) returns empty") {
    std::vector<uint8_t> big(packet_file::MAX_BYTES + 1, 0xEE);
    auto path = make_tmp_file(big);
    auto bytes = packet_file::read(path);
    unlink(path.c_str());
    CHECK(bytes.empty());
}

TEST_CASE("read: file at exactly MAX_BYTES is returned") {
    std::vector<uint8_t> big(packet_file::MAX_BYTES, 0x42);
    auto path = make_tmp_file(big);
    auto bytes = packet_file::read(path);
    unlink(path.c_str());

    REQUIRE(bytes.size() == packet_file::MAX_BYTES);
    CHECK(bytes[0] == 0x42);
    CHECK(bytes[packet_file::MAX_BYTES - 1] == 0x42);
}
