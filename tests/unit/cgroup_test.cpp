#include "doctest.h"
#include "proxy/cgroup.hpp"

using namespace wrangler::proxy;

TEST_CASE("cgroup: path uses UID") {
    auto p = cgroup::path_for_uid(1000);
    CHECK(p == "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"
               "/app.slice/discord-wrangler-discord.scope");
}

TEST_CASE("cgroup: parent_dir strips final segment") {
    auto p = cgroup::path_for_uid(1000);
    auto parent = cgroup::parent_dir(p);
    CHECK(parent == "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"
                    "/app.slice");
}

TEST_CASE("cgroup: scope_basename returns the scope filename") {
    CHECK(cgroup::scope_basename() == "discord-wrangler-discord.scope");
}

TEST_CASE("cgroup: exists is false for fabricated path") {
    auto p = cgroup::path_for_uid(99999);  // not a real user; not running
    CHECK_FALSE(cgroup::exists(p));
}
