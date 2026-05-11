#pragma once

#include <cstdint>
#include <string>

namespace wrangler::proxy::cgroup {

// Returns the absolute cgroup v2 path that discord-wrangler-launch creates
// for user `uid` via `systemd-run --user --scope --unit=...`.
std::string path_for_uid(uint32_t uid);

// Returns the parent directory of a given cgroup path (used as the inotify
// watch target).
std::string parent_dir(const std::string& cgroup_path);

// Fixed name of the scope created by the launcher.
inline std::string scope_basename() { return "discord-wrangler-discord.scope"; }

// True if `path` exists as a directory.
bool exists(const std::string& path);

} // namespace wrangler::proxy::cgroup
