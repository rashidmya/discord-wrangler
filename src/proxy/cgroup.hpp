#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace wrangler::proxy::cgroup {

std::string path_for_uid(uint32_t uid);
std::string parent_dir(const std::string& cgroup_path);
inline std::string scope_basename() { return "discord-wrangler-discord.scope"; }
bool exists(const std::string& path);

// Watches the parent_dir for creation/deletion of scope_basename().
// Callback `on_appear` runs (in a worker thread) when the scope appears;
// `on_disappear` runs when it goes away.
//
// On start(), if the scope already exists, on_appear is called once
// immediately. Then inotify takes over until stop().
class Watcher {
public:
    using Callback = std::function<void()>;

    Watcher(std::string parent_dir, std::string scope_name,
            Callback on_appear, Callback on_disappear);
    ~Watcher();

    int start();   // returns 0 on success, negative errno on inotify failure.
    void stop();

private:
    std::string parent_dir_;
    std::string scope_name_;
    Callback on_appear_;
    Callback on_disappear_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    int inotify_fd_ = -1;
};

} // namespace wrangler::proxy::cgroup
