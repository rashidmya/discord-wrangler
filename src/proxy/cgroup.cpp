#include "proxy/cgroup.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

namespace wrangler::proxy::cgroup {

std::string path_for_uid(uint32_t uid) {
    std::string u = std::to_string(uid);
    return "/sys/fs/cgroup/user.slice/user-" + u + ".slice/user@" + u +
           ".service/app.slice/" + scope_basename();
}

std::string parent_dir(const std::string& cgroup_path) {
    auto pos = cgroup_path.rfind('/');
    if (pos == std::string::npos) return "";
    return cgroup_path.substr(0, pos);
}

bool exists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

Watcher::Watcher(std::string parent, std::string scope,
                 Callback on_appear, Callback on_disappear)
    : parent_dir_(std::move(parent)),
      scope_name_(std::move(scope)),
      on_appear_(std::move(on_appear)),
      on_disappear_(std::move(on_disappear)) {}

Watcher::~Watcher() { stop(); }

int Watcher::start() {
    inotify_fd_ = ::inotify_init1(IN_CLOEXEC);
    if (inotify_fd_ < 0) {
        int e = errno;
        WLOG_WARN("cgroup: inotify_init1: %s", strerror(e));
        return -e;
    }

    int wd = ::inotify_add_watch(inotify_fd_, parent_dir_.c_str(),
                                 IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd < 0) {
        int e = errno;
        WLOG_WARN("cgroup: inotify_add_watch(%s): %s",
                  parent_dir_.c_str(), strerror(e));
        ::close(inotify_fd_);
        inotify_fd_ = -1;
        return -e;
    }

    running_.store(true, std::memory_order_release);

    // Fire on_appear once if scope already exists.
    if (exists(parent_dir_ + "/" + scope_name_)) {
        WLOG_INFO("cgroup: scope already present at startup; installing rules");
        on_appear_();
    }

    // Capture the fd in a local. stop() writes inotify_fd_ concurrently;
    // reading it from the worker thread would race the assignment.
    int fd = inotify_fd_;
    thread_ = std::thread([this, fd]{
        char buf[4096] __attribute__((aligned(__alignof__(inotify_event))));
        while (running_.load(std::memory_order_acquire)) {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            for (char* p = buf; p < buf + n; ) {
                auto* ev = reinterpret_cast<inotify_event*>(p);
                if (ev->len > 0 && scope_name_ == ev->name) {
                    if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
                        WLOG_INFO("cgroup: scope appeared -- installing rules");
                        on_appear_();
                    } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
                        WLOG_INFO("cgroup: scope disappeared -- removing rules");
                        on_disappear_();
                    }
                }
                p += sizeof(inotify_event) + ev->len;
            }
        }
    });
    return 0;
}

void Watcher::stop() {
    running_.store(false, std::memory_order_release);
    if (inotify_fd_ >= 0) { ::close(inotify_fd_); inotify_fd_ = -1; }
    if (thread_.joinable()) thread_.join();
}

} // namespace wrangler::proxy::cgroup
