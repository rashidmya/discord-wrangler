#include "proxy/nft.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <initializer_list>
#include <sstream>
#include <string>
#include <unistd.h>
#include <utility>
#include <sys/wait.h>

#ifndef DISCORD_WRANGLER_NFT_BIN
#define DISCORD_WRANGLER_NFT_BIN "/usr/sbin/nft"
#endif

namespace wrangler::proxy::nft {
namespace {

// nft's `socket cgroupv2 level N "PATH"` matcher expects PATH relative to
// the cgroup root (e.g. "user.slice/user-1000.slice/...") — NOT prefixed
// with /sys/fs/cgroup/. The inotify watcher uses the full filesystem path,
// so strip the prefix here when handing it to nft.
std::string to_cgroup_relative(const std::string& path) {
    static const std::string PREFIX = "/sys/fs/cgroup/";
    if (path.compare(0, PREFIX.size(), PREFIX) == 0) {
        return path.substr(PREFIX.size());
    }
    return path;
}

std::string read_template(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

// Substitute each @KEY@ placeholder in `tmpl` in a single forward pass.
// Substituted text is not re-scanned, so a value that happens to contain
// `@OTHER@` cannot accidentally trigger a second replacement.
std::string substitute(const std::string& tmpl,
                       std::initializer_list<std::pair<std::string, std::string>> subs) {
    std::string out;
    out.reserve(tmpl.size());
    for (size_t i = 0; i < tmpl.size();) {
        if (tmpl[i] != '@') { out += tmpl[i++]; continue; }
        bool matched = false;
        for (const auto& [key, val] : subs) {
            if (tmpl.compare(i, key.size(), key) == 0) {
                out += val;
                i += key.size();
                matched = true;
                break;
            }
        }
        if (!matched) { out += tmpl[i++]; }
    }
    return out;
}

// Spawn nft with the given argv (NULL-terminated). Optionally pipe `stdin_data`
// to the child's stdin. Returns 0 on success, negative errno-style code on
// pipe/fork/exec/wait failure or non-zero exit.
int spawn_nft(const char* const argv[], const std::string* stdin_data,
              bool suppress_stderr) {
    int p[2] = {-1, -1};
    if (stdin_data && ::pipe2(p, O_CLOEXEC) < 0) return -errno;

    pid_t pid = ::fork();
    if (pid < 0) {
        int e = errno;
        if (p[0] >= 0) { ::close(p[0]); ::close(p[1]); }
        return -e;
    }
    if (pid == 0) {
        if (stdin_data) {
            ::dup2(p[0], 0);
            ::close(p[0]); ::close(p[1]);
        }
        if (suppress_stderr) {
            int devnull = ::open("/dev/null", O_WRONLY);
            if (devnull >= 0) { ::dup2(devnull, 2); ::close(devnull); }
        }
        ::execv(DISCORD_WRANGLER_NFT_BIN, const_cast<char* const*>(argv));
        _exit(127);
    }
    if (stdin_data) {
        ::close(p[0]);
        ssize_t left = static_cast<ssize_t>(stdin_data->size());
        const char* buf = stdin_data->data();
        while (left > 0) {
            ssize_t n = ::write(p[1], buf, left);
            if (n < 0) { if (errno == EINTR) continue; break; }
            buf += n; left -= n;
        }
        ::close(p[1]);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -EIO;
    }
    return 0;
}

} // namespace

int install(const std::string& tmpl_path,
            const std::string& cgroup_path,
            uint16_t relay_port) {
    std::string tmpl = read_template(tmpl_path);
    if (tmpl.empty()) {
        WLOG_ERROR("nft: template %s missing or empty", tmpl_path.c_str());
        return -ENOENT;
    }
    std::string rules = substitute(tmpl, {
        {"@CGROUP_PATH@", to_cgroup_relative(cgroup_path)},
        {"@RELAY_PORT@",  std::to_string(relay_port)},
    });
    WLOG_INFO("nft: installing proxy rules (cgroup=%s relay=:%u)",
              cgroup_path.c_str(), relay_port);
    const char* const argv[] = {"nft", "-f", "-", nullptr};
    int r = spawn_nft(argv, &rules, /*suppress_stderr=*/false);
    if (r != 0) {
        WLOG_ERROR("nft -f - failed (%s)", std::strerror(-r));
    }
    return r;
}

int remove() {
    // Best-effort: nonzero exit (e.g. "table not found") is fine.
    const char* const argv[] = {
        "nft", "delete", "table", "inet", "discord_wrangler_proxy", nullptr,
    };
    (void)spawn_nft(argv, /*stdin_data=*/nullptr, /*suppress_stderr=*/true);
    return 0;
}

} // namespace wrangler::proxy::nft
