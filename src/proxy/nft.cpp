#include "proxy/nft.hpp"
#include "log.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <sys/wait.h>

namespace wrangler::proxy::nft {
namespace {

std::string render(const std::string& tmpl_path,
                   const std::string& cgroup_path,
                   uint16_t relay_port) {
    std::ifstream f(tmpl_path);
    if (!f) return "";
    std::ostringstream oss;
    oss << f.rdbuf();
    std::string s = oss.str();

    auto replace = [&](const std::string& key, const std::string& val) {
        size_t pos = 0;
        while ((pos = s.find(key, pos)) != std::string::npos) {
            s.replace(pos, key.size(), val);
            pos += val.size();
        }
    };
    replace("@CGROUP_PATH@", cgroup_path);
    replace("@RELAY_PORT@",  std::to_string(relay_port));
    return s;
}

// Run `nft -f -` and feed `rules` on stdin. Returns 0 on exit-zero,
// negative on any failure.
int nft_apply(const std::string& rules) {
    int p[2];
    if (::pipe(p) < 0) return -errno;
    pid_t pid = ::fork();
    if (pid < 0) {
        int e = errno; ::close(p[0]); ::close(p[1]); return -e;
    }
    if (pid == 0) {
        // Child: stdin <- pipe, exec nft.
        ::dup2(p[0], 0);
        ::close(p[0]); ::close(p[1]);
        ::execlp("nft", "nft", "-f", "-", nullptr);
        _exit(127);
    }
    ::close(p[0]);
    ssize_t left = static_cast<ssize_t>(rules.size());
    const char* buf = rules.data();
    while (left > 0) {
        ssize_t n = ::write(p[1], buf, left);
        if (n < 0) { if (errno == EINTR) continue; break; }
        buf += n; left -= n;
    }
    ::close(p[1]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        WLOG_ERROR("nft -f - exited with status %d", WEXITSTATUS(status));
        return -EIO;
    }
    return 0;
}

} // namespace

int install(const std::string& tmpl_path,
            const std::string& cgroup_path,
            uint16_t relay_port) {
    std::string rules = render(tmpl_path, cgroup_path, relay_port);
    if (rules.empty()) {
        WLOG_ERROR("nft: template %s missing or empty", tmpl_path.c_str());
        return -ENOENT;
    }
    WLOG_INFO("nft: installing proxy rules (cgroup=%s relay=:%u)",
              cgroup_path.c_str(), relay_port);
    return nft_apply(rules);
}

int remove() {
    pid_t pid = ::fork();
    if (pid < 0) return -errno;
    if (pid == 0) {
        // Suppress nft's "table not found" stderr noise.
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) { ::dup2(devnull, 2); ::close(devnull); }
        ::execlp("nft", "nft", "delete", "table", "inet", "discord_wrangler_proxy",
                 nullptr);
        _exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return 0;  // best-effort; nonzero = table already absent, fine.
}

} // namespace wrangler::proxy::nft
