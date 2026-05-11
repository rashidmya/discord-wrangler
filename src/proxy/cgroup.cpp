#include "proxy/cgroup.hpp"

#include <sys/stat.h>

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

} // namespace wrangler::proxy::cgroup
