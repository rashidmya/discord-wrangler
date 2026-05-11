#pragma once

#include <chrono>
#include <string>
#include <unordered_map>

namespace wrangler::proxy {

class RateLimiter {
public:
    explicit RateLimiter(std::chrono::milliseconds window) : window_(window) {}

    bool allow(const std::string& key) {
        auto now = std::chrono::steady_clock::now();
        auto it = last_.find(key);
        if (it != last_.end() && now - it->second < window_) return false;
        last_[key] = now;
        return true;
    }

private:
    std::chrono::milliseconds window_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_;
};

} // namespace wrangler::proxy
