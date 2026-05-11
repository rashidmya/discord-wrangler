#include "flow_table.hpp"

#include <time.h>

namespace wrangler {

FlowTable::FlowTable() = default;
FlowTable::~FlowTable() = default;

int64_t FlowTable::real_now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000
         + static_cast<int64_t>(ts.tv_nsec / 1'000'000);
}

int64_t FlowTable::now_ms_locked() const {
    return (test_clock_ms_ >= 0) ? test_clock_ms_ : real_now_ms();
}

void FlowTable::set_test_clock_ms(int64_t v) {
    std::lock_guard<std::mutex> lk(mu_);
    test_clock_ms_ = v;
}

void FlowTable::collect_garbage_locked(int64_t now) {
    int64_t cutoff = now - GC_THRESHOLD_MS;
    for (auto it = entries_.begin(); it != entries_.end(); ) {
        if (it->second.created_at_ms < cutoff) it = entries_.erase(it);
        else ++it;
    }
}

bool FlowTable::consume_first(const Tuple& tuple) {
    std::lock_guard<std::mutex> lk(mu_);
    int64_t now = now_ms_locked();
    collect_garbage_locked(now);

    auto [it, inserted] = entries_.try_emplace(tuple, Entry{now});
    if (inserted) return true;
    // Re-claim after GC: handled implicitly above (sweep happens before insert).
    return false;
}

} // namespace wrangler
