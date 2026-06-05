#pragma once

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string_view>

namespace wrangler::log {

enum class Level : int { Debug = 0, Info = 1, Warn = 2, Error = 3 };

// Set once by main() (before any worker thread is spawned) via
// set_level_from_env(). After that the value is read-only, so plain
// non-atomic access is safe.
inline Level g_level = Level::Info;

// Set the level from a string name. Unknown/empty values are ignored, leaving
// the current level unchanged.
inline void set_level_from_string(std::string_view v) {
    if      (v == "debug") g_level = Level::Debug;
    else if (v == "info")  g_level = Level::Info;
    else if (v == "warn")  g_level = Level::Warn;
    else if (v == "error") g_level = Level::Error;
}

inline void set_level_from_env() {
    if (const char* v = std::getenv("WRANGLER_LOG_LEVEL")) set_level_from_string(v);
}

inline const char* prefix(Level l) {
    switch (l) {
        case Level::Debug: return "[debug] ";
        case Level::Info:  return "[info]  ";
        case Level::Warn:  return "[warn]  ";
        case Level::Error: return "[error] ";
    }
    return "[?] ";
}

__attribute__((format(printf, 2, 3)))
inline void logf(Level l, const char* fmt, ...) {
    if (static_cast<int>(l) < static_cast<int>(g_level)) return;
    std::fputs(prefix(l), stderr);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

#define WLOG_DEBUG(...) ::wrangler::log::logf(::wrangler::log::Level::Debug, __VA_ARGS__)
#define WLOG_INFO(...)  ::wrangler::log::logf(::wrangler::log::Level::Info,  __VA_ARGS__)
#define WLOG_WARN(...)  ::wrangler::log::logf(::wrangler::log::Level::Warn,  __VA_ARGS__)
#define WLOG_ERROR(...) ::wrangler::log::logf(::wrangler::log::Level::Error, __VA_ARGS__)

} // namespace wrangler::log
