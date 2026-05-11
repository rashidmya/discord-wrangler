#pragma once

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>

namespace wrangler::log {

enum class Level : int { Debug = 0, Info = 1, Warn = 2, Error = 3 };

inline Level g_level = Level::Info;

inline void set_level_from_env() {
    const char* v = std::getenv("WRANGLER_LOG_LEVEL");
    if (!v) return;
    if      (std::strcmp(v, "debug") == 0) g_level = Level::Debug;
    else if (std::strcmp(v, "info")  == 0) g_level = Level::Info;
    else if (std::strcmp(v, "warn")  == 0) g_level = Level::Warn;
    else if (std::strcmp(v, "error") == 0) g_level = Level::Error;
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
