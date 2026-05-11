#include "config.hpp"

#include <climits>
#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>

namespace wrangler::config {
namespace {

uint32_t parse_u32(const char* v, uint32_t fallback) {
    if (!v || !*v) return fallback;
    char* end = nullptr;
    long x = std::strtol(v, &end, 10);
    if (end == v || x < 0 || x > static_cast<long>(UINT32_MAX)) return fallback;
    return static_cast<uint32_t>(x);
}

uint32_t parse_u32(const std::string& v, uint32_t fallback) {
    return v.empty() ? fallback : parse_u32(v.c_str(), fallback);
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Strip inline comments starting with ';' or '#'. Does not handle quoted strings
// (we don't need them for our config).
std::string strip_comment(const std::string& s) {
    size_t i = s.find_first_of(";#");
    return (i == std::string::npos) ? s : s.substr(0, i);
}

// Read INI file into a flat key->value map. Section names are ignored — we
// only have one section. Returns empty map if file missing or unreadable.
std::unordered_map<std::string, std::string> read_ini(const std::string& path) {
    std::unordered_map<std::string, std::string> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        line = trim(strip_comment(line));
        if (line.empty()) continue;
        if (line.front() == '[' && line.back() == ']') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = trim(line.substr(eq + 1));
        out[k] = v;
    }
    return out;
}

const char* conf_path() {
    if (const char* p = std::getenv("WRANGLER_CONF_FILE")) return p;
    return "/etc/discord-wrangler/discord-wrangler.conf";
}

std::string env_or(const char* name, const std::string& fallback) {
    if (const char* v = std::getenv(name); v && *v) return v;
    return fallback;
}

} // namespace

Config from_env() {
    Config c;
    auto ini = read_ini(conf_path());

    // Precedence: env > file > default. Read file first into a temp, then
    // overlay env.
    std::string queue_num_s   = ini.count("queue_num")   ? ini["queue_num"]   : "";
    std::string first_len_s   = ini.count("first_len")   ? ini["first_len"]   : "";
    std::string hold_ms_s     = ini.count("hold_ms")     ? ini["hold_ms"]     : "";
    std::string packet_file_s = ini.count("packet_file") ? ini["packet_file"] : "";

    queue_num_s   = env_or("WRANGLER_QUEUE_NUM",   queue_num_s);
    first_len_s   = env_or("WRANGLER_FIRST_LEN",   first_len_s);
    hold_ms_s     = env_or("WRANGLER_HOLD_MS",     hold_ms_s);
    packet_file_s = env_or("WRANGLER_PACKET_FILE", packet_file_s);

    c.queue_num   = static_cast<uint16_t>(parse_u32(queue_num_s, c.queue_num));
    c.first_len   = static_cast<uint16_t>(parse_u32(first_len_s, c.first_len));
    c.hold_ms     = parse_u32(hold_ms_s, c.hold_ms);
    c.packet_file = packet_file_s;

    return c;
}

} // namespace wrangler::config
