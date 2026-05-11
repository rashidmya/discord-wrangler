#include "packet_file.hpp"

#include <stdlib.h>
#include <fstream>

namespace wrangler::direct::packet_file {

static std::optional<std::string> env(const char* name) {
    const char* v = ::getenv(name);
    if (!v) return std::nullopt;
    return std::string(v);
}

std::optional<std::string> resolve_path() {
    if (auto e = env("WRANGLER_PACKET_FILE")) {
        if (e->empty()) return std::nullopt;   // explicit disable
        return *e;
    }
    if (auto xdg = env("XDG_CONFIG_HOME")) {
        return *xdg + "/discord-wrangler/wrangler-packet.bin";
    }
    if (auto home = env("HOME")) {
        return *home + "/.config/discord-wrangler/wrangler-packet.bin";
    }
    return std::nullopt;
}

std::vector<uint8_t> read(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) return {};

    std::streamsize size = ifs.tellg();
    if (size <= 0) return {};
    if (static_cast<size_t>(size) > MAX_BYTES) return {};

    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(static_cast<size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(out.data()), size)) return {};
    return out;
}

} // namespace wrangler::direct::packet_file
