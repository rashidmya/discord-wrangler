#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wrangler::packet_file {

constexpr size_t MAX_BYTES = 65536;

// Resolves the packet file path per env-var precedence rules.
// Returns nullopt if no path is configured (lookup is disabled).
std::optional<std::string> resolve_path();

// Reads up to MAX_BYTES from `path`. Returns empty vector on any error
// (missing, oversized, permission denied, etc). Never throws.
std::vector<uint8_t> read(const std::string& path);

} // namespace wrangler::packet_file
