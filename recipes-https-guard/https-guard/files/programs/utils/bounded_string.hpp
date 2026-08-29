#pragma once

#include <cstddef>
#include <cstring>
#include <string>

namespace https_guard {

/**
 * Converts a fixed-size char array (as found in a raw BPF event struct,
 * e.g. uprobe_event::process) into a std::string, stopping at the first
 * null byte or the array's own size — whichever comes first. Safe even
 * when the source was never null-terminated (bpf_get_current_comm() and
 * bpf_probe_read_user() don't guarantee it).
 */
template <std::size_t N>
std::string boundedString(const char (&raw)[N])
{
    return std::string(raw, strnlen(raw, N));
}

}  // namespace https_guard
