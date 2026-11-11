#pragma once
#include <chrono>
#include <cstdint>

namespace orbitguard {

inline std::uint64_t unix_time_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

}  // namespace orbitguard
