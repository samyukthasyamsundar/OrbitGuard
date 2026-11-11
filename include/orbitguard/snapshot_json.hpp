#pragma once
#include <cstdint>
#include <string>

#include "orbitguard/telemetry_store.hpp"

namespace orbitguard {

// JSON for the dashboard API. Samples have already passed codec validation, so
// every number is finite (JSON cannot represent NaN or infinity).
std::string snapshot_to_json(const Snapshot& snapshot, std::uint64_t server_time_ms);

}  // namespace orbitguard
