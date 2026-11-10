#pragma once
#include <cstdint>

namespace orbitguard {

// In-memory (engineering units) telemetry sample. This struct is NEVER sent
// on the wire directly; see packet_codec.hpp for the wire format.
struct Telemetry {
    std::uint32_t sequence = 0;
    std::uint64_t timestamp_ms = 0;  // ms since Unix epoch (UTC)
    double battery_pct = 0.0;        // 0 .. 100 %
    double temperature_c = 0.0;      // -100 .. 150 C
    double cpu_pct = 0.0;            // 0 .. 100 %
    double signal_dbm = 0.0;         // -200 .. 50 dBm
};

// Physical limits enforced on both encode and decode.
namespace limits {
constexpr double kBatteryMin = 0.0,    kBatteryMax = 100.0;
constexpr double kTempMin    = -100.0, kTempMax    = 150.0;
constexpr double kCpuMin     = 0.0,    kCpuMax     = 100.0;
constexpr double kSignalMin  = -200.0, kSignalMax  = 50.0;
}  // namespace limits

}  // namespace orbitguard
