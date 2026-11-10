#pragma once
// Deterministic (seeded) satellite state model. Separate from networking so
// it can be unit-tested and reused by a future dashboard/replay tool.
#include <cstdint>
#include <random>

#include "orbitguard/telemetry.hpp"

namespace orbitguard {

class TelemetryGenerator {
public:
    // orbit_period_s: simulated orbit length; ~37% of it is spent in eclipse.
    explicit TelemetryGenerator(std::uint32_t seed = 42, double orbit_period_s = 90.0 * 60.0);

    // Advance the model by dt_s simulated seconds and emit one sample.
    // The caller supplies the timestamp so tests do not depend on wall time.
    Telemetry next(double dt_s, std::uint64_t timestamp_ms);

private:
    std::mt19937 rng_;
    double period_s_;
    double t_s_ = 0.0;
    double battery_ = 95.0;
    double temp_ = 20.0;
    std::uint32_t seq_ = 0;
};

}  // namespace orbitguard
