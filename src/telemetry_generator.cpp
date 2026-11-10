#include "orbitguard/telemetry_generator.hpp"

#include <algorithm>
#include <cmath>

namespace orbitguard {

namespace {
constexpr double kPi = 3.14159265358979323846;
double clamp(double v, double lo, double hi) { return std::min(hi, std::max(lo, v)); }
}  // namespace

TelemetryGenerator::TelemetryGenerator(std::uint32_t seed, double orbit_period_s)
    : rng_(seed), period_s_(orbit_period_s) {}

Telemetry TelemetryGenerator::next(double dt_s, std::uint64_t timestamp_ms) {
    std::normal_distribution<double> noise(0.0, 1.0);

    t_s_ += dt_s;
    const double phase = std::fmod(t_s_, period_s_) / period_s_;  // 0..1
    const bool eclipse = phase > 0.63;

    // Battery: charges in sunlight, drains in eclipse (percent per second).
    battery_ = clamp(battery_ + (eclipse ? -0.020 : 0.012) * dt_s, 0.0, 100.0);

    // Temperature relaxes toward a sun/eclipse equilibrium (first-order lag).
    const double target = eclipse ? -15.0 : 45.0;
    temp_ += (target - temp_) * std::min(1.0, dt_s / 600.0);

    // CPU: baseline load plus an activity burst during the sunlit pass.
    const double cpu = 25.0 + (eclipse ? 0.0 : 15.0 * std::sin(phase / 0.63 * kPi)) + 3.0 * noise(rng_);

    // Signal: strongest at the middle of the sunlit pass (proxy for ground-station elevation).
    const double sig = -95.0 + 25.0 * std::sin(phase * 2.0 * kPi) * std::sin(phase * 2.0 * kPi) + 1.5 * noise(rng_);

    Telemetry t;
    t.sequence = seq_++;
    t.timestamp_ms = timestamp_ms;
    t.battery_pct = battery_;
    t.temperature_c = clamp(temp_ + 0.5 * noise(rng_), limits::kTempMin, limits::kTempMax);
    t.cpu_pct = clamp(cpu, limits::kCpuMin, limits::kCpuMax);
    t.signal_dbm = clamp(sig, limits::kSignalMin, limits::kSignalMax);
    return t;
}

}  // namespace orbitguard
