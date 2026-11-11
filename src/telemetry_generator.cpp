#include "orbitguard/telemetry_generator.hpp"

#include <algorithm>
#include <cmath>

namespace orbitguard {

namespace {
constexpr double kPi = 3.14159265358979323846;
double clamp(double v, double lo, double hi) { return std::min(hi, std::max(lo, v)); }
}  // namespace

bool parse_scenario(const std::string& name, Scenario& out) {
    if (name == "nominal") out = Scenario::Nominal;
    else if (name == "battery-drain") out = Scenario::BatteryDrain;
    else if (name == "overheat") out = Scenario::Overheat;
    else if (name == "cpu-spike") out = Scenario::CpuSpike;
    else if (name == "signal-loss") out = Scenario::SignalLoss;
    else return false;
    return true;
}

TelemetryGenerator::TelemetryGenerator(std::uint32_t seed, double orbit_period_s, Scenario scenario)
    : rng_(seed), period_s_(orbit_period_s), scenario_(scenario) {}

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

    double batt_out = battery_, temp_out = temp_ + 0.5 * noise(rng_), cpu_out = cpu, sig_out = sig;
    if (scenario_ != Scenario::Nominal) {
        anomaly_s_ += dt_s;
        const double k = anomaly_s_ / 60.0;  // minutes of simulated time since the anomaly began
        switch (scenario_) {
            case Scenario::BatteryDrain: batt_out = battery_ - 0.5 * k; break;
            case Scenario::Overheat: temp_out += 1.2 * k; break;
            case Scenario::CpuSpike: cpu_out = 97.0 + 1.5 * noise(rng_); break;
            case Scenario::SignalLoss: sig_out = sig - 2.0 * k; break;
            case Scenario::Nominal: break;
        }
    }

    Telemetry t;
    t.sequence = seq_++;
    t.timestamp_ms = timestamp_ms;
    t.battery_pct = clamp(batt_out, limits::kBatteryMin, limits::kBatteryMax);
    t.temperature_c = clamp(temp_out, limits::kTempMin, limits::kTempMax);
    t.cpu_pct = clamp(cpu_out, limits::kCpuMin, limits::kCpuMax);
    t.signal_dbm = clamp(sig_out, limits::kSignalMin, limits::kSignalMax);
    return t;
}

}  // namespace orbitguard
