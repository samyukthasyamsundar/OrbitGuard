#pragma once
// Threshold alerts with hysteresis.
//
// Each metric has a warning and a critical limit. An alert is raised when a value
// crosses a limit and cleared only after it recovers past that limit by a margin
// (hysteresis), so a value hovering at a threshold does not flap on and off.
// Severity only escalates immediately and de-escalates one level at a time.
#include <cstdint>
#include <string>
#include <vector>

#include "orbitguard/telemetry.hpp"

namespace orbitguard {

enum class Severity { Ok = 0, Warning = 1, Critical = 2 };
const char* to_string(Severity s);

enum class Metric { Battery, Temperature, Cpu, Signal };
const char* to_string(Metric m);

struct Limits {
    // "Low" limits trigger when value < limit, "high" limits when value > limit.
    // For a metric watched on one side only, leave the other side as NaN-free sentinel
    // via has_low / has_high.
    bool has_low = false, has_high = false;
    double warn_low = 0, crit_low = 0;     // crit_low <= warn_low
    double warn_high = 0, crit_high = 0;   // crit_high >= warn_high
    double hysteresis = 0;                 // recovery margin, in the metric's units
};

struct AlertConfig {
    Limits battery, temperature, cpu, signal;
    static AlertConfig defaults();
    bool valid() const;
};

struct Alert {
    Metric metric;
    Severity severity;
    double value;
    std::uint64_t since_ms;  // timestamp of the sample that raised the current severity
    bool low_side;           // true: below the low limit, false: above the high limit
};

class AlertEvaluator {
public:
    explicit AlertEvaluator(AlertConfig cfg = AlertConfig::defaults()) : cfg_(cfg) {}

    // Feed one sample; returns the alerts that are active afterwards.
    const std::vector<Alert>& update(const Telemetry& t);
    const std::vector<Alert>& active() const { return active_; }
    // Total number of times any alert was raised or escalated since start.
    std::uint64_t raised_count() const { return raised_; }

private:
    struct Track { Severity sev = Severity::Ok; bool low_side = false; std::uint64_t since = 0; };
    void evaluate(Metric m, const Limits& lim, double value, std::uint64_t ts, Track& tr);

    AlertConfig cfg_;
    Track tracks_[4];
    std::vector<Alert> active_;
    std::uint64_t raised_ = 0;
};

}  // namespace orbitguard
