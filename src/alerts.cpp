#include "orbitguard/alerts.hpp"

#include <cmath>

namespace orbitguard {

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Ok: return "ok";
        case Severity::Warning: return "warning";
        case Severity::Critical: return "critical";
    }
    return "ok";
}

const char* to_string(Metric m) {
    switch (m) {
        case Metric::Battery: return "battery";
        case Metric::Temperature: return "temperature";
        case Metric::Cpu: return "cpu";
        case Metric::Signal: return "signal";
    }
    return "battery";
}

AlertConfig AlertConfig::defaults() {
    AlertConfig c;
    c.battery.has_low = true;
    c.battery.warn_low = 40; c.battery.crit_low = 20; c.battery.hysteresis = 3;

    c.temperature.has_low = c.temperature.has_high = true;
    c.temperature.warn_low = -25; c.temperature.crit_low = -40;
    c.temperature.warn_high = 60; c.temperature.crit_high = 80;
    c.temperature.hysteresis = 3;

    c.cpu.has_high = true;
    c.cpu.warn_high = 85; c.cpu.crit_high = 95; c.cpu.hysteresis = 3;

    c.signal.has_low = true;
    c.signal.warn_low = -105; c.signal.crit_low = -115; c.signal.hysteresis = 2;
    return c;
}

namespace {
bool limits_valid(const Limits& l) {
    if (!std::isfinite(l.hysteresis) || l.hysteresis < 0) return false;
    if (l.has_low && !(std::isfinite(l.warn_low) && std::isfinite(l.crit_low) && l.crit_low <= l.warn_low)) return false;
    if (l.has_high && !(std::isfinite(l.warn_high) && std::isfinite(l.crit_high) && l.crit_high >= l.warn_high)) return false;
    if (l.has_low && l.has_high && !(l.warn_low < l.warn_high)) return false;
    return true;
}
}  // namespace

bool AlertConfig::valid() const {
    return limits_valid(battery) && limits_valid(temperature) && limits_valid(cpu) && limits_valid(signal);
}

void AlertEvaluator::evaluate(Metric m, const Limits& lim, double v, std::uint64_t ts, Track& tr) {
    // Severity the raw value calls for right now, and on which side.
    Severity raw = Severity::Ok;
    bool low = false;
    if (lim.has_low) {
        if (v < lim.crit_low) { raw = Severity::Critical; low = true; }
        else if (v < lim.warn_low) { raw = Severity::Warning; low = true; }
    }
    if (lim.has_high && raw != Severity::Critical) {
        if (v > lim.crit_high) { raw = Severity::Critical; low = false; }
        else if (v > lim.warn_high && raw == Severity::Ok) { raw = Severity::Warning; low = false; }
    }

    // A value must clear the limit by the hysteresis margin before the severity drops.
    Severity held = Severity::Ok;
    if (tr.sev != Severity::Ok) {
        const double h = lim.hysteresis;
        const bool crit_holds = tr.sev == Severity::Critical &&
            (tr.low_side ? v < lim.crit_low + h : v > lim.crit_high - h);
        const bool warn_holds = tr.low_side ? v < lim.warn_low + h : v > lim.warn_high - h;
        if (crit_holds) held = Severity::Critical;
        else if (warn_holds) held = Severity::Warning;
    }

    Severity next = raw;
    bool next_low = low;
    if (held > raw) { next = held; next_low = tr.low_side; }  // hysteresis keeps the old, higher state

    if (next > tr.sev || (next != Severity::Ok && tr.sev == Severity::Ok)) {
        ++raised_;
        tr.since = ts;
    }
    tr.sev = next;
    tr.low_side = next_low;
    if (next != Severity::Ok) active_.push_back({m, next, v, tr.since, next_low});
}

const std::vector<Alert>& AlertEvaluator::update(const Telemetry& t) {
    active_.clear();
    evaluate(Metric::Battery, cfg_.battery, t.battery_pct, t.timestamp_ms, tracks_[0]);
    evaluate(Metric::Temperature, cfg_.temperature, t.temperature_c, t.timestamp_ms, tracks_[1]);
    evaluate(Metric::Cpu, cfg_.cpu, t.cpu_pct, t.timestamp_ms, tracks_[2]);
    evaluate(Metric::Signal, cfg_.signal, t.signal_dbm, t.timestamp_ms, tracks_[3]);
    return active_;
}

}  // namespace orbitguard
