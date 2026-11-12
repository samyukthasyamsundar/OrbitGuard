#include "orbitguard/telemetry_store.hpp"

#include <algorithm>
#include <cmath>

namespace orbitguard {

TelemetryStore::TelemetryStore(std::size_t capacity, const AlertConfig& alerts)
    : capacity_(std::max<std::size_t>(1, capacity)), alerts_(alerts) {}

void TelemetryStore::enable_orbit(const OrbitParams& orbit, double sim_seconds_per_packet) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!orbit.valid() || !std::isfinite(sim_seconds_per_packet) || sim_seconds_per_packet <= 0) {
        orbit_enabled_ = false;
        return;
    }
    orbit_ = orbit;
    sim_s_per_packet_ = sim_seconds_per_packet;
    orbit_enabled_ = true;
}

SequenceStatus TelemetryStore::ingest(const Telemetry& t, std::uint64_t rx_time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    const SequenceStatus st = tracker_.observe(t.sequence, t.timestamp_ms);
    ++valid_;
    has_last_rx_ = true;
    last_rx_ms_ = rx_time_ms;
    if (st != SequenceStatus::Duplicate && st != SequenceStatus::OutOfOrder) {
        samples_.push_back(t);
        alerts_.update(t);
        // The orbit time follows the sequence number, so a sender restart (sequence back to 0) puts the
        // satellite back at the start of its orbit, just as the simulator itself does.
        if (orbit_enabled_) orbit_time_s_ = static_cast<double>(t.sequence) * sim_s_per_packet_;
        while (samples_.size() > capacity_) samples_.pop_front();
    }
    return st;
}

void TelemetryStore::reject() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++rejected_;
}

void TelemetryStore::auth_failure() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++auth_failures_;
}

void TelemetryStore::replay() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++replays_;
}

Snapshot TelemetryStore::snapshot(std::size_t max_samples) const {
    std::lock_guard<std::mutex> lock(mutex_);
    Snapshot s;
    s.stats.valid = valid_;
    s.stats.rejected = rejected_;
    s.stats.lost = tracker_.lost();
    s.stats.duplicates = tracker_.duplicates();
    s.stats.out_of_order = tracker_.out_of_order();
    s.stats.restarts = tracker_.restarts();
    s.stats.alerts_raised = alerts_.raised_count();
    s.stats.auth_failures = auth_failures_;
    s.stats.replays = replays_;
    s.alerts = alerts_.active();
    if (orbit_enabled_ && !samples_.empty()) {
        s.has_position = true;
        s.orbit = orbit_;
        s.orbit_time_s = orbit_time_s_;
        s.position = position_at(orbit_, orbit_time_s_);
    }
    s.stats.has_last_rx = has_last_rx_;
    s.stats.last_rx_ms = last_rx_ms_;
    const std::size_t n = std::min(max_samples, samples_.size());
    s.samples.assign(samples_.end() - static_cast<std::ptrdiff_t>(n), samples_.end());
    return s;
}

}  // namespace orbitguard
