#include "orbitguard/telemetry_store.hpp"

#include <algorithm>

namespace orbitguard {

TelemetryStore::TelemetryStore(std::size_t capacity) : capacity_(std::max<std::size_t>(1, capacity)) {}

SequenceStatus TelemetryStore::ingest(const Telemetry& t, std::uint64_t rx_time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    const SequenceStatus st = tracker_.observe(t.sequence, t.timestamp_ms);
    ++valid_;
    has_last_rx_ = true;
    last_rx_ms_ = rx_time_ms;
    if (st != SequenceStatus::Duplicate && st != SequenceStatus::OutOfOrder) {
        samples_.push_back(t);
        while (samples_.size() > capacity_) samples_.pop_front();
    }
    return st;
}

void TelemetryStore::reject() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++rejected_;
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
    s.stats.has_last_rx = has_last_rx_;
    s.stats.last_rx_ms = last_rx_ms_;
    const std::size_t n = std::min(max_samples, samples_.size());
    s.samples.assign(samples_.end() - static_cast<std::ptrdiff_t>(n), samples_.end());
    return s;
}

}  // namespace orbitguard
