#pragma once
// Thread-safe store shared by the UDP receive loop (writer) and the HTTP
// server threads (readers). It owns the sequence tracker so counters and the
// sample history can never disagree.
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "orbitguard/alerts.hpp"
#include "orbitguard/orbit.hpp"
#include "orbitguard/sequence_tracker.hpp"
#include "orbitguard/telemetry.hpp"

namespace orbitguard {

constexpr std::size_t kDefaultStoreCapacity = 600;

struct LinkStats {
    std::uint64_t valid = 0;       // packets that passed validation (incl. duplicates)
    std::uint64_t rejected = 0;    // packets that failed validation
    std::uint64_t lost = 0;
    std::uint64_t duplicates = 0;
    std::uint64_t out_of_order = 0;
    std::uint64_t restarts = 0;
    std::uint64_t alerts_raised = 0;  // times any alert was raised or escalated
    std::uint64_t auth_failures = 0;  // forged, tampered, wrong-key, unknown-key or downgraded packets
    std::uint64_t replays = 0;        // authentic packets rejected as replays or too old
    bool has_last_rx = false;
    std::uint64_t last_rx_ms = 0;  // wall-clock time the last valid packet arrived
};

struct Snapshot {
    LinkStats stats;
    std::vector<Telemetry> samples;  // oldest first
    std::vector<Alert> alerts;       // active alerts as of the newest charted sample
    // Where the satellite is, for the map. Only present once a sample has been charted AND the
    // store was given an orbit model; has_position is false otherwise.
    bool has_position = false;
    GeoPosition position;
    OrbitParams orbit;               // the model the position came from (for drawing the ground track)
    double orbit_time_s = 0;         // the orbit time that position corresponds to
};

class TelemetryStore {
public:
    explicit TelemetryStore(std::size_t capacity = kDefaultStoreCapacity,
                            const AlertConfig& alerts = AlertConfig::defaults());

    // Record a validated packet. Duplicates and late (out-of-order) packets are
    // counted but not added to the history, which stays monotonic for charting.
    // Alerts are evaluated only on samples that enter the history, so a stale
    // or repeated packet can neither raise nor clear an alert.
    SequenceStatus ingest(const Telemetry& t, std::uint64_t rx_time_ms);

    // Enable the map. `sim_seconds_per_packet` is how much simulated orbit time one packet represents
    // (the simulator's time-scale divided by its rate); the orbit time of a packet is then its
    // sequence number times that. Must be finite and > 0; invalid input leaves the map disabled.
    void enable_orbit(const OrbitParams& orbit, double sim_seconds_per_packet);

    // Record a packet that failed validation.
    void reject();
    // Security events (secure mode): a packet that failed authentication, and an authentic one
    // rejected as a replay. Neither enters the sample history.
    void auth_failure();
    void replay();

    // Copy of the counters plus the newest `max_samples` samples (0 = stats only).
    Snapshot snapshot(std::size_t max_samples) const;

private:
    mutable std::mutex mutex_;
    std::size_t capacity_;
    std::deque<Telemetry> samples_;
    SequenceTracker tracker_;
    AlertEvaluator alerts_;
    bool orbit_enabled_ = false;
    OrbitParams orbit_;
    double sim_s_per_packet_ = 0;
    double orbit_time_s_ = 0;
    std::uint64_t valid_ = 0, rejected_ = 0, last_rx_ms_ = 0, auth_failures_ = 0, replays_ = 0;
    bool has_last_rx_ = false;
};

}  // namespace orbitguard
