#pragma once
// Simulated link impairments for the satellite side: drop, corrupt, duplicate
// and reorder datagrams. It sits between the encoder and the socket and is a
// pure function of (packet, RNG state), so it is testable without a network.
//
// Evaluation order for each packet: drop -> corrupt -> reorder-hold -> duplicate.
// A packet that is held back is released right after the NEXT packet that gets
// through, which is how a late (out-of-order) arrival looks to the receiver.
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

namespace orbitguard {

struct FaultConfig {
    double drop = 0.0;       // probability the datagram never leaves
    double corrupt = 0.0;    // probability of a single bit flip or a truncation
    double duplicate = 0.0;  // probability the datagram is sent twice
    double reorder = 0.0;    // probability the datagram is delayed behind the next one
    std::uint32_t seed = 1;

    // All probabilities must lie in [0, 1] (NaN is rejected).
    bool valid() const;
    bool any() const { return drop > 0 || corrupt > 0 || duplicate > 0 || reorder > 0; }
};

struct FaultStats {
    std::uint64_t dropped = 0, corrupted = 0, duplicated = 0, reordered = 0;
};

class FaultInjector {
public:
    using Datagram = std::vector<std::uint8_t>;

    explicit FaultInjector(FaultConfig cfg = {}) : cfg_(cfg), rng_(cfg.seed) {}

    // Datagrams to put on the wire for this packet, in send order (may be empty).
    std::vector<Datagram> process(Datagram packet);

    // Release a packet still being held back (call once when the stream ends).
    std::vector<Datagram> flush();

    const FaultStats& stats() const { return stats_; }

private:
    bool roll(double p);
    void corrupt_in_place(Datagram& d);

    FaultConfig cfg_;
    std::mt19937 rng_;
    FaultStats stats_;
    std::optional<Datagram> held_;
};

}  // namespace orbitguard
