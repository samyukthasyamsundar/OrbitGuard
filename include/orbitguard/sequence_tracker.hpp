#pragma once
// Ground-side link-quality accounting based on the packet sequence number.
// UDP can lose, duplicate and reorder datagrams, and the sender can restart;
// the tracker classifies each arrival.
#include <cstdint>

namespace orbitguard {

enum class SequenceStatus { First, InOrder, Gap, Duplicate, OutOfOrder, Restart };

class SequenceTracker {
public:
    // Classifies `seq` against the last accepted packet. Sequence arithmetic is
    // modular (wrap-safe: the u32 counter wraps after 2^32).
    //
    // The sender timestamp separates two cases that look identical by sequence
    // number alone, a sequence number that moved backwards:
    //   * older timestamp  -> a late (reordered) packet            -> OutOfOrder
    //   * newer timestamp  -> the sender restarted its counter     -> Restart
    // A restart re-baselines the tracker without counting any loss. Likewise a packet
    // that is ahead by sequence but older by timestamp is a pre-restart straggler
    // (OutOfOrder), never a forward gap.
    //
    // Assumes the sender timestamp does not step backwards within a session. If it
    // does (e.g. wall-clock adjustment), packets are classified OutOfOrder until it
    // catches up; flight software would use a monotonic mission clock instead.
    SequenceStatus observe(std::uint32_t seq, std::uint64_t timestamp_ms);

    std::uint64_t received() const { return received_; }
    std::uint64_t lost() const { return lost_; }          // missing packets inferred from gaps
    std::uint64_t duplicates() const { return duplicates_; }
    std::uint64_t out_of_order() const { return out_of_order_; }
    std::uint64_t restarts() const { return restarts_; }

private:
    bool have_last_ = false;
    std::uint32_t last_ = 0;
    std::uint64_t last_ts_ = 0;
    std::uint64_t received_ = 0, lost_ = 0, duplicates_ = 0, out_of_order_ = 0, restarts_ = 0;
};

}  // namespace orbitguard
