#pragma once
// Ground-side link-quality accounting based on the packet sequence number.
// UDP can lose, duplicate and reorder datagrams; the tracker classifies each.
#include <cstdint>

namespace orbitguard {

enum class SequenceStatus { First, InOrder, Gap, Duplicate, OutOfOrder };

class SequenceTracker {
public:
    // Returns how this sequence number relates to the last accepted one.
    // Uses modular (wrap-safe) arithmetic: u32 sequence wraps after 2^32.
    SequenceStatus observe(std::uint32_t seq);

    std::uint64_t received() const { return received_; }
    std::uint64_t lost() const { return lost_; }          // missing packets inferred from gaps
    std::uint64_t duplicates() const { return duplicates_; }
    std::uint64_t out_of_order() const { return out_of_order_; }

private:
    bool have_last_ = false;
    std::uint32_t last_ = 0;
    std::uint64_t received_ = 0, lost_ = 0, duplicates_ = 0, out_of_order_ = 0;
};

}  // namespace orbitguard
