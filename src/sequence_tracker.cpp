#include "orbitguard/sequence_tracker.hpp"

namespace orbitguard {

SequenceStatus SequenceTracker::observe(std::uint32_t seq) {
    if (!have_last_) {
        have_last_ = true;
        last_ = seq;
        ++received_;
        return SequenceStatus::First;
    }
    // Signed modular difference: positive = ahead of last, negative = behind.
    const std::int32_t diff = static_cast<std::int32_t>(seq - last_);
    if (diff == 0) {
        ++duplicates_;
        return SequenceStatus::Duplicate;
    }
    if (diff < 0) {
        ++out_of_order_;
        return SequenceStatus::OutOfOrder;  // 'last_' is not rewound
    }
    ++received_;
    last_ = seq;
    if (diff == 1) return SequenceStatus::InOrder;
    lost_ += static_cast<std::uint64_t>(diff - 1);
    return SequenceStatus::Gap;
}

}  // namespace orbitguard
