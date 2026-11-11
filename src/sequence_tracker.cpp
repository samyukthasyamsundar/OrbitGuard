#include "orbitguard/sequence_tracker.hpp"

namespace orbitguard {

SequenceStatus SequenceTracker::observe(std::uint32_t seq, std::uint64_t timestamp_ms) {
    if (!have_last_) {
        have_last_ = true;
        last_ = seq;
        last_ts_ = timestamp_ms;
        ++received_;
        return SequenceStatus::First;
    }
    // Signed modular difference: positive = ahead of last, negative = behind.
    const std::int32_t diff = static_cast<std::int32_t>(seq - last_);

    if (diff <= 0) {
        if (timestamp_ms > last_ts_) {  // behind (or equal) by sequence, but newer in time
            last_ = seq;
            last_ts_ = timestamp_ms;
            ++received_;
            ++restarts_;
            return SequenceStatus::Restart;
        }
        if (diff == 0) {
            ++duplicates_;
            return SequenceStatus::Duplicate;
        }
        ++out_of_order_;
        return SequenceStatus::OutOfOrder;  // baseline is not rewound
    }

    // Ahead by sequence but older in time: a straggler from before a restart, not a
    // real advance. Accepting it would move the baseline and invent a huge loss count.
    if (timestamp_ms < last_ts_) {
        ++out_of_order_;
        return SequenceStatus::OutOfOrder;
    }

    ++received_;
    last_ = seq;
    last_ts_ = timestamp_ms;
    if (diff == 1) return SequenceStatus::InOrder;
    lost_ += static_cast<std::uint64_t>(diff - 1);
    return SequenceStatus::Gap;
}

}  // namespace orbitguard
