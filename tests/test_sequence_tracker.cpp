#include <gtest/gtest.h>

#include "orbitguard/sequence_tracker.hpp"

using namespace orbitguard;

TEST(SequenceTracker, FirstThenInOrder) {
    SequenceTracker t;
    EXPECT_EQ(t.observe(10, 1000), SequenceStatus::First);
    EXPECT_EQ(t.observe(11, 1001), SequenceStatus::InOrder);
    EXPECT_EQ(t.received(), 2u);
    EXPECT_EQ(t.lost(), 0u);
}

TEST(SequenceTracker, CountsGap) {
    SequenceTracker t;
    t.observe(0, 1000);
    EXPECT_EQ(t.observe(4, 1004), SequenceStatus::Gap);
    EXPECT_EQ(t.lost(), 3u);
}

TEST(SequenceTracker, Duplicate) {
    SequenceTracker t;
    t.observe(5, 1000);
    EXPECT_EQ(t.observe(5, 1000), SequenceStatus::Duplicate);
    EXPECT_EQ(t.duplicates(), 1u);
    EXPECT_EQ(t.received(), 1u);
}

TEST(SequenceTracker, OutOfOrderDoesNotRewind) {
    SequenceTracker t;
    t.observe(5, 1000);
    t.observe(8, 1003);
    EXPECT_EQ(t.observe(6, 1001), SequenceStatus::OutOfOrder);  // older timestamp: a late packet
    EXPECT_EQ(t.out_of_order(), 1u);
    EXPECT_EQ(t.observe(9, 1004), SequenceStatus::InOrder);
}

TEST(SequenceTracker, HandlesWraparound) {
    SequenceTracker t;
    t.observe(0xFFFFFFFEu, 1000);
    EXPECT_EQ(t.observe(0xFFFFFFFFu, 1001), SequenceStatus::InOrder);
    EXPECT_EQ(t.observe(0u, 1002), SequenceStatus::InOrder);
    EXPECT_EQ(t.observe(2u, 1003), SequenceStatus::Gap);
    EXPECT_EQ(t.lost(), 1u);
}

TEST(SequenceTracker, SenderRestartIsDetectedByNewerTimestamp) {
    SequenceTracker t;
    t.observe(500, 1000);
    t.observe(501, 1001);
    // The sender restarted: sequence is back at 0 but the clock moved forward.
    EXPECT_EQ(t.observe(0, 9000), SequenceStatus::Restart);
    EXPECT_EQ(t.restarts(), 1u);
    EXPECT_EQ(t.lost(), 0u);          // a restart is not packet loss
    EXPECT_EQ(t.out_of_order(), 0u);
    EXPECT_EQ(t.observe(1, 9001), SequenceStatus::InOrder);  // re-baselined
}

TEST(SequenceTracker, RestartToSameSequenceWithNewerTimestamp) {
    SequenceTracker t;
    t.observe(0, 1000);
    EXPECT_EQ(t.observe(0, 5000), SequenceStatus::Restart);  // equal sequence, later in time
}

TEST(SequenceTracker, LateBurstAfterRestartIsStillOutOfOrder) {
    SequenceTracker t;
    t.observe(100, 1000);
    t.observe(0, 9000);  // restart
    // A straggler from before the restart arrives late: older timestamp.
    EXPECT_EQ(t.observe(99, 1500), SequenceStatus::OutOfOrder);
}

TEST(SequenceTracker, StragglerAfterRestartDoesNotInventLossOrMoveBaseline) {
    SequenceTracker t;
    t.observe(100, 1000);
    t.observe(0, 9000);  // restart
    EXPECT_EQ(t.observe(99, 1500), SequenceStatus::OutOfOrder);
    EXPECT_EQ(t.lost(), 0u);
    EXPECT_EQ(t.observe(1, 9001), SequenceStatus::InOrder);  // baseline still the new session
}

TEST(SequenceTracker, EqualTimestampsAtHighRateAreNotRejected) {
    SequenceTracker t;
    t.observe(0, 1000);
    EXPECT_EQ(t.observe(1, 1000), SequenceStatus::InOrder);  // same millisecond
    EXPECT_EQ(t.observe(2, 1000), SequenceStatus::InOrder);
}
