#include <gtest/gtest.h>

#include "orbitguard/sequence_tracker.hpp"

using namespace orbitguard;

TEST(SequenceTracker, FirstThenInOrder) {
    SequenceTracker t;
    EXPECT_EQ(t.observe(10), SequenceStatus::First);
    EXPECT_EQ(t.observe(11), SequenceStatus::InOrder);
    EXPECT_EQ(t.received(), 2u);
    EXPECT_EQ(t.lost(), 0u);
}

TEST(SequenceTracker, CountsGap) {
    SequenceTracker t;
    t.observe(0);
    EXPECT_EQ(t.observe(4), SequenceStatus::Gap);
    EXPECT_EQ(t.lost(), 3u);
}

TEST(SequenceTracker, Duplicate) {
    SequenceTracker t;
    t.observe(5);
    EXPECT_EQ(t.observe(5), SequenceStatus::Duplicate);
    EXPECT_EQ(t.duplicates(), 1u);
    EXPECT_EQ(t.received(), 1u);
}

TEST(SequenceTracker, OutOfOrderDoesNotRewind) {
    SequenceTracker t;
    t.observe(5);
    t.observe(8);
    EXPECT_EQ(t.observe(6), SequenceStatus::OutOfOrder);
    EXPECT_EQ(t.out_of_order(), 1u);
    EXPECT_EQ(t.observe(9), SequenceStatus::InOrder);
}

TEST(SequenceTracker, HandlesWraparound) {
    SequenceTracker t;
    t.observe(0xFFFFFFFEu);
    EXPECT_EQ(t.observe(0xFFFFFFFFu), SequenceStatus::InOrder);
    EXPECT_EQ(t.observe(0u), SequenceStatus::InOrder);
    EXPECT_EQ(t.observe(2u), SequenceStatus::Gap);
    EXPECT_EQ(t.lost(), 1u);
}
