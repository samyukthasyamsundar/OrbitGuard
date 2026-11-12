#include <gtest/gtest.h>

#include <limits>

#include "orbitguard/rate_limiter.hpp"

using namespace orbitguard;

TEST(RateLimiter, AllowsABurstThenRefuses) {
    RateLimiter r(10, 5);
    for (int i = 0; i < 5; ++i) EXPECT_TRUE(r.allow(1000)) << i;
    EXPECT_FALSE(r.allow(1000));
    EXPECT_EQ(r.refused(), 1u);
}

TEST(RateLimiter, RefillsAtTheConfiguredRate) {
    RateLimiter r(10, 5);                 // 10 tokens/s
    for (int i = 0; i < 5; ++i) r.allow(0);
    EXPECT_FALSE(r.allow(0));
    EXPECT_FALSE(r.allow(50));            // 0.5 token so far
    EXPECT_TRUE(r.allow(100));            // a full token after 100 ms
    EXPECT_FALSE(r.allow(100));
}

TEST(RateLimiter, NeverExceedsTheBurstCap) {
    RateLimiter r(1000, 3);
    r.allow(0);
    int ok = 0;
    for (int i = 0; i < 20; ++i) ok += r.allow(1000000);   // a long idle period refills, but only to 3
    EXPECT_EQ(ok, 3);
}

TEST(RateLimiter, ASteadyRateBelowTheLimitIsNeverRefused) {
    RateLimiter r(100, 10);
    for (std::uint64_t t = 0; t < 10000; t += 20) ASSERT_TRUE(r.allow(t)) << t;   // 50/s < 100/s
    EXPECT_EQ(r.refused(), 0u);
}

TEST(RateLimiter, ASustainedFloodIsHeldToTheRate) {
    RateLimiter r(100, 10);
    long allowed = 0;
    for (std::uint64_t t = 0; t < 10000; ++t) allowed += r.allow(t) ? 1 : 0;      // 1000 attempts/s for 10 s
    EXPECT_GE(allowed, 100 * 10);                  // about rate * time ...
    EXPECT_LE(allowed, 100 * 10 + 10 + 1);         // ... plus the initial burst, and no more
}

TEST(RateLimiter, WouldAllowDoesNotConsume) {
    RateLimiter r(1, 1);
    EXPECT_TRUE(r.would_allow(0));
    EXPECT_TRUE(r.would_allow(0));
    EXPECT_TRUE(r.allow(0));
    EXPECT_FALSE(r.would_allow(0));
}

TEST(RateLimiter, ClockGoingBackwardsNeverAddsTokens) {
    RateLimiter r(10, 2);
    r.allow(5000); r.allow(5000);
    EXPECT_FALSE(r.allow(5000));
    EXPECT_FALSE(r.allow(1000));          // time went backwards: no refill
    EXPECT_FALSE(r.allow(5000));
}

TEST(RateLimiter, MisconfiguredLimiterFailsOpen) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    for (RateLimiter r : {RateLimiter(0, 5), RateLimiter(-1, 5), RateLimiter(10, 0), RateLimiter(nan, 5), RateLimiter(10, nan)}) {
        for (int i = 0; i < 1000; ++i) ASSERT_TRUE(r.allow(0));
        EXPECT_EQ(r.refused(), 0u);
    }
}

TEST(RateLimiter, RefundReturnsATokenButNeverAboveTheBurst) {
    RateLimiter r(1, 2);
    EXPECT_TRUE(r.allow(0));
    EXPECT_TRUE(r.allow(0));
    EXPECT_FALSE(r.allow(0));
    r.refund();
    EXPECT_TRUE(r.allow(0));
    r.refund(); r.refund(); r.refund(); r.refund();
    int ok = 0;
    for (int i = 0; i < 10; ++i) ok += r.allow(0);
    EXPECT_EQ(ok, 2);                     // capped at the burst, not 4
}
