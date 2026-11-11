#include <gtest/gtest.h>

#include <cmath>
#include <limits>

#include "orbitguard/fault_injector.hpp"
#include "orbitguard/packet_codec.hpp"

using namespace orbitguard;

namespace {
FaultInjector::Datagram packet(std::uint32_t seq) {
    Telemetry t;
    t.sequence = seq;
    t.timestamp_ms = 1000 + seq;
    t.battery_pct = 50; t.temperature_c = 10; t.cpu_pct = 20; t.signal_dbm = -90;
    return serialize(t).value();
}
std::uint32_t seq_of(const FaultInjector::Datagram& d) { return deserialize(d).value().sequence; }
}  // namespace

TEST(FaultConfig, ValidatesProbabilities) {
    FaultConfig c;
    EXPECT_TRUE(c.valid());
    EXPECT_FALSE(c.any());
    c.drop = 1.0001;
    EXPECT_FALSE(c.valid());
    c = {};
    c.corrupt = -0.1;
    EXPECT_FALSE(c.valid());
    c = {};
    c.reorder = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(c.valid());
    c = {};
    c.duplicate = 0.2;
    EXPECT_TRUE(c.valid());
    EXPECT_TRUE(c.any());
}

TEST(FaultInjector, ZeroProbabilitiesPassEverythingUntouched) {
    FaultInjector f;
    for (std::uint32_t i = 0; i < 100; ++i) {
        auto out = f.process(packet(i));
        ASSERT_EQ(out.size(), 1u);
        EXPECT_EQ(out[0], packet(i));
    }
    EXPECT_EQ(f.stats().dropped + f.stats().corrupted + f.stats().duplicated + f.stats().reordered, 0u);
    EXPECT_TRUE(f.flush().empty());
}

TEST(FaultInjector, DropAllDropsAll) {
    FaultConfig c;
    c.drop = 1.0;
    FaultInjector f(c);
    for (std::uint32_t i = 0; i < 10; ++i) EXPECT_TRUE(f.process(packet(i)).empty());
    EXPECT_EQ(f.stats().dropped, 10u);
}

TEST(FaultInjector, DuplicateAllSendsTwoIdenticalCopies) {
    FaultConfig c;
    c.duplicate = 1.0;
    FaultInjector f(c);
    auto out = f.process(packet(5));
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], out[1]);
    EXPECT_EQ(f.stats().duplicated, 1u);
}

TEST(FaultInjector, CorruptedPacketsAreAlwaysRejectedByTheCodec) {
    FaultConfig c;
    c.corrupt = 1.0;
    c.seed = 123;
    FaultInjector f(c);
    for (std::uint32_t i = 0; i < 2000; ++i) {
        auto out = f.process(packet(i));
        ASSERT_EQ(out.size(), 1u);
        ASSERT_NE(out[0], packet(i)) << "packet " << i << " was not altered";
        ASSERT_FALSE(deserialize(out[0]).ok()) << "corrupted packet " << i << " was accepted";
    }
    EXPECT_EQ(f.stats().corrupted, 2000u);
}

TEST(FaultInjector, ReorderHoldsOnePacketBehindTheNext) {
    FaultConfig c;
    c.reorder = 1.0;
    FaultInjector f(c);
    EXPECT_TRUE(f.process(packet(0)).empty());  // held
    auto out = f.process(packet(1));            // already holding, so this one passes through
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(seq_of(out[0]), 1u);              // the newer packet first...
    EXPECT_EQ(seq_of(out[1]), 0u);              // ...then the delayed one
    EXPECT_EQ(f.stats().reordered, 1u);
}

TEST(FaultInjector, FlushReleasesAHeldPacketExactlyOnce) {
    FaultConfig c;
    c.reorder = 1.0;
    FaultInjector f(c);
    EXPECT_TRUE(f.process(packet(9)).empty());
    auto out = f.flush();
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(seq_of(out[0]), 9u);
    EXPECT_TRUE(f.flush().empty());
}

TEST(FaultInjector, ADroppedPacketDoesNotReleaseTheHeldOne) {
    // Find a seed where packet 0 is held and packet 1 is dropped, using the
    // real injector, then check the held packet is only released by flush().
    for (std::uint32_t seed = 1; seed < 500; ++seed) {
        FaultConfig c;
        c.reorder = 0.5; c.drop = 0.5; c.seed = seed;
        FaultInjector f(c);
        if (!f.process(packet(0)).empty()) continue;
        if (f.stats().reordered != 1) continue;           // packet 0 must have been held
        if (!f.process(packet(1)).empty()) continue;
        if (f.stats().dropped != 1) continue;             // packet 1 must have been dropped
        auto rest = f.flush();
        ASSERT_EQ(rest.size(), 1u);
        EXPECT_EQ(seq_of(rest[0]), 0u);
        return;
    }
    FAIL() << "no seed produced the hold-then-drop sequence";
}

TEST(FaultInjector, NoPacketIsInventedOrLostBeyondTheConfiguredFaults) {
    FaultConfig c;
    c.reorder = 0.3;
    c.seed = 5;
    FaultInjector f(c);
    std::size_t sent = 0;
    for (std::uint32_t i = 0; i < 1000; ++i) sent += f.process(packet(i)).size();
    sent += f.flush().size();
    EXPECT_EQ(sent, 1000u);  // reordering delays packets, it never loses or adds any
}

TEST(FaultInjector, SameSeedIsReproducible) {
    FaultConfig c;
    c.drop = 0.2; c.corrupt = 0.2; c.duplicate = 0.2; c.reorder = 0.2;
    c.seed = 77;
    FaultInjector a(c), b(c);
    for (std::uint32_t i = 0; i < 300; ++i) EXPECT_EQ(a.process(packet(i)), b.process(packet(i)));
    EXPECT_EQ(a.stats().dropped, b.stats().dropped);
}

TEST(FaultInjector, RatesRoughlyMatchProbability) {
    FaultConfig c;
    c.drop = 0.25;
    c.seed = 2024;
    FaultInjector f(c);
    for (std::uint32_t i = 0; i < 20000; ++i) f.process(packet(i));
    const double rate = static_cast<double>(f.stats().dropped) / 20000.0;
    EXPECT_NEAR(rate, 0.25, 0.03);  // loose bound: the RNG stream differs between standard libraries
}
