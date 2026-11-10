#include <gtest/gtest.h>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/telemetry_generator.hpp"

using namespace orbitguard;

TEST(TelemetryGenerator, SequenceIncrementsFromZero) {
    TelemetryGenerator g(1);
    for (std::uint32_t i = 0; i < 10; ++i) EXPECT_EQ(g.next(1.0, 0).sequence, i);
}

TEST(TelemetryGenerator, SameSeedIsReproducible) {
    TelemetryGenerator a(7), b(7);
    for (int i = 0; i < 50; ++i) {
        Telemetry x = a.next(30.0, 1000), y = b.next(30.0, 1000);
        EXPECT_DOUBLE_EQ(x.battery_pct, y.battery_pct);
        EXPECT_DOUBLE_EQ(x.cpu_pct, y.cpu_pct);
        EXPECT_DOUBLE_EQ(x.signal_dbm, y.signal_dbm);
    }
}

TEST(TelemetryGenerator, UsesCallerTimestamp) {
    TelemetryGenerator g;
    EXPECT_EQ(g.next(1.0, 987654321ULL).timestamp_ms, 987654321ULL);
}

TEST(TelemetryGenerator, ThousandsOfSamplesAlwaysEncodable) {
    // Several full orbits with a large step: every sample must pass codec validation.
    TelemetryGenerator g(99);
    for (int i = 0; i < 5000; ++i) {
        Telemetry t = g.next(25.0, static_cast<std::uint64_t>(i));
        ASSERT_TRUE(serialize(t).ok()) << "sample " << i;
    }
}
