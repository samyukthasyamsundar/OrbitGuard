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

#include "orbitguard/alerts.hpp"

namespace {
// Run a scenario for `n` one-minute steps and report the worst severity seen per metric.
std::vector<Severity> worst(Scenario sc, int n) {
    TelemetryGenerator g(3, 90.0 * 60.0, sc);
    AlertEvaluator ev;
    std::vector<Severity> w(4, Severity::Ok);
    for (int i = 0; i < n; ++i) {
        for (const Alert& a : ev.update(g.next(60.0, 1000 + static_cast<std::uint64_t>(i) * 60000)))
            if (a.severity > w[static_cast<std::size_t>(a.metric)]) w[static_cast<std::size_t>(a.metric)] = a.severity;
    }
    return w;
}
}  // namespace

TEST(Scenario, ParsesKnownNamesOnly) {
    Scenario s;
    EXPECT_TRUE(parse_scenario("battery-drain", s));
    EXPECT_EQ(s, Scenario::BatteryDrain);
    EXPECT_TRUE(parse_scenario("nominal", s));
    EXPECT_FALSE(parse_scenario("", s));
    EXPECT_FALSE(parse_scenario("Battery-Drain", s));
    EXPECT_FALSE(parse_scenario("explode", s));
}

TEST(Scenario, NominalNeverAlertsOverManyOrbits) {
    for (Severity s : worst(Scenario::Nominal, 600)) EXPECT_EQ(s, Severity::Ok);
}

TEST(Scenario, EachAnomalyTriggersItsOwnMetricAndOnlyThat) {
    struct Case { Scenario sc; Metric m; };
    for (Case c : {Case{Scenario::BatteryDrain, Metric::Battery}, Case{Scenario::Overheat, Metric::Temperature},
                   Case{Scenario::CpuSpike, Metric::Cpu}, Case{Scenario::SignalLoss, Metric::Signal}}) {
        auto w = worst(c.sc, 120);
        for (std::size_t m = 0; m < 4; ++m) {
            if (m == static_cast<std::size_t>(c.m)) EXPECT_EQ(w[m], Severity::Critical) << "scenario " << static_cast<int>(c.sc);
            else EXPECT_EQ(w[m], Severity::Ok) << "scenario " << static_cast<int>(c.sc) << " metric " << m;
        }
    }
}

TEST(Scenario, AnomaliesStayWithinCodecLimits) {
    for (Scenario sc : {Scenario::BatteryDrain, Scenario::Overheat, Scenario::CpuSpike, Scenario::SignalLoss}) {
        TelemetryGenerator g(8, 90.0 * 60.0, sc);
        for (int i = 0; i < 3000; ++i) ASSERT_TRUE(serialize(g.next(60.0, 0)).ok()) << "scenario " << static_cast<int>(sc);
    }
}

TEST(Scenario, NominalIsUnchangedByTheScenarioParameter) {
    TelemetryGenerator a(5), b(5, 90.0 * 60.0, Scenario::Nominal);
    for (int i = 0; i < 100; ++i) {
        Telemetry x = a.next(30, 1), y = b.next(30, 1);
        EXPECT_DOUBLE_EQ(x.temperature_c, y.temperature_c);
        EXPECT_DOUBLE_EQ(x.battery_pct, y.battery_pct);
    }
}
