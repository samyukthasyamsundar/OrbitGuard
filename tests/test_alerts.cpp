#include <gtest/gtest.h>

#include <cmath>
#include <limits>

#include "orbitguard/alerts.hpp"

using namespace orbitguard;

namespace {
Telemetry sample(double batt = 80, double temp = 20, double cpu = 30, double sig = -90, std::uint64_t ts = 1000) {
    Telemetry t;
    t.timestamp_ms = ts;
    t.battery_pct = batt; t.temperature_c = temp; t.cpu_pct = cpu; t.signal_dbm = sig;
    return t;
}
const Alert* find(const std::vector<Alert>& v, Metric m) {
    for (const auto& a : v) if (a.metric == m) return &a;
    return nullptr;
}
}  // namespace

TEST(AlertConfig, DefaultsAreValid) { EXPECT_TRUE(AlertConfig::defaults().valid()); }

TEST(AlertConfig, RejectsInconsistentLimits) {
    auto c = AlertConfig::defaults();
    c.battery.crit_low = 50;  // critical must be at or below warning
    EXPECT_FALSE(c.valid());
    c = AlertConfig::defaults();
    c.cpu.crit_high = 50;  // critical must be at or above warning
    EXPECT_FALSE(c.valid());
    c = AlertConfig::defaults();
    c.signal.hysteresis = -1;
    EXPECT_FALSE(c.valid());
    c = AlertConfig::defaults();
    c.temperature.warn_high = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(c.valid());
    c = AlertConfig::defaults();
    c.temperature.warn_low = 70;  // low side above high side
    c.temperature.crit_low = 60;
    EXPECT_FALSE(c.valid());
}

TEST(Alerts, NominalValuesRaiseNothing) {
    AlertEvaluator e;
    EXPECT_TRUE(e.update(sample()).empty());
    EXPECT_EQ(e.raised_count(), 0u);
}

TEST(Alerts, LowBatteryWarningThenCritical) {
    AlertEvaluator e;
    auto a = e.update(sample(39.9));
    ASSERT_EQ(a.size(), 1u);
    EXPECT_EQ(a[0].metric, Metric::Battery);
    EXPECT_EQ(a[0].severity, Severity::Warning);
    EXPECT_TRUE(a[0].low_side);
    a = e.update(sample(19.9));
    ASSERT_EQ(a.size(), 1u);
    EXPECT_EQ(a[0].severity, Severity::Critical);
}

TEST(Alerts, ThresholdValueItselfIsNotAnAlert) {
    AlertEvaluator e;
    EXPECT_TRUE(e.update(sample(40.0)).empty());   // exactly at the warn limit
    EXPECT_TRUE(e.update(sample(80, 60.0)).empty());
    EXPECT_TRUE(e.update(sample(80, 20, 85.0)).empty());
}

TEST(Alerts, TemperatureAlertsOnBothSides) {
    AlertEvaluator e;
    auto a = e.update(sample(80, 61));
    ASSERT_NE(find(a, Metric::Temperature), nullptr);
    EXPECT_FALSE(find(a, Metric::Temperature)->low_side);
    a = e.update(sample(80, 20));   // recovers fully
    EXPECT_TRUE(a.empty());
    a = e.update(sample(80, -26));
    ASSERT_NE(find(a, Metric::Temperature), nullptr);
    EXPECT_TRUE(find(a, Metric::Temperature)->low_side);
}

TEST(Alerts, MultipleMetricsAtOnce) {
    AlertEvaluator e;
    auto a = e.update(sample(10, 90, 99, -120));
    EXPECT_EQ(a.size(), 4u);
    for (const auto& x : a) EXPECT_EQ(x.severity, Severity::Critical);
}

TEST(Alerts, HysteresisPreventsFlapping) {
    AlertEvaluator e;
    e.update(sample(39));                            // warning raised
    EXPECT_EQ(e.raised_count(), 1u);
    EXPECT_EQ(e.update(sample(41)).size(), 1u);      // above the limit but inside the margin: held
    EXPECT_EQ(e.update(sample(39.5)).size(), 1u);
    EXPECT_EQ(e.update(sample(42.9)).size(), 1u);    // 40 + 3 = 43 clears it
    EXPECT_TRUE(e.update(sample(43.1)).empty());     // recovered
    EXPECT_EQ(e.raised_count(), 1u);                 // hovering did not re-raise
}

TEST(Alerts, ReRaisedAfterRecoveryCountsAgain) {
    AlertEvaluator e;
    e.update(sample(39));
    e.update(sample(60));
    e.update(sample(39));
    EXPECT_EQ(e.raised_count(), 2u);
}

TEST(Alerts, CriticalDeEscalatesToWarningBeforeClearing) {
    AlertEvaluator e;
    e.update(sample(10));                       // critical
    auto a = e.update(sample(25));              // above crit_low + h (23): critical clears, still below warn
    ASSERT_EQ(a.size(), 1u);
    EXPECT_EQ(a[0].severity, Severity::Warning);
    EXPECT_TRUE(e.update(sample(50)).empty());
}

TEST(Alerts, CriticalHeldByHysteresisNearItsLimit) {
    AlertEvaluator e;
    e.update(sample(19));                       // critical (< 20)
    auto a = e.update(sample(21));              // above 20 but within 3: still critical
    ASSERT_EQ(a.size(), 1u);
    EXPECT_EQ(a[0].severity, Severity::Critical);
}

TEST(Alerts, SinceTimestampIsWhenSeverityLastWorsened) {
    AlertEvaluator e;
    e.update(sample(39, 20, 30, -90, 1000));
    auto a = e.update(sample(38, 20, 30, -90, 2000));  // still warning: same incident
    EXPECT_EQ(a[0].since_ms, 1000u);
    a = e.update(sample(15, 20, 30, -90, 3000));       // escalates to critical
    EXPECT_EQ(a[0].since_ms, 3000u);
}

TEST(Alerts, ActiveReflectsLastUpdate) {
    AlertEvaluator e;
    e.update(sample(10));
    EXPECT_EQ(e.active().size(), 1u);
    e.update(sample(90));
    EXPECT_TRUE(e.active().empty());
}

TEST(Alerts, StringNamesAreStable) {
    EXPECT_STREQ(to_string(Severity::Warning), "warning");
    EXPECT_STREQ(to_string(Severity::Critical), "critical");
    EXPECT_STREQ(to_string(Metric::Signal), "signal");
}
