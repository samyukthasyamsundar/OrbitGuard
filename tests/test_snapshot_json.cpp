#include <gtest/gtest.h>

#include <string>

#include "orbitguard/snapshot_json.hpp"

using namespace orbitguard;

TEST(SnapshotJson, EmptySnapshot) {
    Snapshot s;
    EXPECT_EQ(snapshot_to_json(s, 42),
              "{\"server_time_ms\":42,\"stats\":{\"valid\":0,\"rejected\":0,\"lost\":0,"
              "\"duplicates\":0,\"out_of_order\":0,\"restarts\":0,\"alerts_raised\":0,\"last_rx_ms\":null},"
              "\"alerts\":[],\"samples\":[]}");
}

TEST(SnapshotJson, SamplesAndStats) {
    Snapshot s;
    s.stats.valid = 2;
    s.stats.has_last_rx = true;
    s.stats.last_rx_ms = 777;
    Telemetry t;
    t.sequence = 7;
    t.timestamp_ms = 1700000000123ULL;
    t.battery_pct = 87.65;
    t.temperature_c = -12.34;
    t.cpu_pct = 42.5;
    t.signal_dbm = -97.25;
    s.samples.push_back(t);
    const std::string j = snapshot_to_json(s, 1);
    EXPECT_NE(j.find("\"valid\":2"), std::string::npos);
    EXPECT_NE(j.find("\"last_rx_ms\":777"), std::string::npos);
    EXPECT_NE(j.find("{\"seq\":7,\"ts\":1700000000123,\"battery\":87.65,\"temp\":-12.34,\"cpu\":42.50,\"signal\":-97.25}"),
              std::string::npos);
}

TEST(SnapshotJson, MultipleSamplesAreCommaSeparated) {
    Snapshot s;
    s.samples.resize(3);
    const std::string j = snapshot_to_json(s, 0);
    std::size_t commas = 0, pos = j.find("\"samples\":[");
    for (std::size_t i = pos; i < j.size(); ++i)
        if (j.compare(i, 3, "},{") == 0) ++commas;
    EXPECT_EQ(commas, 2u);
}

TEST(SnapshotJson, ActiveAlertsAreSerialised) {
    Snapshot s;
    s.alerts.push_back({Metric::Battery, Severity::Critical, 18.5, 1234, true});
    s.alerts.push_back({Metric::Temperature, Severity::Warning, 61.0, 99, false});
    const std::string j = snapshot_to_json(s, 0);
    EXPECT_NE(j.find("{\"metric\":\"battery\",\"severity\":\"critical\",\"side\":\"low\",\"value\":18.50,\"since_ms\":1234}"),
              std::string::npos);
    EXPECT_NE(j.find("{\"metric\":\"temperature\",\"severity\":\"warning\",\"side\":\"high\",\"value\":61.00,\"since_ms\":99}"),
              std::string::npos);
}
