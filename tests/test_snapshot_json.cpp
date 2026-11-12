#include <gtest/gtest.h>

#include <cmath>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "orbitguard/snapshot_json.hpp"

using namespace orbitguard;

TEST(SnapshotJson, EmptySnapshot) {
    Snapshot s;
    EXPECT_EQ(snapshot_to_json(s, 42),
              "{\"server_time_ms\":42,\"stats\":{\"valid\":0,\"rejected\":0,\"lost\":0,"
              "\"duplicates\":0,\"out_of_order\":0,\"restarts\":0,\"alerts_raised\":0,\"auth_failures\":0,\"replays\":0,\"last_rx_ms\":null},"
              "\"alerts\":[],\"position\":null,\"samples\":[]}");
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

TEST(SnapshotJson, PositionAndTrackAppearOnlyWhenTheMapIsEnabled) {
    Snapshot s;
    s.has_position = true;
    s.position = GeoPosition{12.34, -56.78, true};
    s.orbit_time_s = 1000;
    const std::string j = snapshot_to_json(s, 0);
    EXPECT_NE(j.find("\"position\":{\"lat\":12.34,\"lon\":-56.78,\"sunlit\":true"), std::string::npos);
    EXPECT_NE(j.find("\"track\":[["), std::string::npos);
    EXPECT_EQ(snapshot_to_json(Snapshot{}, 0).find("\"track\""), std::string::npos);   // no map, no track
}

TEST(SnapshotJson, TrackCoversOneOrbitAndMarksWhereNowIs) {
    Snapshot s;
    s.has_position = true;
    s.orbit_time_s = 0;
    const std::string j = snapshot_to_json(s, 0);
    // 1 orbit sampled every period/160 => 161 points; count the "[lat,lon]" pairs.
    std::size_t pairs = 0;
    for (std::size_t p = j.find("\"track\":[["); p != std::string::npos && p < j.size(); ) {
        p = j.find("],[", p + 1);
        if (p == std::string::npos) break;
        ++pairs;
    }
    EXPECT_EQ(pairs, 160u);   // 161 points => 160 separators
    EXPECT_NE(j.find("\"track_now_index\":40"), std::string::npos);
}

namespace {
// Parse the "track":[[lat,lon],[lat,lon],...] array out of the JSON into pairs.
std::vector<std::pair<double, double>> parse_track(const std::string& j) {
    std::vector<std::pair<double, double>> out;
    std::size_t p = j.find("\"track\":[");
    if (p == std::string::npos) return out;
    p = j.find('[', p + 8);                      // the array's own opening bracket
    ++p;                                         // step inside it
    while (p < j.size() && j[p] == '[') {
        double lat = 0, lon = 0;
        int used = 0;
        if (std::sscanf(j.c_str() + p, "[%lf,%lf]%n", &lat, &lon, &used) != 2) break;
        out.emplace_back(lat, lon);
        p += static_cast<std::size_t>(used);
        if (p < j.size() && j[p] == ',') ++p;
    }
    return out;
}
}  // namespace

TEST(SnapshotJson, TheTrackPassesThroughTheSatellitesOwnPositionAtTheNowIndex) {
    // Regression: the trail and the path ahead must join at the satellite. They once did not, because
    // the track was two full orbits (which differ by the Earth's rotation) and the split point was wrong.
    OrbitParams o;
    Snapshot s;
    s.has_position = true;
    s.orbit = o;
    s.orbit_time_s = 12345.0;
    s.position = position_at(o, s.orbit_time_s);
    const auto track = parse_track(snapshot_to_json(s, 0));

    ASSERT_EQ(track.size(), 161u);
    EXPECT_NEAR(track[40].first, s.position.lat_deg, 0.01);
    EXPECT_NEAR(track[40].second, s.position.lon_deg, 0.01);
    EXPECT_GT(std::fabs(track[41].first - s.position.lat_deg) + std::fabs(track[41].second - s.position.lon_deg), 0.0);
}
