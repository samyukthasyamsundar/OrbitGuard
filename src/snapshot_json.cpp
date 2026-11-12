#include "orbitguard/snapshot_json.hpp"

#include <cstdio>

#include "orbitguard/orbit.hpp"

namespace orbitguard {

namespace {
std::string fixed2(double v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.2f", v);
    return buf;
}
void field(std::string& o, const char* name, std::uint64_t v, bool comma = true) {
    o += '"';
    o += name;
    o += "\":";
    o += std::to_string(v);
    if (comma) o += ',';
}
}  // namespace

std::string snapshot_to_json(const Snapshot& s, std::uint64_t server_time_ms) {
    std::string o;
    o.reserve(256 + s.samples.size() * 96);
    o += '{';
    field(o, "server_time_ms", server_time_ms);
    o += "\"stats\":{";
    field(o, "valid", s.stats.valid);
    field(o, "rejected", s.stats.rejected);
    field(o, "lost", s.stats.lost);
    field(o, "duplicates", s.stats.duplicates);
    field(o, "out_of_order", s.stats.out_of_order);
    field(o, "restarts", s.stats.restarts);
    field(o, "alerts_raised", s.stats.alerts_raised);
    field(o, "auth_failures", s.stats.auth_failures);
    field(o, "replays", s.stats.replays);
    o += "\"last_rx_ms\":";
    o += s.stats.has_last_rx ? std::to_string(s.stats.last_rx_ms) : "null";
    o += "},\"alerts\":[";
    for (std::size_t i = 0; i < s.alerts.size(); ++i) {
        const Alert& a = s.alerts[i];
        if (i) o += ',';
        o += "{\"metric\":\"";
        o += to_string(a.metric);
        o += "\",\"severity\":\"";
        o += to_string(a.severity);
        o += "\",\"side\":\"";
        o += a.low_side ? "low" : "high";
        o += "\",\"value\":" + fixed2(a.value);
        o += ",\"since_ms\":" + std::to_string(a.since_ms) + '}';
    }
    o += "],\"position\":";
    if (!s.has_position) {
        o += "null";
    } else {
        o += "{\"lat\":" + fixed2(s.position.lat_deg) + ",\"lon\":" + fixed2(s.position.lon_deg);
        o += std::string(",\"sunlit\":") + (s.position.sunlit ? "true" : "false");
        o += ",\"orbit_time_s\":" + fixed2(s.orbit_time_s);
        o += ",\"inclination_deg\":" + fixed2(s.orbit.inclination_deg);
        o += ",\"period_s\":" + fixed2(s.orbit.period_s);
        // Past and upcoming ground track: one orbit behind and one ahead, so the page can draw a trail
        // and the path the satellite is about to follow. 3-decimal precision is under 150 m, far finer
        // than a map pixel.
        // A quarter orbit behind and three quarters ahead, so the trail and the path to come join at
        // the satellite instead of drawing two overlapping full orbits (the Earth turns under the orbit,
        // so consecutive orbits are different curves 22 degrees apart). "now" is index kNowIndex.
        const auto track = ground_track(s.orbit, s.orbit_time_s - 0.25 * s.orbit.period_s, s.orbit.period_s, s.orbit.period_s / 160.0);
        o += ",\"track_now_index\":40";
        o += ",\"track\":[";
        for (std::size_t i = 0; i < track.size(); ++i) {
            if (i) o += ',';
            char b[64];
            std::snprintf(b, sizeof b, "[%.2f,%.2f]", track[i].lat_deg, track[i].lon_deg);
            o += b;
        }
        o += "]}";
    }
    o += ",\"samples\":[";
    for (std::size_t i = 0; i < s.samples.size(); ++i) {
        const Telemetry& t = s.samples[i];
        if (i) o += ',';
        o += '{';
        field(o, "seq", t.sequence);
        field(o, "ts", t.timestamp_ms);
        o += "\"battery\":" + fixed2(t.battery_pct);
        o += ",\"temp\":" + fixed2(t.temperature_c);
        o += ",\"cpu\":" + fixed2(t.cpu_pct);
        o += ",\"signal\":" + fixed2(t.signal_dbm);
        o += '}';
    }
    o += "]}";
    return o;
}

}  // namespace orbitguard
