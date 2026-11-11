#include "orbitguard/snapshot_json.hpp"

#include <cstdio>

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
    o += "\"last_rx_ms\":";
    o += s.stats.has_last_rx ? std::to_string(s.stats.last_rx_ms) : "null";
    o += "},\"samples\":[";
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
