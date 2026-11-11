#include "orbitguard/dashboard_routes.hpp"

#include <cstdlib>

#include "orbitguard/snapshot_json.hpp"
#include "orbitguard/time_util.hpp"

namespace orbitguard {

namespace {
constexpr std::size_t kDefaultSamples = 120;
constexpr std::size_t kMaxSamples = kDefaultStoreCapacity;

std::size_t parse_count(const std::string& s) {
    if (s.empty() || s.size() > 6) return kDefaultSamples;
    for (char c : s)
        if (c < '0' || c > '9') return kDefaultSamples;
    const unsigned long v = std::strtoul(s.c_str(), nullptr, 10);
    return v > kMaxSamples ? kMaxSamples : static_cast<std::size_t>(v);
}
}  // namespace

HttpServer::Handler make_dashboard_handler(const TelemetryStore& store, const char* html) {
    return [&store, html](const HttpRequest& req) -> HttpResponse {
        if (req.path == "/" || req.path == "/index.html")
            return {200, "text/html; charset=utf-8", html};
        if (req.path == "/api/telemetry") {
            const std::size_t n = parse_count(query_param(req.query, "n"));
            return {200, "application/json", snapshot_to_json(store.snapshot(n), unix_time_ms())};
        }
        if (req.path == "/healthz") return {200, "text/plain; charset=utf-8", "ok\n"};
        return {404, "text/plain; charset=utf-8", "not found\n"};
    };
}

}  // namespace orbitguard
