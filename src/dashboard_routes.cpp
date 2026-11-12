#include "orbitguard/dashboard_routes.hpp"

#include <cstdlib>

#include "orbitguard/snapshot_json.hpp"
#include "orbitguard/time_util.hpp"

namespace orbitguard {

namespace {
// Start URL is "/" with no query: the browser sends the HttpOnly cookie, so the token never needs to
// be stored in the app's launch URL.
constexpr const char* kManifest = R"OGM({
  "name": "OrbitGuard Ground Station",
  "short_name": "OrbitGuard",
  "description": "Live satellite telemetry dashboard",
  "start_url": "/",
  "scope": "/",
  "display": "standalone",
  "orientation": "any",
  "background_color": "#f9f9f7",
  "theme_color": "#2a78d6",
  "icons": [
    { "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }
  ]
})OGM";

constexpr const char* kIconSvg = R"OGI(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="112" fill="#2a78d6"/>
  <ellipse cx="256" cy="256" rx="170" ry="62" fill="none" stroke="#ffffff" stroke-width="22" transform="rotate(-28 256 256)"/>
  <circle cx="256" cy="256" r="58" fill="#ffffff"/>
  <circle cx="384" cy="160" r="26" fill="#ffffff"/>
</svg>)OGI";

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
        // Installable-app metadata. Served from memory (the server never touches the filesystem).
        // Deliberately NO service worker: it would cache responses, and this page shows live data
        // behind an access token that must never be stored by a cache.
        if (req.path == "/manifest.webmanifest") return {200, "application/manifest+json", kManifest};
        if (req.path == "/icon.svg") return {200, "image/svg+xml", kIconSvg};
        return {404, "text/plain; charset=utf-8", "not found\n"};
    };
}

}  // namespace orbitguard
