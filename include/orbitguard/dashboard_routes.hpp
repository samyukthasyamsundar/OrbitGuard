#pragma once
#include "orbitguard/http_server.hpp"
#include "orbitguard/telemetry_store.hpp"

namespace orbitguard {

// Routes:
//   GET /                  the dashboard page
//   GET /api/telemetry?n=N JSON snapshot: link counters + newest N samples (default 120, max 600)
//   GET /healthz           "ok"
// Anything else is 404. The handler only reads from the store.
HttpServer::Handler make_dashboard_handler(const TelemetryStore& store, const char* html);

}  // namespace orbitguard
