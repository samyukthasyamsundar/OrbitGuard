// OrbitGuard ground station: receives, validates and logs telemetry over UDP,
// and serves a live web dashboard on localhost.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include "orbitguard/dashboard_routes.hpp"
#include "orbitguard/dashboard_html.hpp"
#include "orbitguard/packet_codec.hpp"
#include "orbitguard/recording.hpp"
#include "orbitguard/telemetry_store.hpp"
#include "orbitguard/time_util.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--port N] [--http-port N] [--no-dashboard] [--record FILE]\n"
        "          [--max-packets N] [--idle-timeout-s N]\n"
        "  --port N            UDP port to listen on, localhost only (default 5000)\n"
        "  --http-port N       dashboard HTTP port, localhost only (default 8080)\n"
        "  --no-dashboard      do not start the web dashboard\n"
        "  --record FILE       save every received datagram (valid or not) to a NEW file;\n"
        "                      refuses to overwrite. Replay with telemetry_replay\n"
        "  --max-packets N     exit after N valid packets (default 0 = unlimited)\n"
        "  --idle-timeout-s N  exit if nothing arrives for N seconds (default 0 = never)\n", prog);
}
bool parse_num(const char* s, double& out) {
    char* end = nullptr;
    out = std::strtod(s, &end);
    return end != s && *end == '\0';
}
}  // namespace

int main(int argc, char** argv) {
    double port = 5000, http_port = 8080, max_packets = 0, idle_s = 0;
    bool dashboard = true;
    std::string record_path;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!std::strcmp(argv[i], "--record")) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            record_path = argv[++i];
            continue;
        }
        if (!std::strcmp(argv[i], "--no-dashboard")) { dashboard = false; continue; }
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--http-port")) target = &http_port;
        else if (!std::strcmp(argv[i], "--max-packets")) target = &max_packets;
        else if (!std::strcmp(argv[i], "--idle-timeout-s")) target = &idle_s;
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 0 || port > 65535 || http_port < 0 || http_port > 65535 || max_packets < 0 || idle_s < 0) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::optional<RecordWriter> recorder;
    if (!record_path.empty()) {
        auto w = RecordWriter::create(record_path);
        if (!w) { std::fprintf(stderr, "error: %s\n", w.error().message.c_str()); return 1; }
        recorder.emplace(std::move(w.value()));
        std::printf("ground_station: recording to %s\n", record_path.c_str());
    }

    auto sock = UdpSocket::bind_loopback(static_cast<std::uint16_t>(port));
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }
    std::printf("ground_station: listening for telemetry on udp 127.0.0.1:%u\n", sock.value().local_port());

    TelemetryStore store;
    HttpServer http;
    if (dashboard) {
        auto started = http.start(static_cast<std::uint16_t>(http_port), make_dashboard_handler(store, kDashboardHtml));
        if (!started) { std::fprintf(stderr, "error: %s\n", started.error().message.c_str()); return 1; }
        std::printf("ground_station: dashboard at http://127.0.0.1:%u/\n", http.port());
    }
    std::fflush(stdout);

    unsigned long long valid = 0;
    int idle_ms = 0;
    constexpr int kPollMs = 250;  // short poll so Ctrl-C is handled promptly

    while (!g_stop && (max_packets == 0 || valid < static_cast<unsigned long long>(max_packets))) {
        auto rx = sock.value().receive(kPollMs);
        if (!rx) { std::fprintf(stderr, "receive error: %s\n", rx.error().message.c_str()); return 1; }
        if (rx.value().timed_out) {
            idle_ms += kPollMs;
            if (idle_s > 0 && idle_ms >= idle_s * 1000) { std::printf("idle timeout\n"); break; }
            continue;
        }
        idle_ms = 0;

        // Record the raw datagram before validating it, so invalid traffic is captured too.
        const std::uint64_t rx_ms = unix_time_ms();
        if (recorder) {
            auto wrote = recorder->append(Record{rx_ms, rx.value().data});
            if (!wrote) {
                std::fprintf(stderr, "recording stopped: %s\n", wrote.error().message.c_str());
                recorder.reset();  // keep receiving; just stop recording
            }
        }

        auto pkt = deserialize(rx.value().data);
        if (!pkt) {
            store.reject();
            std::fprintf(stderr, "rejected packet (%zu bytes): %s\n", rx.value().data.size(), to_string(pkt.error()));
            continue;  // a bad packet must never stop the receiver
        }
        ++valid;
        const Telemetry& t = pkt.value();
        const SequenceStatus st = store.ingest(t, rx_ms);
        const char* note = st == SequenceStatus::Gap ? " [GAP]" : st == SequenceStatus::Duplicate ? " [DUP]"
                         : st == SequenceStatus::OutOfOrder ? " [OUT-OF-ORDER]"
                         : st == SequenceStatus::Restart ? " [SENDER RESTART]" : "";
        std::printf("recv seq=%u ts=%llu batt=%.2f%% temp=%.2fC cpu=%.2f%% sig=%.2fdBm%s\n",
                    t.sequence, static_cast<unsigned long long>(t.timestamp_ms),
                    t.battery_pct, t.temperature_c, t.cpu_pct, t.signal_dbm, note);
        std::fflush(stdout);
    }

    if (recorder) std::printf("recorded %llu datagrams to %s\n",
                              static_cast<unsigned long long>(recorder->count()), record_path.c_str());
    const Snapshot snap = store.snapshot(0);
    std::printf("summary: valid=%llu rejected=%llu lost=%llu duplicates=%llu out_of_order=%llu restarts=%llu\n",
                static_cast<unsigned long long>(snap.stats.valid),
                static_cast<unsigned long long>(snap.stats.rejected),
                static_cast<unsigned long long>(snap.stats.lost),
                static_cast<unsigned long long>(snap.stats.duplicates),
                static_cast<unsigned long long>(snap.stats.out_of_order),
                static_cast<unsigned long long>(snap.stats.restarts));
    return 0;
}
