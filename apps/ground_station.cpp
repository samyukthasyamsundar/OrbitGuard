// OrbitGuard ground station: receives, validates and logs telemetry over UDP,
// and serves a live web dashboard on localhost.
#include <csignal>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include "orbitguard/dashboard_routes.hpp"
#include "orbitguard/dashboard_html.hpp"
#include "orbitguard/packet_codec.hpp"
#include "orbitguard/recording.hpp"
#include "orbitguard/secure_packet.hpp"
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
        "          [--key-file FILE] [--key-id N]\n"
        "          [--max-packets N] [--idle-timeout-s N]\n"
        "  --port N            UDP port to listen on, localhost only (default 5000)\n"
        "  --http-port N       dashboard HTTP port, localhost only (default 8080)\n"
        "  --no-dashboard      do not start the web dashboard\n"
        "  --key-file FILE     require authenticated packets: only packets signed with the key in\n"
        "                      FILE (hex, chmod 600) are accepted; others are counted as attacks\n"
        "  --key-id N          identifier for that key (default 1)\n"
        "  --record FILE       save every received datagram (valid or not) to a NEW file;\n"
        "                      refuses to overwrite. Replay with telemetry_replay\n"
        "  --lan               let other devices on your network (e.g. a phone) open the dashboard. Off by\n"
        "                      by default. Prints a one-time secret link; anyone with the link and network\n"
        "                      access can view the dashboard, so only use it on a network you trust\n"
        "  --verify-budget     OPT-IN: cap the HMAC work forced by well-formed but badly signed packets\n"
        "                      (2000/s, burst 500). Saves CPU under a forgery flood but also refuses\n"
        "                      genuine packets while the budget is empty; see docs/THREAT_MODEL.md\n"
        "  --map TIMESCALE,RATE  show the satellite on a world map. Give the same --time-scale and\n"
        "                      --rate-hz that satellite_sim uses (e.g. --map 300,5); the orbit is a\n"
        "                      simple circular model positioned from each packet's sequence number\n"
        "  --recv-buffer-kb N  ask the OS for a UDP receive buffer of N KiB so a burst queues instead of\n"
        "                      being dropped (default: OS default)\n"
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
    bool dashboard = true, verify_budget = false, lan = false;
    double map_scale = 0, map_rate = 0;   // both > 0 once --map is given   // off by default: it trades availability for CPU
    std::string record_path, key_path;
    double key_id = 1, recv_kb = 0;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--key-file")) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            key_path = argv[++i];
            continue;
        }
        if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!std::strcmp(argv[i], "--record")) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            record_path = argv[++i];
            continue;
        }
        if (!std::strcmp(argv[i], "--no-dashboard")) { dashboard = false; continue; }
        if (!std::strcmp(argv[i], "--verify-budget")) { verify_budget = true; continue; }
        if (!std::strcmp(argv[i], "--lan")) { lan = true; continue; }
        if (!std::strcmp(argv[i], "--map")) {
            // "--map SCALE,RATE": both must be positive finite numbers.
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            const char* spec = argv[++i];
            char* mid = nullptr;
            map_scale = std::strtod(spec, &mid);
            if (mid == spec || *mid != ',') { std::fprintf(stderr, "error: --map expects TIMESCALE,RATE (e.g. 300,5)\n"); return 2; }
            char* end = nullptr;
            map_rate = std::strtod(mid + 1, &end);
            if (end == mid + 1 || *end != '\0' || !std::isfinite(map_scale) || !std::isfinite(map_rate) ||
                map_scale <= 0 || map_rate <= 0 || map_rate > 1000) {
                std::fprintf(stderr, "error: --map needs a positive time scale and a rate between 0 and 1000\n");
                return 2;
            }
            continue;
        }
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--http-port")) target = &http_port;
        else if (!std::strcmp(argv[i], "--max-packets")) target = &max_packets;
        else if (!std::strcmp(argv[i], "--idle-timeout-s")) target = &idle_s;
        else if (!std::strcmp(argv[i], "--key-id")) target = &key_id;
        else if (!std::strcmp(argv[i], "--recv-buffer-kb")) target = &recv_kb;
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 0 || port > 65535 || http_port < 0 || http_port > 65535 || max_packets < 0 || idle_s < 0) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }

    if (key_id < 0 || key_id > 255 || key_id != static_cast<int>(key_id)) {
        std::fprintf(stderr, "error: --key-id must be an integer 0..255\n");
        return 2;
    }
    KeyRing keyring;
    if (!key_path.empty()) {
        auto kb = load_key_file(key_path);
        if (!kb) { std::fprintf(stderr, "error: %s\n", kb.error().message.c_str()); return 1; }
        keyring.add(Key{static_cast<std::uint8_t>(key_id), std::move(kb.value())});
        // Opt-in cap on the HMAC work an attacker can force with well-formed but badly signed packets.
        if (verify_budget) keyring.set_verification_budget(2000.0, 500.0);
    }
    const bool secure = !keyring.empty();

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::optional<RecordWriter> recorder;
    if (!record_path.empty()) {
        auto w = RecordWriter::create(record_path);
        if (!w) { std::fprintf(stderr, "error: %s\n", w.error().message.c_str()); return 1; }
        recorder.emplace(std::move(w.value()));
        std::printf("ground_station: recording to %s\n", record_path.c_str());
    }

    if (recv_kb < 0 || recv_kb > 65536) {
        std::fprintf(stderr, "error: --recv-buffer-kb must be 0..65536\n");
        return 2;
    }
    auto sock = UdpSocket::bind_loopback(static_cast<std::uint16_t>(port), static_cast<int>(recv_kb) * 1024);
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }
    std::printf("ground_station: listening for telemetry on udp 127.0.0.1:%u%s\n", sock.value().local_port(),
                secure ? " (authentication REQUIRED)" : "");
    if (recv_kb > 0) std::printf("ground_station: receive buffer %d KiB (requested %d KiB)\n",
                                 sock.value().receive_buffer_bytes() / 1024, static_cast<int>(recv_kb));

    TelemetryStore store;
    if (map_scale > 0) {
        store.enable_orbit(OrbitParams{}, map_scale / map_rate);
        std::printf("ground_station: map enabled (%.0f sim-s per real-s at %.2f packets/s)\n", map_scale, map_rate);
    }
    HttpServer http;
    if (dashboard) {
        HttpServer::Options hopt;
        std::string token;
        if (lan) {
            // A fresh random secret every run. If the system cannot supply randomness we refuse to open the
            // network at all, rather than fall back to something guessable.
            token = random_token_hex(16);
            if (token.empty()) {
                std::fprintf(stderr, "error: cannot generate a secure access token; refusing to open the dashboard to the network\n");
                return 1;
            }
            hopt.allow_lan = true;
            hopt.access_token = token;
        }
        auto started = http.start(static_cast<std::uint16_t>(http_port), make_dashboard_handler(store, kDashboardHtml), hopt);
        if (!started) { std::fprintf(stderr, "error: %s\n", started.error().message.c_str()); return 1; }
        if (!lan) {
            std::printf("ground_station: dashboard at http://127.0.0.1:%u/\n", http.port());
        } else {
            std::printf("ground_station: dashboard is OPEN TO YOUR NETWORK (port %u, secret link required)\n", http.port());
            std::printf("  on this computer: http://127.0.0.1:%u/?k=%s\n", http.port(), token.c_str());
            const auto addrs = local_ipv4_addresses();
            if (addrs.empty()) std::printf("  (no network address found; connect to Wi-Fi to reach it from a phone)\n");
            for (const auto& a : addrs)
                std::printf("  on your phone (same network): http://%s:%u/?k=%s\n", a.c_str(), http.port(), token.c_str());
            std::printf("  The link is a password: anyone who has it and is on your network can view the dashboard.\n");
            std::printf("  It changes every time you start the ground station. Press Ctrl-C to close it.\n");
        }
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

        // Decode. In secure mode ONLY authenticated packets are accepted: an unsigned (v1) packet is
        // a downgrade attempt and is treated as an attack, never silently accepted.
        std::optional<Telemetry> accepted;
        if (secure) {
            const auto& d = rx.value().data;
            if (!looks_secure(d.data(), d.size())) {
                store.auth_failure();
                std::fprintf(stderr, "SECURITY: unauthenticated packet refused (%zu bytes)\n", d.size());
                continue;
            }
            auto opened = keyring.receive(d.data(), d.size(), rx_ms);
            if (!opened) {
                const SecureError e = opened.error();
                if (e == SecureError::RateLimited) {
                    store.auth_failure();   // still an attack signal; just no per-packet log line, which would itself be a DoS amplifier
                    continue;
                }
                if (e == SecureError::Replay || e == SecureError::TooOld || e == SecureError::TooFarAhead) {
                    store.replay();
                    std::fprintf(stderr, "SECURITY: %s\n", to_string(e));
                } else {
                    store.auth_failure();
                    std::fprintf(stderr, "SECURITY: %s (%zu bytes)\n", to_string(e), d.size());
                }
                continue;
            }
            accepted = opened.value().telemetry;
        } else {
            auto pkt = deserialize(rx.value().data);
            if (!pkt) {
                store.reject();
                std::fprintf(stderr, "rejected packet (%zu bytes): %s\n", rx.value().data.size(), to_string(pkt.error()));
                continue;  // a bad packet must never stop the receiver
            }
            accepted = pkt.value();
        }
        ++valid;
        const Telemetry& t = *accepted;
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
    std::printf("summary: valid=%llu rejected=%llu lost=%llu duplicates=%llu out_of_order=%llu restarts=%llu"
                " auth_failures=%llu replays=%llu\n",
                static_cast<unsigned long long>(snap.stats.valid),
                static_cast<unsigned long long>(snap.stats.rejected),
                static_cast<unsigned long long>(snap.stats.lost),
                static_cast<unsigned long long>(snap.stats.duplicates),
                static_cast<unsigned long long>(snap.stats.out_of_order),
                static_cast<unsigned long long>(snap.stats.restarts),
                static_cast<unsigned long long>(snap.stats.auth_failures),
                static_cast<unsigned long long>(snap.stats.replays));
    return 0;
}
