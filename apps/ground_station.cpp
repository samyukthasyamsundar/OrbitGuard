// OrbitGuard ground station: receives, validates and logs telemetry over UDP.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/sequence_tracker.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--port N] [--max-packets N] [--idle-timeout-s N]\n"
        "  --port N            UDP port to listen on, localhost only (default 5000)\n"
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
    double port = 5000, max_packets = 0, idle_s = 0;
    for (int i = 1; i < argc; ++i) {
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--max-packets")) target = &max_packets;
        else if (!std::strcmp(argv[i], "--idle-timeout-s")) target = &idle_s;
        else if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 0 || port > 65535 || max_packets < 0 || idle_s < 0) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    auto sock = UdpSocket::bind_loopback(static_cast<std::uint16_t>(port));
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }
    std::printf("ground_station: listening on 127.0.0.1:%u\n", sock.value().local_port());
    std::fflush(stdout);

    SequenceTracker tracker;
    unsigned long long rejected = 0, valid = 0;
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

        auto pkt = deserialize(rx.value().data);
        if (!pkt) {
            ++rejected;
            std::fprintf(stderr, "rejected packet (%zu bytes): %s\n", rx.value().data.size(), to_string(pkt.error()));
            continue;  // a bad packet must never stop the receiver
        }
        ++valid;
        const Telemetry& t = pkt.value();
        const SequenceStatus st = tracker.observe(t.sequence);
        const char* note = st == SequenceStatus::Gap ? " [GAP]" : st == SequenceStatus::Duplicate ? " [DUP]"
                         : st == SequenceStatus::OutOfOrder ? " [OUT-OF-ORDER]" : "";
        std::printf("recv seq=%u ts=%llu batt=%.2f%% temp=%.2fC cpu=%.2f%% sig=%.2fdBm%s\n",
                    t.sequence, static_cast<unsigned long long>(t.timestamp_ms),
                    t.battery_pct, t.temperature_c, t.cpu_pct, t.signal_dbm, note);
        std::fflush(stdout);
    }

    std::printf("summary: valid=%llu rejected=%llu lost=%llu duplicates=%llu out_of_order=%llu\n",
                valid, rejected,
                static_cast<unsigned long long>(tracker.lost()),
                static_cast<unsigned long long>(tracker.duplicates()),
                static_cast<unsigned long long>(tracker.out_of_order()));
    return 0;
}
