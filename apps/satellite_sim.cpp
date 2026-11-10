// OrbitGuard satellite simulator: generates telemetry and sends it over UDP.
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/telemetry_generator.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--port N] [--rate-hz N] [--count N] [--seed N] [--time-scale X]\n"
        "  --port N        ground station UDP port on localhost (default 5000)\n"
        "  --rate-hz N     packets per wall-clock second (default 1)\n"
        "  --count N       stop after N packets (default 0 = run until Ctrl-C)\n"
        "  --seed N        RNG seed for reproducible telemetry (default 42)\n"
        "  --time-scale X  simulated seconds per real second (default 60)\n", prog);
}

bool parse_num(const char* s, double& out) {
    char* end = nullptr;
    out = std::strtod(s, &end);
    return end != s && *end == '\0';
}
}  // namespace

int main(int argc, char** argv) {
    double port = 5000, rate = 1, count = 0, seed = 42, scale = 60;
    for (int i = 1; i < argc; ++i) {
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--rate-hz")) target = &rate;
        else if (!std::strcmp(argv[i], "--count")) target = &count;
        else if (!std::strcmp(argv[i], "--seed")) target = &seed;
        else if (!std::strcmp(argv[i], "--time-scale")) target = &scale;
        else if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 1 || port > 65535 || rate <= 0 || rate > 1000 || count < 0 || seed < 0 || scale <= 0) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    auto sock = UdpSocket::create();
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }

    TelemetryGenerator gen(static_cast<std::uint32_t>(seed));
    const auto period = std::chrono::duration<double>(1.0 / rate);
    const double sim_dt = scale / rate;
    auto next_tick = std::chrono::steady_clock::now();

    std::printf("satellite_sim: sending to 127.0.0.1:%d at %.2f Hz\n", static_cast<int>(port), rate);
    for (long sent = 0; !g_stop && (count == 0 || sent < static_cast<long>(count)); ++sent) {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        Telemetry t = gen.next(sim_dt, static_cast<std::uint64_t>(now_ms));

        auto bytes = serialize(t);
        if (!bytes) {
            std::fprintf(stderr, "encode error: %s\n", to_string(bytes.error()));
            return 1;
        }
        auto sent_ok = sock.value().send_to_loopback(static_cast<std::uint16_t>(port), bytes.value());
        if (!sent_ok) std::fprintf(stderr, "send error: %s\n", sent_ok.error().message.c_str());
        else std::printf("sent seq=%u batt=%.1f%% temp=%.1fC cpu=%.1f%% sig=%.1fdBm\n",
                         t.sequence, t.battery_pct, t.temperature_c, t.cpu_pct, t.signal_dbm);
        std::fflush(stdout);

        next_tick += std::chrono::duration_cast<std::chrono::steady_clock::duration>(period);
        std::this_thread::sleep_until(next_tick);
    }
    return 0;
}
