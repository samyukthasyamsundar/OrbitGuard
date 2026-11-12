// OrbitGuard satellite simulator: generates telemetry and sends it over UDP.
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "orbitguard/fault_injector.hpp"
#include "orbitguard/packet_codec.hpp"
#include "orbitguard/secure_packet.hpp"
#include "orbitguard/telemetry_generator.hpp"
#include "orbitguard/time_util.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [--port N] [--rate-hz N] [--count N] [--seed N] [--time-scale X]\n"
        "          [--scenario NAME] [--key-file FILE] [--key-id N]\n"
        "          [--drop P] [--corrupt P] [--duplicate P] [--reorder P] [--fault-seed N]\n"
        "  --port N        ground station UDP port on localhost (default 5000)\n"
        "  --rate-hz N     packets per wall-clock second (default 1)\n"
        "  --count N       stop after N packets (default 0 = run until Ctrl-C)\n"
        "  --seed N        RNG seed for reproducible telemetry (default 42)\n"
        "  --time-scale X  simulated seconds per real second (default 60)\n"
        "  --scenario NAME inject an anomaly to trigger dashboard alerts: nominal (default),\n"
        "                  battery-drain, overheat, cpu-spike, signal-loss\n"
        "  --key-file FILE sign every packet with the key in FILE (hex, chmod 600) so the ground\n"
        "                  station can authenticate it; needs the same file on both sides\n"
        "  --key-id N      key identifier 0..255 sent in each packet (default 1)\n"
        "Link faults (probabilities 0..1, default 0), to exercise the ground station:\n"
        "  --drop P        packet is never sent\n"
        "  --corrupt P     packet gets a bit flip or is truncated\n"
        "  --duplicate P   packet is sent twice\n"
        "  --reorder P     packet is delayed behind the next one\n"
        "  --fault-seed N  RNG seed for the faults (default 1)\n", prog);
}

bool parse_num(const char* s, double& out) {
    char* end = nullptr;
    out = std::strtod(s, &end);
    return end != s && *end == '\0';
}
}  // namespace

int main(int argc, char** argv) {
    double port = 5000, rate = 1, count = 0, seed = 42, scale = 60;
    double drop = 0, corrupt = 0, duplicate = 0, reorder = 0, fault_seed = 1;
    Scenario scenario = Scenario::Nominal;
    std::string key_path;
    double key_id = 1;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--key-file")) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            key_path = argv[++i];
            continue;
        }
        if (!std::strcmp(argv[i], "--scenario")) {
            if (i + 1 >= argc || !parse_scenario(argv[++i], scenario)) { usage(argv[0]); return 2; }
            continue;
        }
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--rate-hz")) target = &rate;
        else if (!std::strcmp(argv[i], "--count")) target = &count;
        else if (!std::strcmp(argv[i], "--seed")) target = &seed;
        else if (!std::strcmp(argv[i], "--time-scale")) target = &scale;
        else if (!std::strcmp(argv[i], "--drop")) target = &drop;
        else if (!std::strcmp(argv[i], "--corrupt")) target = &corrupt;
        else if (!std::strcmp(argv[i], "--duplicate")) target = &duplicate;
        else if (!std::strcmp(argv[i], "--reorder")) target = &reorder;
        else if (!std::strcmp(argv[i], "--fault-seed")) target = &fault_seed;
        else if (!std::strcmp(argv[i], "--key-id")) target = &key_id;
        else if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 1 || port > 65535 || rate <= 0 || rate > 1000 || count < 0 || seed < 0 || scale <= 0) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }

    if (key_id < 0 || key_id > 255 || key_id != static_cast<int>(key_id)) {
        std::fprintf(stderr, "error: --key-id must be an integer 0..255\n");
        return 2;
    }
    Key signing_key;
    const bool secure = !key_path.empty();
    if (secure) {
        auto kb = load_key_file(key_path);
        if (!kb) { std::fprintf(stderr, "error: %s\n", kb.error().message.c_str()); return 1; }
        signing_key.id = static_cast<std::uint8_t>(key_id);
        signing_key.bytes = std::move(kb.value());
    }

    FaultConfig fc;
    fc.drop = drop; fc.corrupt = corrupt; fc.duplicate = duplicate; fc.reorder = reorder;
    fc.seed = static_cast<std::uint32_t>(fault_seed);
    if (!fc.valid() || fault_seed < 0 || fault_seed > 4294967295.0) {
        std::fprintf(stderr, "error: fault probabilities must be between 0 and 1\n");
        return 2;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    auto sock = UdpSocket::create();
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }

    TelemetryGenerator gen(static_cast<std::uint32_t>(seed), 90.0 * 60.0, scenario);
    FaultInjector faults(fc);
    auto transmit = [&](const std::vector<std::vector<std::uint8_t>>& datagrams) {
        for (const auto& d : datagrams) {
            auto r = sock.value().send_to_loopback(static_cast<std::uint16_t>(port), d);
            if (!r) std::fprintf(stderr, "send error: %s\n", r.error().message.c_str());
        }
    };
    const auto period = std::chrono::duration<double>(1.0 / rate);
    const double sim_dt = scale / rate;
    auto next_tick = std::chrono::steady_clock::now();

    const std::uint64_t counter_base = secure ? unix_time_ms() * 1000ULL : 0;
    if (secure) std::printf("satellite_sim: authenticating packets (key id %d)\n", static_cast<int>(key_id));
    std::printf("satellite_sim: sending to 127.0.0.1:%d at %.2f Hz\n", static_cast<int>(port), rate);
    for (long sent = 0; !g_stop && (count == 0 || sent < static_cast<long>(count)); ++sent) {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        Telemetry t = gen.next(sim_dt, static_cast<std::uint64_t>(now_ms));

        std::vector<std::uint8_t> wire_bytes;
        if (secure) {
            // Counter: wall-clock based so it keeps increasing across sender restarts (a counter must
            // never be reused under one key), then +1 per packet.
            auto sealed = seal(t, signing_key, counter_base + static_cast<std::uint64_t>(sent));
            if (!sealed) { std::fprintf(stderr, "encode error: %s\n", to_string(sealed.error())); return 1; }
            wire_bytes = std::move(sealed.value());
        } else {
            auto plain = serialize(t);
            if (!plain) { std::fprintf(stderr, "encode error: %s\n", to_string(plain.error())); return 1; }
            wire_bytes = std::move(plain.value());
        }
        const std::size_t wire = [&] {
            auto out = faults.process(wire_bytes);
            transmit(out);
            return out.size();
        }();
        std::printf("sent seq=%u batt=%.1f%% temp=%.1fC cpu=%.1f%% sig=%.1fdBm%s\n",
                    t.sequence, t.battery_pct, t.temperature_c, t.cpu_pct, t.signal_dbm,
                    fc.any() ? (wire == 0 ? " [not delivered]" : wire > 1 ? " [multiple datagrams]" : "") : "");
        std::fflush(stdout);

        next_tick += std::chrono::duration_cast<std::chrono::steady_clock::duration>(period);
        std::this_thread::sleep_until(next_tick);
    }
    transmit(faults.flush());  // release a packet still held back for reordering
    if (fc.any()) {
        const FaultStats& fs = faults.stats();
        std::printf("faults injected: dropped=%llu corrupted=%llu duplicated=%llu reordered=%llu\n",
                    static_cast<unsigned long long>(fs.dropped), static_cast<unsigned long long>(fs.corrupted),
                    static_cast<unsigned long long>(fs.duplicated), static_cast<unsigned long long>(fs.reordered));
    }
    return 0;
}
