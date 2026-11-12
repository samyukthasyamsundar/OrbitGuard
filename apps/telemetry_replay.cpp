// Replays a recording made by `ground_station --record` to a ground station over UDP.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "orbitguard/replay.hpp"

using namespace orbitguard;

namespace {
volatile std::sig_atomic_t g_stop = 0;
void on_signal(int) { g_stop = 1; }

void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s --file RECORDING [--port N] [--speed X] [--max-gap-ms N]\n"
        "  --file F         recording made with ground_station --record (required)\n"
        "  --port N         ground station UDP port on localhost (default 5000)\n"
        "  --speed X        playback speed, 2 = twice as fast (default 1)\n"
        "  --max-gap-ms N   shorten pauses longer than N ms (default 5000, 0 = keep all)\n", prog);
}
bool parse_num(const char* s, double& out) {
    char* end = nullptr;
    out = std::strtod(s, &end);
    return end != s && *end == '\0';
}
}  // namespace

int main(int argc, char** argv) {
    std::string file;
    double port = 5000;
    ReplayOptions opt;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!std::strcmp(argv[i], "--file")) {
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            file = argv[++i];
            continue;
        }
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--speed")) target = &opt.speed;
        else if (!std::strcmp(argv[i], "--max-gap-ms")) target = &opt.max_gap_ms;
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (file.empty() || port < 1 || port > 65535 || !opt.valid()) {
        std::fprintf(stderr, "error: missing or out-of-range argument\n");
        usage(argv[0]);
        return 2;
    }

    auto reader = RecordReader::open(file);
    if (!reader) { std::fprintf(stderr, "error: %s\n", reader.error().message.c_str()); return 1; }
    auto sock = UdpSocket::create();
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::printf("telemetry_replay: %s -> udp 127.0.0.1:%d at %.2gx\n", file.c_str(), static_cast<int>(port), opt.speed);
    std::fflush(stdout);

    auto res = replay(reader.value(), sock.value(), static_cast<std::uint16_t>(port), opt,
                      [] { return g_stop != 0; });
    if (!res) { std::fprintf(stderr, "error: %s\n", res.error().message.c_str()); return 1; }

    std::printf("replayed %llu datagrams%s\n", static_cast<unsigned long long>(res.value().sent),
                res.value().stopped ? " (interrupted)" : "");
    if (!res.value().stopped && res.value().end != ReadEnd::Eof) {
        std::fprintf(stderr, "warning: stopped early: %s\n", to_string(res.value().end));
        return 3;
    }
    return 0;
}
