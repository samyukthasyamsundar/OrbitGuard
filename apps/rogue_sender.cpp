// OrbitGuard rogue sender: a deliberately hostile client for DEMONSTRATING and TESTING the
// ground station's defences against a local, authorised target (127.0.0.1 only).
//
// It never targets anything but loopback, and it only ever sends packets to a port you give it.
// Attacks:
//   forge     unauthenticated v1 packet with plausible values   (a downgrade / spoofing attempt)
//   wrongkey  a correctly formatted v2 packet signed with the WRONG key
//   tamper    a genuine signed packet with one field altered after signing
//   replay    one captured genuine packet sent again and again
//   flood     a burst of random datagrams
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/secure_packet.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
void usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s --attack forge|wrongkey|tamper|replay|flood [--port N] [--count N]\n"
        "          [--key-file FILE] [--key-id N]\n"
        "  --attack A      which attack to run (required)\n"
        "  --port N        target ground station UDP port on localhost (default 5000)\n"
        "  --count N       how many datagrams to send (default 20, max 100000)\n"
        "  --key-file F    the REAL key: needed for tamper/replay, to produce one genuine packet\n"
        "                  that the attacker is assumed to have captured off the wire\n"
        "  --key-id N      key id to claim (default 1)\n", prog);
}
bool parse_num(const char* s, double& out) {
    char* end = nullptr;
    out = std::strtod(s, &end);
    return end != s && *end == '\0';
}
Telemetry fake(std::uint32_t seq, double battery) {
    Telemetry t;
    t.sequence = seq;
    t.timestamp_ms = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    t.battery_pct = battery; t.temperature_c = 20; t.cpu_pct = 25; t.signal_dbm = -90;
    return t;
}
}  // namespace

int main(int argc, char** argv) {
    std::string attack, key_path;
    double port = 5000, count = 20, key_id = 1;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        if (!std::strcmp(argv[i], "--attack") || !std::strcmp(argv[i], "--key-file")) {
            const bool is_attack = !std::strcmp(argv[i], "--attack");
            if (i + 1 >= argc) { usage(argv[0]); return 2; }
            (is_attack ? attack : key_path) = argv[++i];
            continue;
        }
        double* target = nullptr;
        if (!std::strcmp(argv[i], "--port")) target = &port;
        else if (!std::strcmp(argv[i], "--count")) target = &count;
        else if (!std::strcmp(argv[i], "--key-id")) target = &key_id;
        if (!target || i + 1 >= argc || !parse_num(argv[++i], *target)) { usage(argv[0]); return 2; }
    }
    if (port < 1 || port > 65535 || count < 1 || count > 100000 || key_id < 0 || key_id > 255 || key_id != static_cast<int>(key_id)) {
        std::fprintf(stderr, "error: argument out of range\n");
        usage(argv[0]);
        return 2;
    }
    const bool known = attack == "forge" || attack == "wrongkey" || attack == "tamper" || attack == "replay" || attack == "flood";
    if (!known) { std::fprintf(stderr, "error: unknown or missing --attack\n"); usage(argv[0]); return 2; }

    Key real;
    real.id = static_cast<std::uint8_t>(key_id);
    if (attack == "tamper" || attack == "replay") {
        if (key_path.empty()) { std::fprintf(stderr, "error: --attack %s needs --key-file (to model a captured genuine packet)\n", attack.c_str()); return 2; }
        auto kb = load_key_file(key_path);
        if (!kb) { std::fprintf(stderr, "error: %s\n", kb.error().message.c_str()); return 1; }
        real.bytes = std::move(kb.value());
    }

    auto sock = UdpSocket::create();
    if (!sock) { std::fprintf(stderr, "error: %s\n", sock.error().message.c_str()); return 1; }
    const auto dst = static_cast<std::uint16_t>(port);
    const long n = static_cast<long>(count);
    std::mt19937 rng(0xBADC0DE);
    long sent = 0;

    std::vector<std::uint8_t> captured;  // for replay: one genuine packet, fixed counter
    if (attack == "replay") captured = seal(fake(1, 80), real, 1ULL << 62).value();

    for (long i = 0; i < n; ++i) {
        std::vector<std::uint8_t> pkt;
        if (attack == "forge") {
            pkt = serialize(fake(static_cast<std::uint32_t>(i), 1.0)).value();     // claims 1% battery
        } else if (attack == "wrongkey") {
            Key bad{real.id, std::vector<std::uint8_t>(32, static_cast<std::uint8_t>(0x11 + i % 200))};
            pkt = seal(fake(static_cast<std::uint32_t>(i), 1.0), bad, (1ULL << 62) + static_cast<std::uint64_t>(i)).value();
        } else if (attack == "tamper") {
            pkt = seal(fake(static_cast<std::uint32_t>(i), 80), real, (1ULL << 62) + static_cast<std::uint64_t>(i)).value();
            pkt[18] = 0x00; pkt[19] = 0x64;                                         // battery -> 1.00% after signing
        } else if (attack == "replay") {
            pkt = captured;
        } else {  // flood
            pkt.resize(1 + rng() % 200);
            for (auto& b : pkt) b = static_cast<std::uint8_t>(rng());
        }
        if (sock.value().send_to_loopback(dst, pkt)) ++sent;
        if (attack != "flood") std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    std::printf("rogue_sender: %s: sent %ld datagrams to 127.0.0.1:%d\n", attack.c_str(), sent, static_cast<int>(port));
    return 0;
}
