// Portable fuzz driver: seeded random + mutation-based inputs, no libFuzzer needed.
// Less powerful than coverage-guided fuzzing (it cannot learn which inputs reach new code), but it
// runs anywhere and is deterministic for a given seed, so a failure can be reproduced exactly.
//
//   fuzz_driver --target NAME [--iterations N] [--seed N] [--max-size N]
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "orbitguard/crc16.hpp"
#include "orbitguard/packet_codec.hpp"
#include "orbitguard/secure_packet.hpp"
#include "targets.hpp"

using namespace orbitguard;
using Bytes = std::vector<std::uint8_t>;

namespace {

Bytes valid_v1() {
    Telemetry t;
    t.sequence = 1234; t.timestamp_ms = 1700000000000ULL;
    t.battery_pct = 80; t.temperature_c = 21.5; t.cpu_pct = 33; t.signal_dbm = -90;
    return serialize(t).value();
}
Bytes valid_v2() {
    Telemetry t;
    t.sequence = 1234; t.timestamp_ms = 1700000000000ULL;
    t.battery_pct = 80; t.temperature_c = 21.5; t.cpu_pct = 33; t.signal_dbm = -90;
    return seal(t, Key{1, Bytes(32, 0x5A)}, 99).value();   // genuinely valid under the fuzz key
}
Bytes str(const std::string& s) { return Bytes(s.begin(), s.end()); }
Bytes valid_http() { return str("GET /api/telemetry?n=5 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n"); }
Bytes valid_recording() {
    return {0x4F, 0x47, 0x52, 0x43, 0, 1, 0, 0,  0, 0, 0, 0, 0, 0, 0, 1, 0, 3, 'a', 'b', 'c',
            0, 0, 0, 0, 0, 0, 0, 2, 0, 0};
}

Bytes mutate(Bytes b, std::mt19937_64& rng, std::size_t max_size) {
    const int rounds = 1 + static_cast<int>(rng() % 4);
    for (int r = 0; r < rounds; ++r) {
        switch (rng() % 8) {
            case 0: if (!b.empty()) b[rng() % b.size()] ^= static_cast<std::uint8_t>(1u << (rng() % 8)); break;   // flip a bit
            case 1: if (!b.empty()) b[rng() % b.size()] = static_cast<std::uint8_t>(rng()); break;                // random byte
            case 2: if (!b.empty()) b.resize(rng() % (b.size() + 1)); break;                                      // truncate
            case 3: if (b.size() < max_size) b.insert(b.begin() + static_cast<std::ptrdiff_t>(rng() % (b.size() + 1)), static_cast<std::uint8_t>(rng())); break;
            case 4: if (!b.empty()) b.erase(b.begin() + static_cast<std::ptrdiff_t>(rng() % b.size())); break;
            case 5: if (!b.empty()) { const std::size_t i = rng() % b.size(); b[i] = (rng() & 1) ? 0x00 : 0xFF; } break;  // boundary byte
            case 6: if (b.size() >= 2) { const std::size_t i = rng() % (b.size() - 1); std::swap(b[i], b[i + 1]); } break;
            case 7: { const std::size_t n = rng() % 32; for (std::size_t k = 0; k < n && b.size() < max_size; ++k) b.push_back(static_cast<std::uint8_t>(rng())); } break;
        }
    }
    if (b.size() > max_size) b.resize(max_size);
    return b;
}

Bytes random_bytes(std::mt19937_64& rng, std::size_t max_size) {
    Bytes b(rng() % (max_size + 1));
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    return b;
}

// After mutating a v1 packet, recompute its CRC so the input gets PAST the integrity check and
// exercises the field-range and consistency logic behind it (a plain mutation breaks the CRC almost
// every time, so those paths would otherwise be reached only by luck).
Bytes refresh_v1_crc(Bytes b) {
    if (b.size() == kTelemetryPacketSize) {
        const std::uint16_t c = crc16_ccitt(b.data(), b.size() - 2);
        b[b.size() - 2] = static_cast<std::uint8_t>(c >> 8);
        b[b.size() - 1] = static_cast<std::uint8_t>(c);
    }
    return b;
}

}  // namespace

int main(int argc, char** argv) {
    std::string target;
    double iterations = 200000, seed = 1, max_size = 600;
    for (int i = 1; i < argc; ++i) {
        double* d = nullptr;
        if (!std::strcmp(argv[i], "--target") && i + 1 < argc) { target = argv[++i]; continue; }
        if (!std::strcmp(argv[i], "--iterations")) d = &iterations;
        else if (!std::strcmp(argv[i], "--seed")) d = &seed;
        else if (!std::strcmp(argv[i], "--max-size")) d = &max_size;
        char* end = nullptr;
        if (!d || i + 1 >= argc) { std::fprintf(stderr, "bad argument: %s\n", argv[i]); return 2; }
        *d = std::strtod(argv[++i], &end);
        if (end == argv[i] || *end != '\0' || *d < 0) { std::fprintf(stderr, "bad number: %s\n", argv[i]); return 2; }
    }

    void (*fn)(const std::uint8_t*, std::size_t) = nullptr;
    std::vector<Bytes> corpus;
    if (target == "packet_decoder") { fn = fuzz::packet_decoder; corpus = {valid_v1()}; }
    else if (target == "secure_open") { fn = fuzz::secure_open; corpus = {valid_v2(), valid_v1()}; }
    else if (target == "http_head") { fn = fuzz::http_head; corpus = {valid_http()}; }
    else if (target == "recording_reader") { fn = fuzz::recording_reader; corpus = {valid_recording()}; }
    else { std::fprintf(stderr, "usage: fuzz_driver --target packet_decoder|secure_open|http_head|recording_reader [--iterations N] [--seed N] [--max-size N]\n"); return 2; }

    std::mt19937_64 rng(static_cast<std::uint64_t>(seed));
    const std::size_t cap = static_cast<std::size_t>(max_size);
    const auto t0 = std::chrono::steady_clock::now();
    const long long n = static_cast<long long>(iterations);
    // Printed BEFORE the run: if an input crashes the process, this line is how you reproduce it.
    std::printf("fuzz_driver: %s: starting, seed %.0f, %lld inputs (reproduce with --seed %.0f)\n",
                target.c_str(), seed, n, seed);
    std::fflush(stdout);
    for (long long it = 0; it < n; ++it) {
        Bytes input;
        switch (rng() % 4) {
            case 0: input = random_bytes(rng, cap); break;                                  // pure noise
            case 1: input = corpus[rng() % corpus.size()]; break;                           // the valid seed untouched
            case 2: input = mutate(corpus[rng() % corpus.size()], rng, cap); break;         // mutated valid input
            default: {                                                                      // mutated, CRC repaired
                input = mutate(corpus[rng() % corpus.size()], rng, cap);
                if (target == "packet_decoder") input = refresh_v1_crc(std::move(input));
                break;
            }
        }
        fn(input.data(), input.size());
    }
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("fuzz_driver: %s: %lld inputs, seed %.0f, %.1fs (%.0f/s), no crashes or invariant violations\n",
                target.c_str(), n, seed, secs, secs > 0 ? static_cast<double>(n) / secs : 0.0);
    return 0;
}
