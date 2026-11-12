#include "orbitguard/replay.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <thread>

namespace orbitguard {

bool ReplayOptions::valid() const {
    return std::isfinite(speed) && speed > 0.0 && std::isfinite(max_gap_ms) && max_gap_ms >= 0.0;
}

Result<ReplayResult, NetError> replay(RecordReader& reader, UdpSocket& socket, std::uint16_t port,
                                      const ReplayOptions& options, const std::function<bool()>& should_stop) {
    using clock = std::chrono::steady_clock;
    if (!options.valid()) return NetError{0, "invalid replay options (speed must be > 0)"};

    ReplayResult result;
    bool have_prev = false;
    std::uint64_t prev_rx = 0;
    auto due = clock::now();

    for (;;) {
        if (should_stop && should_stop()) { result.stopped = true; return result; }

        auto rec = reader.next();
        if (!rec) { result.end = rec.error(); return result; }
        const Record& r = rec.value();

        if (have_prev) {
            const double gap_ms = r.rx_time_ms > prev_rx ? static_cast<double>(r.rx_time_ms - prev_rx) : 0.0;
            double wait_ms = gap_ms / options.speed;
            if (options.max_gap_ms > 0.0) wait_ms = std::min(wait_ms, options.max_gap_ms);
            due += std::chrono::duration_cast<clock::duration>(std::chrono::duration<double, std::milli>(wait_ms));
        }
        have_prev = true;
        prev_rx = std::max(prev_rx, r.rx_time_ms);

        for (auto now = clock::now(); now < due; now = clock::now()) {
            if (should_stop && should_stop()) { result.stopped = true; return result; }
            std::this_thread::sleep_for(std::min<clock::duration>(due - now, std::chrono::milliseconds(50)));
        }

        auto sent = socket.send_to_loopback(port, r.bytes);
        if (!sent) return sent.error();
        ++result.sent;
    }
}

}  // namespace orbitguard
