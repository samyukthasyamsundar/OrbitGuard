#pragma once
// Re-sends a recording over UDP with its original pacing.
#include <cstdint>
#include <functional>

#include "orbitguard/recording.hpp"
#include "orbitguard/udp_socket.hpp"

namespace orbitguard {

struct ReplayOptions {
    double speed = 1.0;            // 2.0 = twice as fast; must be finite and > 0
    double max_gap_ms = 5000.0;    // a pause longer than this (after scaling) is shortened to it; 0 = never shorten
    bool valid() const;
};

struct ReplayResult {
    std::uint64_t sent = 0;
    bool stopped = false;           // ended early because should_stop() returned true
    ReadEnd end = ReadEnd::Eof;     // why reading stopped (Eof = the whole file was replayed)
};

// Sends each record to 127.0.0.1:port. Datagrams are sent byte-for-byte as recorded,
// including ones that were invalid when first received. A record whose time is not
// later than the previous one is sent immediately (the clock never runs backwards
// here). `should_stop` is polled between datagrams and while waiting.
Result<ReplayResult, NetError> replay(RecordReader& reader, UdpSocket& socket, std::uint16_t port,
                                      const ReplayOptions& options, const std::function<bool()>& should_stop);

}  // namespace orbitguard
