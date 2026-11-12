#pragma once
// Authenticated telemetry (wire format version 2).
//
//   [ 28 bytes  v1 telemetry packet, with its version byte set to 2 and its CRC recomputed ]
//   [  1 byte   key_id                                                                       ]
//   [  8 bytes  counter   u64, strictly increasing per key, never reused                      ]
//   [ 16 bytes  tag       HMAC-SHA256 over every preceding byte, truncated to 128 bits        ]
//                                                                                     = 53 bytes
//
// The CRC stays as a cheap filter for line noise. Authentication, not the CRC, decides
// whether a packet is accepted: the tag covers the version, key id and counter too, so no
// field can be altered without invalidating it, and a packet is verified BEFORE any of its
// contents are used. The counter (not the 32-bit sequence number, which wraps and legitimately
// restarts) is what replay protection keys on.
//
// What this does and does not give you (see docs/THREAT_MODEL.md):
//   + forgery resistance and tamper detection against anyone without the key
//   + replay rejection within a 64-packet window
//   - no confidentiality (telemetry is readable on the wire)
//   - a shared symmetric key: whoever holds it can forge, so it must be protected on both ends
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/result.hpp"

namespace orbitguard {

constexpr std::uint8_t kSecureVersion = 2;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kSecureTrailerSize = 1 + 8 + kTagSize;
constexpr std::size_t kSecurePacketSize = kTelemetryPacketSize + kSecureTrailerSize;  // 53
constexpr std::size_t kMinKeySize = 16;  // 128-bit minimum

enum class SecureError {
    NoKeyForId,       // key_id is not one we hold
    TooShort,         // not enough bytes to be a secure packet
    BadTag,           // authentication failed: forged, tampered, wrong key, or corrupted
    Replay,           // counter already seen
    TooOld,           // counter is older than the replay window
    TooFarAhead,      // counter jumps implausibly far ahead (refused so it cannot lock out the real sender)
    Malformed,        // authenticated, but the inner telemetry is invalid
    InvalidKey        // encode only: key too short
};
const char* to_string(SecureError e);

struct Key {
    std::uint8_t id = 0;
    std::vector<std::uint8_t> bytes;
    bool valid() const { return bytes.size() >= kMinKeySize; }
};

// Sliding-window replay detector for one key. Only call accept() with counters from packets
// that already passed authentication, otherwise an attacker could advance the window.
class ReplayWindow {
public:
    static constexpr std::uint64_t kSize = 64;
    // How far ahead of the highest counter seen a new counter may be. Without a bound, one
    // authentic packet with a huge counter would push the window so far forward that every
    // legitimate packet afterwards looked "too old", locking the real sender out. The default
    // (one day at 1000 ticks per millisecond) allows any realistic sender reboot gap.
    static constexpr std::uint64_t kMaxJump = 86400ULL * 1000ULL * 1000ULL;
    enum class Verdict { Fresh, Replay, TooOld, TooFarAhead };

    // Checks without recording.
    Verdict check(std::uint64_t counter) const;
    // Checks and, if fresh, records.
    Verdict accept(std::uint64_t counter);

    bool empty() const { return !any_; }
    std::uint64_t highest() const { return highest_; }

private:
    bool any_ = false;
    std::uint64_t highest_ = 0;
    std::uint64_t mask_ = 0;  // bit i set => counter (highest_ - i) was seen
};

// Builds an authenticated packet. Fails (InvalidKey) if the key is too short, or the telemetry
// is out of range.
Result<std::vector<std::uint8_t>, SecureError> seal(const Telemetry& t, const Key& key, std::uint64_t counter);

// What a successful open() yields.
struct Opened {
    Telemetry telemetry;
    std::uint8_t key_id = 0;
    std::uint64_t counter = 0;
};

// Verifies and decodes. Does NOT touch replay state; the caller records the counter with
// ReplayWindow::accept only after this succeeds (see KeyRing for the combined operation).
Result<Opened, SecureError> open(const std::uint8_t* data, std::size_t size, const std::vector<Key>& keys);

// Holds keys and a replay window per key; the single entry point a receiver should use.
class KeyRing {
public:
    // Adds a key. Returns false if it is too short or its id is already present.
    bool add(Key key);
    bool empty() const { return keys_.empty(); }

    // Verify the tag, then check and record the counter. The window moves only on success.
    Result<Opened, SecureError> receive(const std::uint8_t* data, std::size_t size);

private:
    std::vector<Key> keys_;
    std::vector<ReplayWindow> windows_;
};

// True if the datagram's version byte says it is a v2 (authenticated) packet.
bool looks_secure(const std::uint8_t* data, std::size_t size);

// Loads a key from a text file containing hex (whitespace ignored). Refuses a file that is
// readable by group/others, or a key shorter than kMinKeySize.
struct KeyLoadError { std::string message; };
Result<std::vector<std::uint8_t>, KeyLoadError> load_key_file(const std::string& path);
std::string to_hex(const std::uint8_t* data, std::size_t size);

}  // namespace orbitguard
