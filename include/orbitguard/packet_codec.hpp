#pragma once
// Wire format, version 1. All integers big-endian.
//
//  offset size field
//  ------ ---- -----------------------------------------------
//   0     2    magic            0x4F47 ("OG")
//   2     1    version          1
//   3     1    type             1 = telemetry
//   4     2    payload_length   20 for telemetry v1
//   6     4    sequence         u32
//  10     8    timestamp_ms     u64, ms since Unix epoch
//  18     2    battery          u16, 0.01 %    (0..10000)
//  20     2    temperature      i16, 0.01 C    (-10000..15000)
//  22     2    cpu              u16, 0.01 %    (0..10000)
//  24     2    signal           i16, 0.01 dBm  (-20000..5000)
//  26     2    crc16            CRC-16/CCITT-FALSE over bytes [0, 26)
//
// Total: 28 bytes.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "orbitguard/result.hpp"
#include "orbitguard/telemetry.hpp"

namespace orbitguard {

constexpr std::uint16_t kMagic = 0x4F47;
constexpr std::uint8_t kProtocolVersion = 1;
constexpr std::uint8_t kTypeTelemetry = 1;
constexpr std::size_t kHeaderSize = 6;
constexpr std::size_t kTelemetryPayloadSize = 20;
constexpr std::size_t kCrcSize = 2;
constexpr std::size_t kTelemetryPacketSize = kHeaderSize + kTelemetryPayloadSize + kCrcSize;

enum class CodecError {
    TooShort,          // fewer bytes than a minimal packet
    BadMagic,          // not an OrbitGuard packet
    UnsupportedVersion,
    UnknownType,
    LengthMismatch,    // payload_length disagrees with type or datagram size
    CrcMismatch,       // corrupted in transit
    FieldOutOfRange,   // decoded value outside physical limits
    InvalidValue       // encode only: NaN / infinity / out of range input
};

const char* to_string(CodecError e);

using EncodeResult = Result<std::vector<std::uint8_t>, CodecError>;
using DecodeResult = Result<Telemetry, CodecError>;

EncodeResult serialize(const Telemetry& t);
DecodeResult deserialize(const std::uint8_t* data, std::size_t size);
inline DecodeResult deserialize(const std::vector<std::uint8_t>& v) {
    return deserialize(v.data(), v.size());
}

}  // namespace orbitguard
