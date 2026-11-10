#include "orbitguard/packet_codec.hpp"

#include <cmath>

#include "orbitguard/byte_io.hpp"
#include "orbitguard/crc16.hpp"

namespace orbitguard {

const char* to_string(CodecError e) {
    switch (e) {
        case CodecError::TooShort: return "packet too short";
        case CodecError::BadMagic: return "bad magic";
        case CodecError::UnsupportedVersion: return "unsupported protocol version";
        case CodecError::UnknownType: return "unknown packet type";
        case CodecError::LengthMismatch: return "length mismatch";
        case CodecError::CrcMismatch: return "CRC mismatch";
        case CodecError::FieldOutOfRange: return "field out of range";
        case CodecError::InvalidValue: return "invalid value";
    }
    return "unknown error";
}

namespace {

bool in_range(double v, double lo, double hi) { return std::isfinite(v) && v >= lo && v <= hi; }

// Round to 0.01 units. Range was checked first so the cast cannot overflow.
std::int32_t to_centi(double v) { return static_cast<std::int32_t>(std::lround(v * 100.0)); }

}  // namespace

EncodeResult serialize(const Telemetry& t) {
    using namespace limits;
    if (!in_range(t.battery_pct, kBatteryMin, kBatteryMax) ||
        !in_range(t.temperature_c, kTempMin, kTempMax) ||
        !in_range(t.cpu_pct, kCpuMin, kCpuMax) ||
        !in_range(t.signal_dbm, kSignalMin, kSignalMax))
        return CodecError::InvalidValue;

    ByteWriter w;
    w.u16(kMagic);
    w.u8(kProtocolVersion);
    w.u8(kTypeTelemetry);
    w.u16(static_cast<std::uint16_t>(kTelemetryPayloadSize));
    w.u32(t.sequence);
    w.u64(t.timestamp_ms);
    w.u16(static_cast<std::uint16_t>(to_centi(t.battery_pct)));
    w.i16(static_cast<std::int16_t>(to_centi(t.temperature_c)));
    w.u16(static_cast<std::uint16_t>(to_centi(t.cpu_pct)));
    w.i16(static_cast<std::int16_t>(to_centi(t.signal_dbm)));
    w.u16(crc16_ccitt(w.bytes().data(), w.bytes().size()));
    return w.take();
}

DecodeResult deserialize(const std::uint8_t* data, std::size_t size) {
    // Order matters: cheapest and most identifying checks first, and the CRC
    // is verified before any payload field is trusted.
    if (data == nullptr || size < kHeaderSize + kCrcSize) return CodecError::TooShort;

    ByteReader r(data, size);
    if (r.u16() != kMagic) return CodecError::BadMagic;
    if (r.u8() != kProtocolVersion) return CodecError::UnsupportedVersion;
    if (r.u8() != kTypeTelemetry) return CodecError::UnknownType;
    const std::uint16_t len = r.u16();
    if (len != kTelemetryPayloadSize || size != kHeaderSize + len + kCrcSize)
        return CodecError::LengthMismatch;

    const std::size_t crc_off = kHeaderSize + len;
    const std::uint16_t expected = crc16_ccitt(data, crc_off);
    const std::uint16_t actual = static_cast<std::uint16_t>((data[crc_off] << 8) | data[crc_off + 1]);
    if (expected != actual) return CodecError::CrcMismatch;

    Telemetry t;
    t.sequence = r.u32();
    t.timestamp_ms = r.u64();
    const std::uint16_t batt = r.u16();
    const std::int16_t temp = r.i16();
    const std::uint16_t cpu = r.u16();
    const std::int16_t sig = r.i16();
    if (r.failed()) return CodecError::TooShort;  // defensive; sizes already checked

    t.battery_pct = batt / 100.0;
    t.temperature_c = temp / 100.0;
    t.cpu_pct = cpu / 100.0;
    t.signal_dbm = sig / 100.0;

    using namespace limits;
    if (!in_range(t.battery_pct, kBatteryMin, kBatteryMax) ||
        !in_range(t.temperature_c, kTempMin, kTempMax) ||
        !in_range(t.cpu_pct, kCpuMin, kCpuMax) ||
        !in_range(t.signal_dbm, kSignalMin, kSignalMax))
        return CodecError::FieldOutOfRange;

    return t;
}

}  // namespace orbitguard
