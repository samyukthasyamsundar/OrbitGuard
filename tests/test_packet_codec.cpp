#include <gtest/gtest.h>

#include <cmath>
#include <limits>

#include "orbitguard/crc16.hpp"
#include "orbitguard/packet_codec.hpp"

using namespace orbitguard;

namespace {
Telemetry sample() {
    Telemetry t;
    t.sequence = 123456;
    t.timestamp_ms = 1700000000123ULL;
    t.battery_pct = 87.65;
    t.temperature_c = -12.34;
    t.cpu_pct = 42.5;
    t.signal_dbm = -97.25;
    return t;
}

// Recompute the CRC after tampering so we can test checks that come after it.
void fix_crc(std::vector<std::uint8_t>& p) {
    const std::uint16_t c = crc16_ccitt(p.data(), p.size() - 2);
    p[p.size() - 2] = static_cast<std::uint8_t>(c >> 8);
    p[p.size() - 1] = static_cast<std::uint8_t>(c);
}
}  // namespace

TEST(PacketCodec, EncodedSizeAndHeader) {
    auto r = serialize(sample());
    ASSERT_TRUE(r.ok());
    const auto& b = r.value();
    ASSERT_EQ(b.size(), kTelemetryPacketSize);
    EXPECT_EQ(kTelemetryPacketSize, 28u);
    EXPECT_EQ(b[0], 0x4F);
    EXPECT_EQ(b[1], 0x47);
    EXPECT_EQ(b[2], kProtocolVersion);
    EXPECT_EQ(b[3], kTypeTelemetry);
}

TEST(PacketCodec, KnownWireBytes) {
    Telemetry t;
    t.sequence = 1;
    t.timestamp_ms = 2;
    t.battery_pct = 100.0;   // 10000 = 0x2710
    t.temperature_c = -1.0;  // -100  = 0xFF9C
    t.cpu_pct = 0.0;
    t.signal_dbm = -1.0;     // 0xFF9C
    auto r = serialize(t);
    ASSERT_TRUE(r.ok());
    const std::vector<std::uint8_t> head = {0x4F, 0x47, 1, 1, 0, 20,
                                            0, 0, 0, 1,
                                            0, 0, 0, 0, 0, 0, 0, 2,
                                            0x27, 0x10, 0xFF, 0x9C, 0x00, 0x00, 0xFF, 0x9C};
    ASSERT_EQ(r.value().size(), head.size() + 2);
    EXPECT_TRUE(std::equal(head.begin(), head.end(), r.value().begin()));
}

TEST(PacketCodec, RoundTrip) {
    const Telemetry in = sample();
    auto enc = serialize(in);
    ASSERT_TRUE(enc.ok());
    auto dec = deserialize(enc.value());
    ASSERT_TRUE(dec.ok());
    const Telemetry& out = dec.value();
    EXPECT_EQ(out.sequence, in.sequence);
    EXPECT_EQ(out.timestamp_ms, in.timestamp_ms);
    EXPECT_NEAR(out.battery_pct, in.battery_pct, 0.005);
    EXPECT_NEAR(out.temperature_c, in.temperature_c, 0.005);
    EXPECT_NEAR(out.cpu_pct, in.cpu_pct, 0.005);
    EXPECT_NEAR(out.signal_dbm, in.signal_dbm, 0.005);
}

TEST(PacketCodec, RoundTripBoundaries) {
    Telemetry lo;
    lo.sequence = 0xFFFFFFFFu;
    lo.timestamp_ms = 0xFFFFFFFFFFFFFFFFULL;
    lo.battery_pct = 0; lo.temperature_c = -100; lo.cpu_pct = 0; lo.signal_dbm = -200;
    Telemetry hi = lo;
    hi.battery_pct = 100; hi.temperature_c = 150; hi.cpu_pct = 100; hi.signal_dbm = 50;
    for (const Telemetry& t : {lo, hi}) {
        auto d = deserialize(serialize(t).value());
        ASSERT_TRUE(d.ok());
        EXPECT_EQ(d.value().sequence, t.sequence);
        EXPECT_EQ(d.value().timestamp_ms, t.timestamp_ms);
        EXPECT_DOUBLE_EQ(d.value().temperature_c, t.temperature_c);
        EXPECT_DOUBLE_EQ(d.value().signal_dbm, t.signal_dbm);
    }
}

TEST(PacketCodec, EncodeRejectsInvalidValues) {
    Telemetry t = sample();
    t.battery_pct = 100.01;
    EXPECT_EQ(serialize(t).error(), CodecError::InvalidValue);
    t = sample();
    t.cpu_pct = -0.01;
    EXPECT_EQ(serialize(t).error(), CodecError::InvalidValue);
    t = sample();
    t.temperature_c = std::numeric_limits<double>::quiet_NaN();
    EXPECT_EQ(serialize(t).error(), CodecError::InvalidValue);
    t = sample();
    t.signal_dbm = std::numeric_limits<double>::infinity();
    EXPECT_EQ(serialize(t).error(), CodecError::InvalidValue);
}

TEST(PacketCodec, RejectsEmptyAndTruncated) {
    EXPECT_EQ(deserialize(nullptr, 0).error(), CodecError::TooShort);
    EXPECT_EQ(deserialize(std::vector<std::uint8_t>{}).error(), CodecError::TooShort);
    auto b = serialize(sample()).value();
    for (std::size_t n = 0; n < b.size(); ++n) {
        auto r = deserialize(b.data(), n);
        ASSERT_FALSE(r.ok()) << "truncated to " << n;
    }
}

TEST(PacketCodec, RejectsTrailingBytes) {
    auto b = serialize(sample()).value();
    b.push_back(0);
    EXPECT_EQ(deserialize(b).error(), CodecError::LengthMismatch);
}

TEST(PacketCodec, RejectsBadMagic) {
    auto b = serialize(sample()).value();
    b[0] = 0x00;
    EXPECT_EQ(deserialize(b).error(), CodecError::BadMagic);
}

TEST(PacketCodec, RejectsUnsupportedVersion) {
    auto b = serialize(sample()).value();
    b[2] = 2;
    EXPECT_EQ(deserialize(b).error(), CodecError::UnsupportedVersion);
}

TEST(PacketCodec, RejectsUnknownType) {
    auto b = serialize(sample()).value();
    b[3] = 9;
    EXPECT_EQ(deserialize(b).error(), CodecError::UnknownType);
}

TEST(PacketCodec, RejectsWrongPayloadLength) {
    auto b = serialize(sample()).value();
    b[5] = 21;
    EXPECT_EQ(deserialize(b).error(), CodecError::LengthMismatch);
}

TEST(PacketCodec, DetectsEverySingleBitCorruption) {
    const auto good = serialize(sample()).value();
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
            auto b = good;
            b[i] ^= static_cast<std::uint8_t>(1u << bit);
            EXPECT_FALSE(deserialize(b).ok()) << "byte " << i << " bit " << bit;
        }
    }
}

TEST(PacketCodec, CrcMismatchReportedForPayloadCorruption) {
    auto b = serialize(sample()).value();
    b[12] ^= 0xFF;
    EXPECT_EQ(deserialize(b).error(), CodecError::CrcMismatch);
}

TEST(PacketCodec, RejectsOutOfRangeFieldEvenWithValidCrc) {
    auto b = serialize(sample()).value();
    b[18] = 0xFF; b[19] = 0xFF;  // battery = 655.35 %
    fix_crc(b);
    EXPECT_EQ(deserialize(b).error(), CodecError::FieldOutOfRange);
}

TEST(PacketCodec, ErrorStringsAreNonEmpty) {
    for (auto e : {CodecError::TooShort, CodecError::BadMagic, CodecError::UnsupportedVersion,
                   CodecError::UnknownType, CodecError::LengthMismatch, CodecError::CrcMismatch,
                   CodecError::FieldOutOfRange, CodecError::InvalidValue})
        EXPECT_GT(std::string(to_string(e)).size(), 0u);
}
