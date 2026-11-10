#include <gtest/gtest.h>

#include "orbitguard/byte_io.hpp"

using namespace orbitguard;

TEST(ByteIo, BigEndianLayout) {
    ByteWriter w;
    w.u16(0x1234);
    w.u32(0xA1B2C3D4);
    w.u64(0x0102030405060708ULL);
    const std::vector<std::uint8_t> expect = {0x12, 0x34, 0xA1, 0xB2, 0xC3, 0xD4,
                                              1, 2, 3, 4, 5, 6, 7, 8};
    EXPECT_EQ(w.bytes(), expect);
}

TEST(ByteIo, RoundTripIncludingNegative) {
    ByteWriter w;
    w.i16(-1234);
    w.u8(200);
    ByteReader r(w.bytes().data(), w.bytes().size());
    EXPECT_EQ(r.i16(), -1234);
    EXPECT_EQ(r.u8(), 200);
    EXPECT_FALSE(r.failed());
    EXPECT_EQ(r.remaining(), 0u);
}

TEST(ByteIo, ReadPastEndFailsSafely) {
    const std::uint8_t d[3] = {1, 2, 3};
    ByteReader r(d, 3);
    EXPECT_EQ(r.u32(), 0u);
    EXPECT_TRUE(r.failed());
    EXPECT_EQ(r.u8(), 0);  // failure is sticky
}
