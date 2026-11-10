#include <gtest/gtest.h>

#include <cstring>

#include "orbitguard/crc16.hpp"

using namespace orbitguard;

TEST(Crc16, StandardCheckValue) {
    const char* s = "123456789";
    EXPECT_EQ(crc16_ccitt(reinterpret_cast<const std::uint8_t*>(s), std::strlen(s)), 0x29B1);
}

TEST(Crc16, EmptyInputIsInitValue) { EXPECT_EQ(crc16_ccitt(nullptr, 0), 0xFFFF); }

TEST(Crc16, DetectsSingleBitFlip) {
    std::uint8_t a[4] = {1, 2, 3, 4}, b[4] = {1, 2, 3, 4};
    b[2] ^= 0x01;
    EXPECT_NE(crc16_ccitt(a, 4), crc16_ccitt(b, 4));
}
