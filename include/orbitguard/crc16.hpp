#pragma once
#include <cstddef>
#include <cstdint>

namespace orbitguard {

// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, no xorout).
// Check value for ASCII "123456789" is 0x29B1.
std::uint16_t crc16_ccitt(const std::uint8_t* data, std::size_t size);

}  // namespace orbitguard
