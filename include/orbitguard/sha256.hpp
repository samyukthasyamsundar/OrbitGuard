#pragma once
// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104 / RFC 4231).
//
// Implemented here, from the standards, so the project has no crypto dependency, and
// tested against the published vectors. This is a learning/demonstration implementation:
// it is not hardened against side channels beyond a constant-time compare, and production
// systems should use a vetted library (libsodium, OpenSSL) instead.
#include <array>
#include <cstddef>
#include <cstdint>

namespace orbitguard {

using Sha256Digest = std::array<std::uint8_t, 32>;

class Sha256 {
public:
    Sha256() { reset(); }
    void reset();
    void update(const std::uint8_t* data, std::size_t size);
    Sha256Digest finish();  // the object must be reset() before reuse

private:
    void compress(const std::uint8_t block[64]);
    std::uint32_t h_[8];
    std::uint8_t buf_[64];
    std::size_t buf_len_ = 0;
    std::uint64_t total_bytes_ = 0;
};

Sha256Digest sha256(const std::uint8_t* data, std::size_t size);

// HMAC-SHA256 with a key of any length (longer than 64 bytes is hashed first, per RFC 2104).
Sha256Digest hmac_sha256(const std::uint8_t* key, std::size_t key_size,
                         const std::uint8_t* data, std::size_t size);

// Compares two byte ranges in time that does not depend on where they first differ.
// Returns false immediately if the lengths differ (lengths are public).
bool constant_time_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t size);

}  // namespace orbitguard
