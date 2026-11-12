// SHA-256 and HMAC-SHA256 against published vectors (FIPS 180-4 / NIST, RFC 4231).
// Values were cross-checked against Python's hashlib/hmac, an independent implementation.
#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#include "orbitguard/sha256.hpp"

using namespace orbitguard;

namespace {
std::string hex(const Sha256Digest& d) {
    std::string s;
    char b[3];
    for (std::uint8_t x : d) { std::snprintf(b, sizeof b, "%02x", x); s += b; }
    return s;
}
std::vector<std::uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }
Sha256Digest hash_str(const std::string& s) { return sha256(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); }
Sha256Digest mac(const std::vector<std::uint8_t>& k, const std::vector<std::uint8_t>& d) {
    return hmac_sha256(k.data(), k.size(), d.data(), d.size());
}
}  // namespace

TEST(Sha256, EmptyString) {
    EXPECT_EQ(hex(sha256(nullptr, 0)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
TEST(Sha256, Abc) {
    EXPECT_EQ(hex(hash_str("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
TEST(Sha256, TwoBlockNistVector) {
    EXPECT_EQ(hex(hash_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}
TEST(Sha256, OneMillionA) {
    Sha256 s;
    const std::string chunk(1000, 'a');
    for (int i = 0; i < 1000; ++i) s.update(reinterpret_cast<const std::uint8_t*>(chunk.data()), chunk.size());
    EXPECT_EQ(hex(s.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}
TEST(Sha256, PaddingBoundaries) {  // 55/56 and 63/64/65 bytes straddle the length-field and block edges
    EXPECT_EQ(hex(hash_str(std::string(55, 'x'))), "d5e285683cd4efc02d021a5c62014694958901005d6f71e89e0989fac77e4072");
    EXPECT_EQ(hex(hash_str(std::string(56, 'x'))), "04c26261370ee7541549d16dee320c723e3fd14671e66a099afe0a377c16888e");
    EXPECT_EQ(hex(hash_str(std::string(63, 'x'))), "75220b47218278e656f2013bb8f0c455a25eaf01e86c64924e9d48d89776d6f2");
    EXPECT_EQ(hex(hash_str(std::string(64, 'x'))), "7ce100971f64e7001e8fe5a51973ecdfe1ced42befe7ee8d5fd6219506b5393c");
    EXPECT_EQ(hex(hash_str(std::string(65, 'x'))), "9537c5fdf120482f7d58d25e9ed583f52c02b4e304ea814db1633ad565aed7e9");
}
TEST(Sha256, IncrementalMatchesOneShotForEverySplit) {
    const std::string msg(200, 'q');
    const auto want = hash_str(msg);
    const auto* p = reinterpret_cast<const std::uint8_t*>(msg.data());
    for (std::size_t split = 0; split <= msg.size(); ++split) {
        Sha256 s;
        s.update(p, split);
        s.update(p + split, msg.size() - split);
        ASSERT_EQ(s.finish(), want) << "split " << split;
    }
}
TEST(Sha256, ResetAllowsReuse) {
    Sha256 s;
    s.update(reinterpret_cast<const std::uint8_t*>("junk"), 4);
    s.finish();
    s.reset();
    s.update(reinterpret_cast<const std::uint8_t*>("abc"), 3);
    EXPECT_EQ(hex(s.finish()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(HmacSha256, Rfc4231Case1) {
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(20, 0x0b), bytes("Hi There"))),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}
TEST(HmacSha256, Rfc4231Case2ShortKey) {
    EXPECT_EQ(hex(mac(bytes("Jefe"), bytes("what do ya want for nothing?"))),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}
TEST(HmacSha256, Rfc4231Case3) {
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(20, 0xaa), std::vector<std::uint8_t>(50, 0xdd))),
              "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}
TEST(HmacSha256, Rfc4231Case4) {
    std::vector<std::uint8_t> key;
    for (std::uint8_t i = 1; i <= 25; ++i) key.push_back(i);
    EXPECT_EQ(hex(mac(key, std::vector<std::uint8_t>(50, 0xcd))),
              "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
}
TEST(HmacSha256, Rfc4231Case6KeyLongerThanBlock) {
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(131, 0xaa), bytes("Test Using Larger Than Block-Size Key - Hash Key First"))),
              "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}
TEST(HmacSha256, Rfc4231Case7LongKeyAndData) {
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(131, 0xaa),
                      bytes("This is a test using a larger than block-size key and a larger than block-size data. "
                            "The key needs to be hashed before being used by the HMAC algorithm."))),
              "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}
TEST(HmacSha256, KeyLengthBoundaryAtBlockSize) {
    // RFC 2104: keys up to and including the 64-byte block size are used as-is; longer keys are
    // hashed first. A key of exactly 64 bytes is the case an off-by-one would get wrong.
    // Expected values come from Python's hmac module (independent of this code).
    const auto msg = bytes("boundary");
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(63, 'k'), msg)), "39a2a2bbece85d5123e0da59869dd103ef466596c886acbab684e93c772eedc6");
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(64, 'k'), msg)), "5a1af747e37d07140ec0b58fa01f85d1b3f0aeef2f6719091e9517e8b474a978");
    EXPECT_EQ(hex(mac(std::vector<std::uint8_t>(65, 'k'), msg)), "ef3f1f0b6c378507c6cd325246f1e48412bbceab9e755d485dc639946cfe3785");
}
TEST(HmacSha256, EmptyKeyIsValid) {
    EXPECT_EQ(hex(hmac_sha256(nullptr, 0, reinterpret_cast<const std::uint8_t*>("data"), 4)),
              "e528c4d99e6177f5841f712a143b90843299a4aa181a06501422d9ca862bd2a5");
}
TEST(HmacSha256, DifferentKeysAndMessagesGiveDifferentTags) {
    const auto k1 = bytes("key-one"), k2 = bytes("key-two"), m1 = bytes("message"), m2 = bytes("messagf");
    EXPECT_NE(mac(k1, m1), mac(k2, m1));
    EXPECT_NE(mac(k1, m1), mac(k1, m2));
}

TEST(ConstantTimeEqual, EqualAndEveryPositionOfDifference) {
    std::uint8_t a[32], b[32];
    for (int i = 0; i < 32; ++i) a[i] = b[i] = static_cast<std::uint8_t>(i);
    EXPECT_TRUE(constant_time_equal(a, b, 32));
    for (int i = 0; i < 32; ++i) {
        b[i] ^= 0x01;
        EXPECT_FALSE(constant_time_equal(a, b, 32)) << "differs at " << i;
        b[i] ^= 0x01;
    }
    EXPECT_TRUE(constant_time_equal(a, b, 0));
}
