// Security tests: these model attacks (forgery, tampering, replay, downgrade), not just round trips.
#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "orbitguard/crc16.hpp"
#include "orbitguard/secure_packet.hpp"

using namespace orbitguard;

namespace {
Key make_key(std::uint8_t id, std::uint8_t fill, std::size_t len = 32) { return Key{id, std::vector<std::uint8_t>(len, fill)}; }

Telemetry sample(std::uint32_t seq = 7) {
    Telemetry t;
    t.sequence = seq; t.timestamp_ms = 1700000000000ULL;
    t.battery_pct = 80; t.temperature_c = 21.5; t.cpu_pct = 33; t.signal_dbm = -90;
    return t;
}
std::vector<std::uint8_t> sealed(std::uint64_t counter, const Key& k = make_key(1, 0xA5), std::uint32_t seq = 7) {
    return seal(sample(seq), k, counter).value();
}
}  // namespace

// ---------- format ----------
TEST(SecurePacket, SizeAndVersionByte) {
    auto p = sealed(1);
    EXPECT_EQ(p.size(), kSecurePacketSize);
    EXPECT_EQ(kSecurePacketSize, 53u);
    EXPECT_EQ(p[2], kSecureVersion);
    EXPECT_TRUE(looks_secure(p.data(), p.size()));
}

TEST(SecurePacket, RoundTripRecoversTelemetryKeyIdAndCounter) {
    const Key k = make_key(9, 0x42);
    auto o = open(sealed(123456789012345ULL, k).data(), kSecurePacketSize, {k});
    ASSERT_TRUE(o.ok());
    EXPECT_EQ(o.value().key_id, 9);
    EXPECT_EQ(o.value().counter, 123456789012345ULL);
    EXPECT_EQ(o.value().telemetry.sequence, 7u);
    EXPECT_NEAR(o.value().telemetry.temperature_c, 21.5, 0.005);
}

TEST(SecurePacket, V1PacketsAreNotMistakenForSecure) {
    auto v1 = serialize(sample()).value();
    EXPECT_FALSE(looks_secure(v1.data(), v1.size()));
}

TEST(SecurePacket, SealRejectsShortKeyAndInvalidTelemetry) {
    EXPECT_EQ(seal(sample(), make_key(1, 1, 15), 1).error(), SecureError::InvalidKey);
    Telemetry bad = sample();
    bad.battery_pct = 500;
    EXPECT_FALSE(seal(bad, make_key(1, 1), 1).ok());
}

// ---------- forgery and tampering ----------
TEST(SecurePacket, WrongKeyIsRejected) {
    auto p = sealed(1, make_key(1, 0xA5));
    auto o = open(p.data(), p.size(), {make_key(1, 0x5A)});  // same id, different key bytes
    ASSERT_FALSE(o.ok());
    EXPECT_EQ(o.error(), SecureError::BadTag);
}

TEST(SecurePacket, UnknownKeyIdIsRejected) {
    auto p = sealed(1, make_key(1, 0xA5));
    EXPECT_EQ(open(p.data(), p.size(), {make_key(2, 0xA5)}).error(), SecureError::NoKeyForId);
    EXPECT_EQ(open(p.data(), p.size(), {}).error(), SecureError::NoKeyForId);
}

TEST(SecurePacket, EverySingleBitFlipAnywhereIsRejected) {
    const Key k = make_key(1, 0xA5);
    const auto good = sealed(77, k);
    for (std::size_t i = 0; i < good.size(); ++i)
        for (int bit = 0; bit < 8; ++bit) {
            auto b = good;
            b[i] ^= static_cast<std::uint8_t>(1u << bit);
            ASSERT_FALSE(open(b.data(), b.size(), {k}).ok()) << "byte " << i << " bit " << bit << " was accepted";
        }
}

TEST(SecurePacket, AttackerWhoRecomputesTheCrcStillCannotForge) {
    // An attacker who knows the format (but not the key) edits a field and fixes the CRC: the
    // old integrity check passes, the authentication must not.
    const Key k = make_key(1, 0xA5);
    auto p = sealed(5, k);
    p[18] = 0x00; p[19] = 0x01;  // battery := 0.01 %
    // keep the 'inner' CRC consistent, as a forger would:
    std::vector<std::uint8_t> head(p.begin(), p.begin() + 26);
    const std::uint16_t crc = crc16_ccitt(head.data(), head.size());
    p[26] = static_cast<std::uint8_t>(crc >> 8); p[27] = static_cast<std::uint8_t>(crc);
    EXPECT_EQ(open(p.data(), p.size(), {k}).error(), SecureError::BadTag);
}

TEST(SecurePacket, TagFromAnotherPacketCannotBeTransplanted) {
    const Key k = make_key(1, 0xA5);
    auto a = sealed(1, k, 100);
    auto b = sealed(2, k, 200);
    std::copy(b.end() - kTagSize, b.end(), a.end() - kTagSize);  // graft b's tag onto a's body
    EXPECT_EQ(open(a.data(), a.size(), {k}).error(), SecureError::BadTag);
}

TEST(SecurePacket, TruncatedAndExtendedPacketsAreRejected) {
    const Key k = make_key(1, 0xA5);
    auto p = sealed(1, k);
    for (std::size_t n = 0; n < p.size(); ++n) EXPECT_FALSE(open(p.data(), n, {k}).ok()) << n;
    auto longer = p;
    longer.push_back(0);
    EXPECT_FALSE(open(longer.data(), longer.size(), {k}).ok());
    EXPECT_FALSE(open(nullptr, 0, {k}).ok());
}

TEST(SecurePacket, ForgedPacketNeverReachesTheReplayWindow) {
    KeyRing ring;
    ASSERT_TRUE(ring.add(make_key(1, 0xA5)));
    auto forged = sealed(1000000, make_key(1, 0x00));        // attacker's guess at the key, huge counter
    EXPECT_EQ(ring.receive(forged.data(), forged.size()).error(), SecureError::BadTag);
    auto legit = sealed(1, make_key(1, 0xA5));               // must still be accepted: window was not advanced
    EXPECT_TRUE(ring.receive(legit.data(), legit.size()).ok());
}

// ---------- replay window ----------
TEST(ReplayWindow, FreshThenReplay) {
    ReplayWindow w;
    EXPECT_EQ(w.accept(10), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(10), ReplayWindow::Verdict::Replay);
}

TEST(ReplayWindow, OutOfOrderWithinWindowIsAcceptedOnce) {
    ReplayWindow w;
    w.accept(100);
    EXPECT_EQ(w.accept(95), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(95), ReplayWindow::Verdict::Replay);
    EXPECT_EQ(w.accept(100), ReplayWindow::Verdict::Replay);
}

TEST(ReplayWindow, WindowEdge) {
    ReplayWindow w;
    w.accept(100);
    EXPECT_EQ(w.accept(100 - (ReplayWindow::kSize - 1)), ReplayWindow::Verdict::Fresh);   // 63 behind: inside
    EXPECT_EQ(w.accept(100 - ReplayWindow::kSize), ReplayWindow::Verdict::TooOld);        // 64 behind: outside
}

TEST(ReplayWindow, BigJumpForwardForgetsOldButStillRejectsThem) {
    ReplayWindow w;
    for (std::uint64_t c = 1; c <= 10; ++c) w.accept(c);
    EXPECT_EQ(w.accept(1000), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(5), ReplayWindow::Verdict::TooOld);   // replaying an old one after a jump
    EXPECT_EQ(w.accept(1000), ReplayWindow::Verdict::Replay);
}

TEST(ReplayWindow, ShiftBySixtyFourOrMoreDoesNotWrapTheMask) {
    // A shift of >= 64 on a 64-bit mask is undefined behaviour in C++ if written naively.
    ReplayWindow w;
    w.accept(1);
    EXPECT_EQ(w.accept(1 + 64), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(1 + 64 + 64), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(1 + 64), ReplayWindow::Verdict::TooOld);
}

TEST(ReplayWindow, ImplausibleJumpIsRefusedAndDoesNotMoveTheWindow) {
    ReplayWindow w;
    w.accept(1000);
    EXPECT_EQ(w.accept(1000 + ReplayWindow::kMaxJump + 1), ReplayWindow::Verdict::TooFarAhead);
    EXPECT_EQ(w.highest(), 1000u);                                   // untouched
    EXPECT_EQ(w.accept(1001), ReplayWindow::Verdict::Fresh);         // the real sender is unaffected
}

TEST(ReplayWindow, JumpAtExactlyTheLimitIsAllowed) {
    ReplayWindow w;
    w.accept(1000);
    EXPECT_EQ(w.accept(1000 + ReplayWindow::kMaxJump), ReplayWindow::Verdict::Fresh);
}

TEST(ReplayWindow, FirstPacketSetsTheBaselineWhateverItsValue) {
    // Documented limitation: the very first counter is trusted, because there is nothing to
    // compare it with. Protecting that first packet needs state outside this window.
    ReplayWindow w;
    EXPECT_EQ(w.accept(0xFFFFFFFFFFFF0000ULL), ReplayWindow::Verdict::Fresh);
}

TEST(ReplayWindow, CounterZeroAndMaximum) {
    ReplayWindow w;
    EXPECT_EQ(w.accept(0), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.accept(0), ReplayWindow::Verdict::Replay);
    ReplayWindow top;                                                 // the extreme top of the range
    EXPECT_EQ(top.accept(0xFFFFFFFFFFFFFFFFULL), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(top.accept(0xFFFFFFFFFFFFFFFEULL), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(top.accept(0xFFFFFFFFFFFFFFFFULL), ReplayWindow::Verdict::Replay);
}

TEST(ReplayWindow, CheckDoesNotRecord) {
    ReplayWindow w;
    EXPECT_EQ(w.check(5), ReplayWindow::Verdict::Fresh);
    EXPECT_EQ(w.check(5), ReplayWindow::Verdict::Fresh);
    EXPECT_TRUE(w.empty());
}

// ---------- key ring ----------
TEST(KeyRing, ReplayedCapturedPacketIsRejected) {
    KeyRing ring;
    ASSERT_TRUE(ring.add(make_key(1, 0xA5)));
    auto p = sealed(42);
    EXPECT_TRUE(ring.receive(p.data(), p.size()).ok());
    auto again = ring.receive(p.data(), p.size());          // the attacker re-sends the captured bytes
    ASSERT_FALSE(again.ok());
    EXPECT_EQ(again.error(), SecureError::Replay);
}

TEST(KeyRing, StalePacketBeyondWindowIsRejected) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    auto old_pkt = sealed(1);
    auto new_pkt = sealed(500);
    EXPECT_TRUE(ring.receive(new_pkt.data(), new_pkt.size()).ok());
    EXPECT_EQ(ring.receive(old_pkt.data(), old_pkt.size()).error(), SecureError::TooOld);
}

TEST(KeyRing, WindowsAreIndependentPerKey) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.add(make_key(2, 0xB6));
    auto a = sealed(5, make_key(1, 0xA5));
    auto b = sealed(5, make_key(2, 0xB6));                   // same counter, different key
    EXPECT_TRUE(ring.receive(a.data(), a.size()).ok());
    EXPECT_TRUE(ring.receive(b.data(), b.size()).ok());
}

TEST(KeyRing, KeyRotationBothKeysAcceptedUntilOneIsRemoved) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.add(make_key(2, 0xB6));
    auto oldk = sealed(1, make_key(1, 0xA5));
    auto newk = sealed(1, make_key(2, 0xB6));
    EXPECT_TRUE(ring.receive(oldk.data(), oldk.size()).ok());
    EXPECT_TRUE(ring.receive(newk.data(), newk.size()).ok());
}

TEST(KeyRing, RejectsShortAndDuplicateKeys) {
    KeyRing ring;
    EXPECT_FALSE(ring.add(make_key(1, 0xA5, 8)));
    EXPECT_TRUE(ring.add(make_key(1, 0xA5)));
    EXPECT_FALSE(ring.add(make_key(1, 0xFF)));
    EXPECT_TRUE(ring.add(make_key(2, 0xFF)));
}

TEST(KeyRing, OneAuthenticPacketWithAHugeCounterCannotLockOutTheRealSender) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    auto first = sealed(1000);                                       // the real sender establishes the baseline
    EXPECT_TRUE(ring.receive(first.data(), first.size()).ok());
    auto huge = sealed(1ULL << 62);                                  // genuine signature, absurd counter
    EXPECT_EQ(ring.receive(huge.data(), huge.size()).error(), SecureError::TooFarAhead);
    for (std::uint64_t c = 1001; c < 1050; ++c) {                    // the real sender carries on unharmed
        auto p = sealed(c);
        ASSERT_TRUE(ring.receive(p.data(), p.size()).ok()) << "counter " << c;
    }
}

namespace {
// Well-formed secure packet, right key id, but signed with the wrong key: forces a full HMAC to reject.
std::vector<std::uint8_t> badly_signed(std::uint64_t counter) { return sealed(counter, make_key(1, 0x00)); }
}  // namespace

TEST(KeyRing, VerificationBudgetCapsTheHmacWorkFailuresCanForce) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.set_verification_budget(10, 20);                      // 10 failures/s, burst of 20
    int bad_tag = 0, limited = 0;
    for (int i = 0; i < 1000; ++i) {                           // 1000 forgeries inside one millisecond
        auto p = badly_signed(static_cast<std::uint64_t>(i));
        auto r = ring.receive(p.data(), p.size(), 5000);
        ASSERT_FALSE(r.ok());
        (r.error() == SecureError::BadTag ? bad_tag : limited)++;
    }
    EXPECT_EQ(bad_tag, 20);                                    // only the burst was verified
    EXPECT_EQ(limited, 980);                                   // the rest were refused without an HMAC
    EXPECT_EQ(ring.budget_refusals(), 980u);
}

TEST(KeyRing, AuthenticTrafficNeverDrawsDownTheBudget) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.set_verification_budget(1, 3);                        // tiny budget: easy to exhaust if it leaked
    for (std::uint64_t c = 1; c <= 500; ++c) {
        auto p = sealed(c);
        ASSERT_TRUE(ring.receive(p.data(), p.size(), 7000).ok()) << c;   // all at the same instant
    }
    EXPECT_EQ(ring.budget_refusals(), 0u);
}

TEST(KeyRing, WhileTheBudgetIsEmptyGenuinePacketsAreAlsoRefusedThenRecover) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.set_verification_budget(1, 2);
    for (int i = 0; i < 200; ++i) { auto p = badly_signed(static_cast<std::uint64_t>(i)); ring.receive(p.data(), p.size(), 9000); }
    // The budget is now empty. A genuine packet is indistinguishable from a forgery until its tag is
    // checked, so it needs a token too. This is the price of the defence: it trades availability for
    // bounded CPU while an attack is in progress, and recovers once the attack stops.
    auto genuine = sealed(1);
    auto r = ring.receive(genuine.data(), genuine.size(), 9000);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.error(), SecureError::RateLimited);
    auto later = ring.receive(genuine.data(), genuine.size(), 9000 + 5000);   // five seconds later: refilled
    EXPECT_TRUE(later.ok());
}

TEST(KeyRing, BudgetRefillsSoAttackStoppingRestoresNormalService) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.set_verification_budget(100, 5);
    for (int i = 0; i < 50; ++i) { auto p = badly_signed(static_cast<std::uint64_t>(i)); ring.receive(p.data(), p.size(), 0); }
    auto p = sealed(1000);
    EXPECT_EQ(ring.receive(p.data(), p.size(), 0).error(), SecureError::RateLimited);
    EXPECT_TRUE(ring.receive(p.data(), p.size(), 100).ok());   // 100 ms at 100/s refills enough
}

TEST(KeyRing, JunkThatCannotReachTheHmacIsNeverBudgeted) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    ring.set_verification_budget(1, 1);
    std::vector<std::uint8_t> junk(53, 0x77);                  // right size, wrong magic: free to reject
    for (int i = 0; i < 100; ++i) EXPECT_NE(ring.receive(junk.data(), junk.size(), 0).error(), SecureError::RateLimited);
    EXPECT_EQ(ring.budget_refusals(), 0u);
}

TEST(KeyRing, WithoutABudgetNothingIsRateLimited) {
    KeyRing ring;
    ring.add(make_key(1, 0xA5));
    for (int i = 0; i < 300; ++i) {
        auto p = badly_signed(static_cast<std::uint64_t>(i));
        EXPECT_EQ(ring.receive(p.data(), p.size(), 0).error(), SecureError::BadTag);
    }
}

TEST(KeyRing, EmptyRingRejectsEverything) {
    KeyRing ring;
    auto p = sealed(1);
    EXPECT_EQ(ring.receive(p.data(), p.size()).error(), SecureError::NoKeyForId);
}

// ---------- key files ----------
namespace {
struct KeyFile {
    std::string path;
    KeyFile(const std::string& content, mode_t mode) {
        char tmpl[] = "/tmp/og_key_XXXXXX";
        int fd = ::mkstemp(tmpl);
        if (fd >= 0) ::close(fd);
        path = tmpl;
        std::ofstream(path) << content;
        ::chmod(path.c_str(), mode);
    }
    ~KeyFile() { std::remove(path.c_str()); }
};
}  // namespace

TEST(KeyFile, LoadsHexWithWhitespace) {
    KeyFile f("00112233 44556677\n8899aabb ccddeeff\n", 0600);
    auto k = load_key_file(f.path);
    ASSERT_TRUE(k.ok()) << k.error().message;
    ASSERT_EQ(k.value().size(), 16u);
    EXPECT_EQ(k.value()[0], 0x00);
    EXPECT_EQ(k.value()[15], 0xFF);
}

TEST(KeyFile, RefusesGroupOrWorldAccessibleFile) {
    for (mode_t m : {mode_t(0640), mode_t(0604), mode_t(0644), mode_t(0666)}) {
        KeyFile f("00112233445566778899aabbccddeeff", m);
        auto k = load_key_file(f.path);
        ASSERT_FALSE(k.ok()) << std::oct << m;
        EXPECT_NE(k.error().message.find("chmod 600"), std::string::npos);
    }
}

TEST(KeyFile, RejectsBadContent) {
    EXPECT_FALSE(load_key_file(KeyFile("00112233445566778899aabbccddee", 0600).path).ok());      // 15 bytes
    EXPECT_FALSE(load_key_file(KeyFile("00112233445566778899aabbccddeef", 0600).path).ok());     // odd digits
    EXPECT_FALSE(load_key_file(KeyFile("zz112233445566778899aabbccddeeff", 0600).path).ok());    // non-hex
    EXPECT_FALSE(load_key_file(KeyFile("", 0600).path).ok());
    EXPECT_FALSE(load_key_file("/tmp/og_no_such_key_file").ok());
}

TEST(KeyFile, RejectsDirectoryAndOversizedFile) {
    EXPECT_FALSE(load_key_file("/tmp").ok());
    KeyFile big(std::string(5000, 'a'), 0600);
    EXPECT_FALSE(load_key_file(big.path).ok());
}

TEST(ToHex, Basic) {
    const std::uint8_t d[] = {0x00, 0x0f, 0xa5, 0xff};
    EXPECT_EQ(to_hex(d, 4), "000fa5ff");
}
