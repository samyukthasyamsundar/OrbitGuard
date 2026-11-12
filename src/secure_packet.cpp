#include "orbitguard/secure_packet.hpp"

#include <sys/stat.h>

#include <cerrno>

#include <cstdio>
#include <cstring>

#include "orbitguard/byte_io.hpp"
#include "orbitguard/crc16.hpp"
#include "orbitguard/sha256.hpp"

namespace orbitguard {

const char* to_string(SecureError e) {
    switch (e) {
        case SecureError::NoKeyForId: return "unknown key id";
        case SecureError::TooShort: return "secure packet too short";
        case SecureError::BadTag: return "authentication failed";
        case SecureError::Replay: return "replayed packet";
        case SecureError::TooOld: return "packet older than the replay window";
        case SecureError::TooFarAhead: return "counter jumps implausibly far ahead";
        case SecureError::Malformed: return "authenticated but malformed telemetry";
        case SecureError::InvalidKey: return "invalid key";
    }
    return "unknown error";
}

// ---------------- replay window ----------------

ReplayWindow::Verdict ReplayWindow::check(std::uint64_t counter) const {
    if (!any_) return Verdict::Fresh;  // the first packet from a key sets the baseline
    if (counter > highest_) return counter - highest_ > kMaxJump ? Verdict::TooFarAhead : Verdict::Fresh;
    const std::uint64_t behind = highest_ - counter;
    if (behind >= kSize) return Verdict::TooOld;
    return (mask_ >> behind) & 1u ? Verdict::Replay : Verdict::Fresh;
}

ReplayWindow::Verdict ReplayWindow::accept(std::uint64_t counter) {
    const Verdict v = check(counter);
    if (v != Verdict::Fresh) return v;
    if (!any_) {
        any_ = true;
        highest_ = counter;
        mask_ = 1;
    } else if (counter > highest_) {
        const std::uint64_t shift = counter - highest_;
        mask_ = shift >= kSize ? 0 : mask_ << shift;
        mask_ |= 1;
        highest_ = counter;
    } else {
        mask_ |= std::uint64_t{1} << (highest_ - counter);
    }
    return Verdict::Fresh;
}

// ---------------- seal / open ----------------

namespace {
Sha256Digest compute_tag(const Key& key, const std::uint8_t* data, std::size_t size) {
    return hmac_sha256(key.bytes.data(), key.bytes.size(), data, size);
}
}  // namespace

Result<std::vector<std::uint8_t>, SecureError> seal(const Telemetry& t, const Key& key, std::uint64_t counter) {
    if (!key.valid()) return SecureError::InvalidKey;
    auto base = serialize(t);
    if (!base) return SecureError::Malformed;

    std::vector<std::uint8_t> p = std::move(base.value());
    p[2] = kSecureVersion;  // version byte, then re-do the CRC over the changed header
    const std::uint16_t crc = crc16_ccitt(p.data(), p.size() - 2);
    p[p.size() - 2] = static_cast<std::uint8_t>(crc >> 8);
    p[p.size() - 1] = static_cast<std::uint8_t>(crc);

    ByteWriter w;
    w.u8(key.id);
    w.u64(counter);
    p.insert(p.end(), w.bytes().begin(), w.bytes().end());

    const Sha256Digest tag = compute_tag(key, p.data(), p.size());
    p.insert(p.end(), tag.begin(), tag.begin() + kTagSize);
    return p;
}

bool looks_secure(const std::uint8_t* data, std::size_t size) {
    return data != nullptr && size >= 3 && data[0] == 0x4F && data[1] == 0x47 && data[2] == kSecureVersion;
}

Result<Opened, SecureError> open(const std::uint8_t* data, std::size_t size, const std::vector<Key>& keys) {
    if (data == nullptr || size != kSecurePacketSize) return SecureError::TooShort;

    // The key id selects which key to try. It is not trusted for anything else until the tag verifies.
    const std::uint8_t key_id = data[kTelemetryPacketSize];
    const Key* key = nullptr;
    for (const Key& k : keys)
        if (k.id == key_id && k.valid()) { key = &k; break; }
    if (!key) return SecureError::NoKeyForId;

    // Authenticate first, in constant time, over everything before the tag.
    const std::size_t tagged = size - kTagSize;
    const Sha256Digest expect = compute_tag(*key, data, tagged);
    if (!constant_time_equal(expect.data(), data + tagged, kTagSize)) return SecureError::BadTag;

    // Authentic. Only now decode the inner telemetry, restoring the v1 version byte so the v1
    // codec (which also verifies the CRC and the field ranges) can be reused unchanged.
    std::vector<std::uint8_t> inner(data, data + kTelemetryPacketSize);
    inner[2] = kProtocolVersion;
    const std::uint16_t crc = crc16_ccitt(inner.data(), inner.size() - 2);
    inner[inner.size() - 2] = static_cast<std::uint8_t>(crc >> 8);
    inner[inner.size() - 1] = static_cast<std::uint8_t>(crc);

    // The sender's own CRC must have been right for the packet it authenticated.
    const std::uint16_t sent_crc = static_cast<std::uint16_t>((data[kTelemetryPacketSize - 2] << 8) | data[kTelemetryPacketSize - 1]);
    std::vector<std::uint8_t> as_sent(data, data + kTelemetryPacketSize);
    if (crc16_ccitt(as_sent.data(), as_sent.size() - 2) != sent_crc) return SecureError::Malformed;

    auto telemetry = deserialize(inner);
    if (!telemetry) return SecureError::Malformed;

    ByteReader r(data + kTelemetryPacketSize + 1, 8);
    Opened out;
    out.telemetry = telemetry.value();
    out.key_id = key_id;
    out.counter = r.u64();
    return out;
}

// ---------------- key ring ----------------

bool KeyRing::add(Key key) {
    if (!key.valid()) return false;
    for (const Key& k : keys_)
        if (k.id == key.id) return false;
    keys_.push_back(std::move(key));
    windows_.emplace_back();
    return true;
}

Result<Opened, SecureError> KeyRing::receive(const std::uint8_t* data, std::size_t size) {
    auto opened = open(data, size, keys_);
    if (!opened) return opened.error();

    for (std::size_t i = 0; i < keys_.size(); ++i) {
        if (keys_[i].id != opened.value().key_id) continue;
        switch (windows_[i].accept(opened.value().counter)) {
            case ReplayWindow::Verdict::Fresh: return opened;
            case ReplayWindow::Verdict::Replay: return SecureError::Replay;
            case ReplayWindow::Verdict::TooOld: return SecureError::TooOld;
            case ReplayWindow::Verdict::TooFarAhead: return SecureError::TooFarAhead;
        }
    }
    return SecureError::NoKeyForId;
}

// ---------------- key files ----------------

std::string to_hex(const std::uint8_t* data, std::size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        s += digits[data[i] >> 4];
        s += digits[data[i] & 0xF];
    }
    return s;
}

Result<std::vector<std::uint8_t>, KeyLoadError> load_key_file(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return KeyLoadError{"cannot read key file " + path + ": " + std::strerror(errno)};
    if (!S_ISREG(st.st_mode)) return KeyLoadError{path + " is not a regular file"};
    if (st.st_mode & (S_IRWXG | S_IRWXO))
        return KeyLoadError{path + " is accessible by other users; run: chmod 600 " + path};

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return KeyLoadError{"cannot open key file " + path};
    std::string text;
    char buf[256];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) {
        text.append(buf, n);
        if (text.size() > 4096) { std::fclose(f); return KeyLoadError{"key file is too large"}; }
    }
    std::fclose(f);

    std::vector<std::uint8_t> key;
    int hi = -1;
    for (char c : text) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        if (v < 0) return KeyLoadError{"key file must contain only hex digits"};
        if (hi < 0) hi = v;
        else { key.push_back(static_cast<std::uint8_t>(hi * 16 + v)); hi = -1; }
    }
    if (hi >= 0) return KeyLoadError{"key file has an odd number of hex digits"};
    if (key.size() < kMinKeySize)
        return KeyLoadError{"key must be at least " + std::to_string(kMinKeySize) + " bytes (" +
                            std::to_string(kMinKeySize * 2) + " hex digits)"};
    return key;
}

}  // namespace orbitguard
