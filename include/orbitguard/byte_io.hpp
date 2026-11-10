#pragma once
// Explicit big-endian (network order) byte writer/reader.
// Fields are written one at a time, so the wire format is independent of
// struct padding, compiler, and host endianness.
#include <cstddef>
#include <cstdint>
#include <vector>

namespace orbitguard {

class ByteWriter {
public:
    void u8(std::uint8_t v) { buf_.push_back(v); }
    void u16(std::uint16_t v) {
        buf_.push_back(static_cast<std::uint8_t>(v >> 8));
        buf_.push_back(static_cast<std::uint8_t>(v));
    }
    void i16(std::int16_t v) { u16(static_cast<std::uint16_t>(v)); }
    void u32(std::uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) buf_.push_back(static_cast<std::uint8_t>(v >> s));
    }
    void u64(std::uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) buf_.push_back(static_cast<std::uint8_t>(v >> s));
    }
    const std::vector<std::uint8_t>& bytes() const { return buf_; }
    std::vector<std::uint8_t> take() { return std::move(buf_); }

private:
    std::vector<std::uint8_t> buf_;
};

// Bounds-checked reader. Reading past the end sets a sticky failure flag
// and returns 0 instead of touching memory out of range.
class ByteReader {
public:
    ByteReader(const std::uint8_t* data, std::size_t size) : p_(data), end_(data + size) {}

    std::uint8_t u8() { return need(1) ? *p_++ : 0; }
    std::uint16_t u16() {
        if (!need(2)) return 0;
        std::uint16_t v = static_cast<std::uint16_t>((p_[0] << 8) | p_[1]);
        p_ += 2;
        return v;
    }
    std::int16_t i16() { return static_cast<std::int16_t>(u16()); }
    std::uint32_t u32() {
        if (!need(4)) return 0;
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | p_[i];
        p_ += 4;
        return v;
    }
    std::uint64_t u64() {
        if (!need(8)) return 0;
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p_[i];
        p_ += 8;
        return v;
    }

    bool failed() const { return failed_; }
    std::size_t remaining() const { return static_cast<std::size_t>(end_ - p_); }

private:
    bool need(std::size_t n) {
        if (failed_ || remaining() < n) { failed_ = true; return false; }
        return true;
    }
    const std::uint8_t* p_;
    const std::uint8_t* end_;
    bool failed_ = false;
};

}  // namespace orbitguard
