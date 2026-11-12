// Replay tests use real UDP sockets on loopback and short recordings.
#include <gtest/gtest.h>

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <limits>
#include <string>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/recording.hpp"
#include "orbitguard/replay.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
struct TempPath {
    std::string path;
    TempPath() {
        char tmpl[] = "/tmp/og_rpl_XXXXXX";
        int fd = ::mkstemp(tmpl);
        if (fd >= 0) ::close(fd);
        path = tmpl;
        std::remove(path.c_str());
    }
    ~TempPath() { std::remove(path.c_str()); }
};

std::vector<std::uint8_t> packet(std::uint32_t seq) {
    Telemetry t;
    t.sequence = seq; t.timestamp_ms = 1000 + seq;
    t.battery_pct = 50; t.temperature_c = 10; t.cpu_pct = 20; t.signal_dbm = -90;
    return serialize(t).value();
}

void write_recording(const std::string& path, const std::vector<Record>& recs) {
    auto w = RecordWriter::create(path);
    ASSERT_TRUE(w.ok());
    for (const auto& r : recs) ASSERT_TRUE(w.value().append(r).ok());
}

double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}
}  // namespace

TEST(ReplayOptions, Validation) {
    ReplayOptions o;
    EXPECT_TRUE(o.valid());
    o.speed = 0;
    EXPECT_FALSE(o.valid());
    o.speed = -1;
    EXPECT_FALSE(o.valid());
    o.speed = std::numeric_limits<double>::infinity();
    EXPECT_FALSE(o.valid());
    o.speed = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(o.valid());
    o = {};
    o.max_gap_ms = -5;
    EXPECT_FALSE(o.valid());
}

TEST(Replay, SendsEveryDatagramByteForByteIncludingInvalidOnes) {
    TempPath tp;
    std::vector<Record> recs = {{100, packet(0)}, {101, {0xDE, 0xAD, 0xBE, 0xEF}}, {102, packet(2)}, {103, {}}};
    write_recording(tp.path, recs);

    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    auto reader = RecordReader::open(tp.path);
    ASSERT_TRUE(reader.ok());

    ReplayOptions opt;
    opt.speed = 1000;
    auto res = replay(reader.value(), tx.value(), rx.value().local_port(), opt, nullptr);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().sent, 4u);
    EXPECT_EQ(res.value().end, ReadEnd::Eof);
    EXPECT_FALSE(res.value().stopped);

    for (const auto& want : recs) {
        auto got = rx.value().receive(2000);
        ASSERT_TRUE(got.ok());
        ASSERT_FALSE(got.value().timed_out);
        EXPECT_EQ(got.value().data, want.bytes);
    }
}

TEST(Replay, KeepsOriginalPacingAndSpeedScalesIt) {
    TempPath tp;
    write_recording(tp.path, {{1000, packet(0)}, {1400, packet(1)}});  // 400 ms apart
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());

    {   // 1x: takes about 400 ms
        auto reader = RecordReader::open(tp.path);
        auto t0 = std::chrono::steady_clock::now();
        ASSERT_TRUE(replay(reader.value(), tx.value(), rx.value().local_port(), {}, nullptr).ok());
        const double took = ms_since(t0);
        EXPECT_GE(took, 380.0);
        EXPECT_LT(took, 1500.0);
    }
    {   // 8x: about 50 ms, and clearly faster than real time
        auto reader = RecordReader::open(tp.path);
        ReplayOptions opt;
        opt.speed = 8;
        auto t0 = std::chrono::steady_clock::now();
        ASSERT_TRUE(replay(reader.value(), tx.value(), rx.value().local_port(), opt, nullptr).ok());
        EXPECT_LT(ms_since(t0), 300.0);
    }
}

TEST(Replay, LongGapsAreShortenedToMaxGap) {
    TempPath tp;
    write_recording(tp.path, {{0, packet(0)}, {600000, packet(1)}});  // ten minutes apart
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    auto reader = RecordReader::open(tp.path);
    ReplayOptions opt;
    opt.max_gap_ms = 100;
    auto t0 = std::chrono::steady_clock::now();
    auto res = replay(reader.value(), tx.value(), rx.value().local_port(), opt, nullptr);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().sent, 2u);
    EXPECT_LT(ms_since(t0), 1500.0);
}

TEST(Replay, BackwardsTimestampsAreSentImmediatelyNotWaitedFor) {
    TempPath tp;
    write_recording(tp.path, {{5000, packet(0)}, {1000, packet(1)}, {1001, packet(2)}});
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    auto reader = RecordReader::open(tp.path);
    auto t0 = std::chrono::steady_clock::now();
    auto res = replay(reader.value(), tx.value(), rx.value().local_port(), {}, nullptr);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().sent, 3u);
    EXPECT_LT(ms_since(t0), 500.0);
}

TEST(Replay, StopRequestEndsEarly) {
    TempPath tp;
    write_recording(tp.path, {{0, packet(0)}, {60000, packet(1)}, {120000, packet(2)}});
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    auto reader = RecordReader::open(tp.path);
    ReplayOptions opt;
    opt.max_gap_ms = 0;  // keep the real minute-long gaps, so only stop() can end this quickly
    auto t0 = std::chrono::steady_clock::now();
    auto res = replay(reader.value(), tx.value(), rx.value().local_port(), opt,
                      [&] { return ms_since(t0) > 150.0; });
    ASSERT_TRUE(res.ok());
    EXPECT_TRUE(res.value().stopped);
    EXPECT_EQ(res.value().sent, 1u);
    EXPECT_LT(ms_since(t0), 2000.0);
}

TEST(Replay, ReportsTruncatedTail) {
    TempPath tp;
    write_recording(tp.path, {{0, packet(0)}, {1, packet(1)}});
    {   // chop the last 5 bytes off
        std::FILE* f = std::fopen(tp.path.c_str(), "rb");
        ASSERT_NE(f, nullptr);
        std::fseek(f, 0, SEEK_END);
        const long size = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        std::vector<char> buf(static_cast<std::size_t>(size - 5));
        ASSERT_EQ(std::fread(buf.data(), 1, buf.size(), f), buf.size());
        std::fclose(f);
        f = std::fopen(tp.path.c_str(), "wb");
        std::fwrite(buf.data(), 1, buf.size(), f);
        std::fclose(f);
    }
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    auto reader = RecordReader::open(tp.path);
    ASSERT_TRUE(reader.ok());
    ReplayOptions opt;
    opt.speed = 1000;
    auto res = replay(reader.value(), tx.value(), rx.value().local_port(), opt, nullptr);
    ASSERT_TRUE(res.ok());
    EXPECT_EQ(res.value().sent, 1u);
    EXPECT_EQ(res.value().end, ReadEnd::TruncatedTail);
}

TEST(Replay, RejectsInvalidOptions) {
    TempPath tp;
    write_recording(tp.path, {{0, packet(0)}});
    auto tx = UdpSocket::create();
    ASSERT_TRUE(tx.ok());
    auto reader = RecordReader::open(tp.path);
    ReplayOptions opt;
    opt.speed = 0;
    EXPECT_FALSE(replay(reader.value(), tx.value(), 9, opt, nullptr).ok());
}
