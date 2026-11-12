// Integration tests: real UDP sockets on 127.0.0.1 using OS-assigned ports.
#include <gtest/gtest.h>

#include <chrono>

#include "orbitguard/packet_codec.hpp"
#include "orbitguard/udp_socket.hpp"

using namespace orbitguard;

namespace {
Telemetry sample(std::uint32_t seq) {
    Telemetry t;
    t.sequence = seq;
    t.timestamp_ms = 1700000000000ULL + seq;
    t.battery_pct = 80; t.temperature_c = 21.5; t.cpu_pct = 33; t.signal_dbm = -90;
    return t;
}
}  // namespace

TEST(UdpLoopback, TelemetryTravelsEndToEnd) {
    auto rx = UdpSocket::bind_loopback(0);
    ASSERT_TRUE(rx.ok()) << rx.error().message;
    auto tx = UdpSocket::create();
    ASSERT_TRUE(tx.ok());
    const std::uint16_t port = rx.value().local_port();
    ASSERT_NE(port, 0);

    auto enc = serialize(sample(7));
    ASSERT_TRUE(enc.ok());
    ASSERT_TRUE(tx.value().send_to_loopback(port, enc.value()).ok());

    auto got = rx.value().receive(2000);
    ASSERT_TRUE(got.ok());
    ASSERT_FALSE(got.value().timed_out);
    auto dec = deserialize(got.value().data);
    ASSERT_TRUE(dec.ok());
    EXPECT_EQ(dec.value().sequence, 7u);
    EXPECT_NEAR(dec.value().temperature_c, 21.5, 0.005);
}

TEST(UdpLoopback, ReceiveTimesOutWhenIdle) {
    auto rx = UdpSocket::bind_loopback(0);
    ASSERT_TRUE(rx.ok());
    auto got = rx.value().receive(50);
    ASSERT_TRUE(got.ok());
    EXPECT_TRUE(got.value().timed_out);
}

TEST(UdpLoopback, GarbageDatagramIsRejectedNotFatal) {
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    const std::uint16_t port = rx.value().local_port();

    ASSERT_TRUE(tx.value().send_to_loopback(port, {0xDE, 0xAD, 0xBE, 0xEF}).ok());
    auto g = rx.value().receive(2000);
    ASSERT_TRUE(g.ok());
    EXPECT_FALSE(deserialize(g.value().data).ok());

    // The receiver must still work afterwards.
    ASSERT_TRUE(tx.value().send_to_loopback(port, serialize(sample(1)).value()).ok());
    auto h = rx.value().receive(2000);
    ASSERT_TRUE(h.ok());
    EXPECT_TRUE(deserialize(h.value().data).ok());
}

TEST(UdpLoopback, BindingSamePortTwiceFails) {
    auto a = UdpSocket::bind_loopback(0);
    ASSERT_TRUE(a.ok());
    auto b = UdpSocket::bind_loopback(a.value().local_port());
    EXPECT_FALSE(b.ok());
}

TEST(UdpLoopback, EmptyDatagramIsDeliveredNotMistakenForATimeout) {
    auto rx = UdpSocket::bind_loopback(0);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    ASSERT_TRUE(tx.value().send_to_loopback(rx.value().local_port(), {}).ok());
    auto got = rx.value().receive(2000);
    ASSERT_TRUE(got.ok());
    EXPECT_FALSE(got.value().timed_out);
    EXPECT_TRUE(got.value().data.empty());
}

TEST(UdpLoopback, IdleReceiveStillWaitsForRoughlyTheTimeout) {
    auto rx = UdpSocket::bind_loopback(0);
    ASSERT_TRUE(rx.ok());
    const auto t0 = std::chrono::steady_clock::now();
    auto got = rx.value().receive(150);
    const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    ASSERT_TRUE(got.ok());
    EXPECT_TRUE(got.value().timed_out);
    EXPECT_GE(ms, 140.0);    // it really waited (not a busy return)...
    EXPECT_LT(ms, 1500.0);   // ...and not forever
}

TEST(UdpLoopback, BackToBackDatagramsAreAllDeliveredInOrder) {
    auto rx = UdpSocket::bind_loopback(0, 1 << 20);
    auto tx = UdpSocket::create();
    ASSERT_TRUE(rx.ok() && tx.ok());
    for (std::uint8_t i = 0; i < 50; ++i) ASSERT_TRUE(tx.value().send_to_loopback(rx.value().local_port(), {i, 0xAB}).ok());
    for (std::uint8_t i = 0; i < 50; ++i) {
        auto got = rx.value().receive(2000);
        ASSERT_TRUE(got.ok());
        ASSERT_FALSE(got.value().timed_out) << i;
        EXPECT_EQ(got.value().data[0], i);
    }
}

TEST(UdpLoopback, RequestedReceiveBufferIsReportedBack) {
    auto def = UdpSocket::bind_loopback(0);
    auto big = UdpSocket::bind_loopback(0, 4 << 20);
    ASSERT_TRUE(def.ok() && big.ok());
    EXPECT_GT(def.value().receive_buffer_bytes(), 0);
    EXPECT_GE(big.value().receive_buffer_bytes(), def.value().receive_buffer_bytes());
}
