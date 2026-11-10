// Integration tests: real UDP sockets on 127.0.0.1 using OS-assigned ports.
#include <gtest/gtest.h>

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
