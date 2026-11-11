#include <gtest/gtest.h>

#include <atomic>
#include <thread>

#include "orbitguard/telemetry_store.hpp"

using namespace orbitguard;

namespace {
Telemetry make(std::uint32_t seq, std::uint64_t ts) {
    Telemetry t;
    t.sequence = seq;
    t.timestamp_ms = ts;
    t.battery_pct = 50; t.temperature_c = 10; t.cpu_pct = 20; t.signal_dbm = -90;
    return t;
}
}  // namespace

TEST(TelemetryStore, StartsEmpty) {
    TelemetryStore s;
    auto snap = s.snapshot(10);
    EXPECT_TRUE(snap.samples.empty());
    EXPECT_FALSE(snap.stats.has_last_rx);
    EXPECT_EQ(snap.stats.valid, 0u);
}

TEST(TelemetryStore, KeepsSamplesInOrderAndTracksLastRx) {
    TelemetryStore s;
    s.ingest(make(0, 100), 5000);
    s.ingest(make(1, 101), 5001);
    auto snap = s.snapshot(10);
    ASSERT_EQ(snap.samples.size(), 2u);
    EXPECT_EQ(snap.samples[0].sequence, 0u);
    EXPECT_EQ(snap.samples[1].sequence, 1u);
    EXPECT_TRUE(snap.stats.has_last_rx);
    EXPECT_EQ(snap.stats.last_rx_ms, 5001u);
}

TEST(TelemetryStore, CapacityDropsOldest) {
    TelemetryStore s(3);
    for (std::uint32_t i = 0; i < 10; ++i) s.ingest(make(i, 100 + i), 0);
    auto snap = s.snapshot(100);
    ASSERT_EQ(snap.samples.size(), 3u);
    EXPECT_EQ(snap.samples.front().sequence, 7u);
    EXPECT_EQ(snap.samples.back().sequence, 9u);
}

TEST(TelemetryStore, SnapshotReturnsNewestN) {
    TelemetryStore s;
    for (std::uint32_t i = 0; i < 10; ++i) s.ingest(make(i, 100 + i), 0);
    auto snap = s.snapshot(4);
    ASSERT_EQ(snap.samples.size(), 4u);
    EXPECT_EQ(snap.samples.front().sequence, 6u);
    EXPECT_EQ(s.snapshot(0).samples.size(), 0u);
}

TEST(TelemetryStore, DuplicatesAndLateAreCountedButNotCharted) {
    TelemetryStore s;
    s.ingest(make(0, 100), 0);
    s.ingest(make(1, 101), 0);
    s.ingest(make(1, 101), 0);  // duplicate
    s.ingest(make(3, 103), 0);  // gap (seq 2 lost)
    s.ingest(make(2, 102), 0);  // late
    auto snap = s.snapshot(100);
    EXPECT_EQ(snap.samples.size(), 3u);  // 0, 1, 3
    EXPECT_EQ(snap.stats.valid, 5u);
    EXPECT_EQ(snap.stats.duplicates, 1u);
    EXPECT_EQ(snap.stats.out_of_order, 1u);
    EXPECT_EQ(snap.stats.lost, 1u);
}

TEST(TelemetryStore, RestartKeepsChartMonotonicInTime) {
    TelemetryStore s;
    s.ingest(make(300, 1000), 0);
    s.ingest(make(0, 9000), 0);
    auto snap = s.snapshot(10);
    ASSERT_EQ(snap.samples.size(), 2u);
    EXPECT_EQ(snap.stats.restarts, 1u);
    EXPECT_LT(snap.samples[0].timestamp_ms, snap.samples[1].timestamp_ms);
}

TEST(TelemetryStore, RejectCounts) {
    TelemetryStore s;
    s.reject();
    s.reject();
    EXPECT_EQ(s.snapshot(0).stats.rejected, 2u);
}

TEST(TelemetryStore, ConcurrentWriterAndReaders) {
    TelemetryStore s(50);
    std::atomic<bool> done{false};
    std::thread writer([&] {
        for (std::uint32_t i = 0; i < 20000; ++i) s.ingest(make(i, 1000 + i), i);
        done = true;
    });
    std::vector<std::thread> readers;
    for (int r = 0; r < 3; ++r)
        readers.emplace_back([&] {
            while (!done) {
                auto snap = s.snapshot(50);
                for (std::size_t i = 1; i < snap.samples.size(); ++i)
                    ASSERT_LT(snap.samples[i - 1].sequence, snap.samples[i].sequence);
            }
        });
    writer.join();
    for (auto& t : readers) t.join();
    EXPECT_EQ(s.snapshot(0).stats.valid, 20000u);
}
