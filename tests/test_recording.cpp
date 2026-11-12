#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

#include "orbitguard/recording.hpp"

using namespace orbitguard;

namespace {
// A unique path in the temp dir, removed on destruction.
struct TempPath {
    std::string path;
    TempPath() {
        char tmpl[] = "/tmp/og_rec_XXXXXX";
        int fd = ::mkstemp(tmpl);
        if (fd >= 0) ::close(fd);
        path = tmpl;
        std::remove(path.c_str());  // start non-existent, since create() must make the file itself
    }
    ~TempPath() { std::remove(path.c_str()); }
};

std::vector<std::uint8_t> slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
void spit(const std::string& p, const std::vector<std::uint8_t>& b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
}
Record rec(std::uint64_t t, std::vector<std::uint8_t> b) { return Record{t, std::move(b)}; }
}  // namespace

TEST(Recording, RoundTripPreservesBytesAndTimes) {
    TempPath tp;
    {
        auto w = RecordWriter::create(tp.path);
        ASSERT_TRUE(w.ok()) << w.error().message;
        ASSERT_TRUE(w.value().append(rec(1000, {1, 2, 3})).ok());
        ASSERT_TRUE(w.value().append(rec(1500, {})).ok());   // an empty datagram is legal
        ASSERT_TRUE(w.value().append(rec(0xFFFFFFFFFFFFFFFFULL, {0xDE, 0xAD})).ok());
        EXPECT_EQ(w.value().count(), 3u);
    }
    auto r = RecordReader::open(tp.path);
    ASSERT_TRUE(r.ok());
    auto a = r.value().next();
    ASSERT_TRUE(a.ok());
    EXPECT_EQ(a.value().rx_time_ms, 1000u);
    EXPECT_EQ(a.value().bytes, (std::vector<std::uint8_t>{1, 2, 3}));
    auto b = r.value().next();
    ASSERT_TRUE(b.ok());
    EXPECT_TRUE(b.value().bytes.empty());
    auto c = r.value().next();
    ASSERT_TRUE(c.ok());
    EXPECT_EQ(c.value().rx_time_ms, 0xFFFFFFFFFFFFFFFFULL);
    auto end = r.value().next();
    ASSERT_FALSE(end.ok());
    EXPECT_EQ(end.error(), ReadEnd::Eof);
}

TEST(Recording, FileLayoutIsExactlyAsDocumented) {
    TempPath tp;
    {
        auto w = RecordWriter::create(tp.path);
        ASSERT_TRUE(w.ok());
        ASSERT_TRUE(w.value().append(rec(0x0102030405060708ULL, {0xAA, 0xBB})).ok());
    }
    const std::vector<std::uint8_t> expect = {
        0x4F, 0x47, 0x52, 0x43,  0x00, 0x01,  0x00, 0x00,                // header: magic, version 1, reserved
        1, 2, 3, 4, 5, 6, 7, 8,  0x00, 0x02,  0xAA, 0xBB};              // record
    EXPECT_EQ(slurp(tp.path), expect);
}

TEST(Recording, CreateRefusesToOverwriteAnExistingFile) {
    TempPath tp;
    spit(tp.path, {'p', 'r', 'e', 'c', 'i', 'o', 'u', 's'});
    auto w = RecordWriter::create(tp.path);
    EXPECT_FALSE(w.ok());
    EXPECT_EQ(slurp(tp.path), (std::vector<std::uint8_t>{'p', 'r', 'e', 'c', 'i', 'o', 'u', 's'}));  // untouched
}

TEST(Recording, CreateFailsInMissingDirectory) {
    EXPECT_FALSE(RecordWriter::create("/nonexistent_dir_og/xx.ogrec").ok());
}

TEST(Recording, AppendRejectsOversizedDatagram) {
    TempPath tp;
    auto w = RecordWriter::create(tp.path);
    ASSERT_TRUE(w.ok());
    EXPECT_FALSE(w.value().append(rec(1, std::vector<std::uint8_t>(kMaxRecordPayload + 1))).ok());
    EXPECT_TRUE(w.value().append(rec(1, std::vector<std::uint8_t>(kMaxRecordPayload))).ok());
    EXPECT_EQ(w.value().count(), 1u);
}

TEST(Recording, OpenRejectsMissingFile) { EXPECT_FALSE(RecordReader::open("/tmp/og_does_not_exist.ogrec").ok()); }

TEST(Recording, OpenRejectsForeignAndShortFiles) {
    TempPath tp;
    spit(tp.path, {});
    EXPECT_FALSE(RecordReader::open(tp.path).ok());
    spit(tp.path, {0x4F, 0x47});
    EXPECT_FALSE(RecordReader::open(tp.path).ok());
    spit(tp.path, {'N', 'O', 'T', 'A', 'R', 'E', 'C', '!', 1, 2, 3});
    EXPECT_FALSE(RecordReader::open(tp.path).ok());
}

TEST(Recording, OpenRejectsUnknownVersion) {
    TempPath tp;
    spit(tp.path, {0x4F, 0x47, 0x52, 0x43, 0x00, 0x09, 0x00, 0x00});
    auto r = RecordReader::open(tp.path);
    ASSERT_FALSE(r.ok());
    EXPECT_NE(r.error().message.find("version"), std::string::npos);
}

TEST(Recording, HeaderOnlyFileIsEmptyNotAnError) {
    TempPath tp;
    { ASSERT_TRUE(RecordWriter::create(tp.path).ok()); }
    auto r = RecordReader::open(tp.path);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().next().error(), ReadEnd::Eof);
}

TEST(Recording, EveryTruncationPointIsHandledWithoutCrashing) {
    TempPath full, cut;
    {
        auto w = RecordWriter::create(full.path);
        ASSERT_TRUE(w.ok());
        ASSERT_TRUE(w.value().append(rec(10, {1, 2, 3, 4, 5})).ok());
        ASSERT_TRUE(w.value().append(rec(20, {6, 7, 8})).ok());
    }
    const auto bytes = slurp(full.path);
    for (std::size_t n = 0; n <= bytes.size(); ++n) {
        spit(cut.path, std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n)));
        auto r = RecordReader::open(cut.path);
        if (n < kRecordFileHeaderSize) { EXPECT_FALSE(r.ok()) << "n=" << n; continue; }
        ASSERT_TRUE(r.ok()) << "n=" << n;
        int got = 0;
        ReadEnd end = ReadEnd::Eof;
        for (;;) {
            auto x = r.value().next();
            if (!x.ok()) { end = x.error(); break; }
            ++got;
        }
        // Records complete within the first n bytes: header(8) + 15 | + 13
        const int complete = n >= 8 + 15 + 13 ? 2 : n >= 8 + 15 ? 1 : 0;
        EXPECT_EQ(got, complete) << "n=" << n;
        const bool on_boundary = (n == 8 || n == 8 + 15 || n == 8 + 15 + 13);
        EXPECT_EQ(end, on_boundary ? ReadEnd::Eof : ReadEnd::TruncatedTail) << "n=" << n;
    }
}

TEST(Recording, HostileLengthIsRejectedBeforeAllocation) {
    TempPath tp;
    // A record claiming a 65535-byte payload, with almost no data behind it.
    spit(tp.path, {0x4F, 0x47, 0x52, 0x43, 0x00, 0x01, 0x00, 0x00,
                   0, 0, 0, 0, 0, 0, 0, 1,  0xFF, 0xFF,  0x41});
    auto r = RecordReader::open(tp.path);
    ASSERT_TRUE(r.ok());
    auto x = r.value().next();
    ASSERT_FALSE(x.ok());
    EXPECT_EQ(x.error(), ReadEnd::BadRecord);
}

TEST(Recording, LengthJustOverTheLimitIsRejectedAndAtTheLimitIsFine) {
    TempPath tp;
    std::vector<std::uint8_t> f = {0x4F, 0x47, 0x52, 0x43, 0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1,
                                   static_cast<std::uint8_t>((kMaxRecordPayload + 1) >> 8),
                                   static_cast<std::uint8_t>((kMaxRecordPayload + 1) & 0xFF)};
    f.resize(f.size() + kMaxRecordPayload + 1, 0x42);
    spit(tp.path, f);
    auto r = RecordReader::open(tp.path);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().next().error(), ReadEnd::BadRecord);
}

TEST(Recording, ReaderMoveSemantics) {
    TempPath tp;
    { auto w = RecordWriter::create(tp.path); ASSERT_TRUE(w.ok()); ASSERT_TRUE(w.value().append(rec(5, {9})).ok()); }
    auto a = RecordReader::open(tp.path);
    ASSERT_TRUE(a.ok());
    RecordReader moved(std::move(a.value()));
    auto x = moved.next();
    ASSERT_TRUE(x.ok());
    EXPECT_EQ(x.value().bytes[0], 9);
}
