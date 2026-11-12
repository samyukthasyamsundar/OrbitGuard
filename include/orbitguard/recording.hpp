#pragma once
// Telemetry capture files: every datagram the ground station receives, raw, with
// its arrival time. Because invalid datagrams are kept too, a recording of a
// degraded link replays the same faults the receiver originally saw.
//
// File format (all integers big-endian):
//   file header   4  magic 0x4F475243 ("OGRC")
//                 2  version (1)
//                 2  reserved (0)
//   record*       8  rx_time_ms   u64, wall clock when the datagram arrived
//                 2  length       u16, 0..kMaxRecordPayload
//                 n  bytes        the datagram exactly as received
//
// The reader treats the file as untrusted: lengths are bounded before any
// allocation, and an incomplete final record (e.g. the process was killed mid
// write) is reported as a truncated tail, never as a crash.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "orbitguard/result.hpp"

namespace orbitguard {

constexpr std::uint32_t kRecordMagic = 0x4F475243;
constexpr std::uint16_t kRecordVersion = 1;
constexpr std::size_t kRecordFileHeaderSize = 8;
constexpr std::size_t kRecordHeaderSize = 10;
constexpr std::size_t kMaxRecordPayload = 2048;  // matches the UDP receive buffer

struct Record {
    std::uint64_t rx_time_ms = 0;
    std::vector<std::uint8_t> bytes;
};

struct RecordError {
    std::string message;
};

class RecordWriter {
public:
    ~RecordWriter();
    RecordWriter(const RecordWriter&) = delete;
    RecordWriter& operator=(const RecordWriter&) = delete;
    RecordWriter(RecordWriter&& o) noexcept : f_(o.f_), count_(o.count_) { o.f_ = nullptr; }
    RecordWriter& operator=(RecordWriter&& o) noexcept;

    // Creates a NEW file. Fails if the path already exists, so a mistyped path
    // can never overwrite someone's data.
    static Result<RecordWriter, RecordError> create(const std::string& path);

    // Appends one record and flushes it to the OS, so a crash loses at most the
    // record being written.
    Result<bool, RecordError> append(const Record& record);

    std::uint64_t count() const { return count_; }

private:
    explicit RecordWriter(std::FILE* f) : f_(f) {}
    std::FILE* f_ = nullptr;
    std::uint64_t count_ = 0;
};

enum class ReadEnd {
    Eof,            // clean end of file
    TruncatedTail,  // file ends partway through a record
    BadRecord       // impossible length, or an I/O error
};
const char* to_string(ReadEnd e);

class RecordReader {
public:
    ~RecordReader();
    RecordReader(const RecordReader&) = delete;
    RecordReader& operator=(const RecordReader&) = delete;
    RecordReader(RecordReader&& o) noexcept : f_(o.f_) { o.f_ = nullptr; }
    RecordReader& operator=(RecordReader&& o) noexcept;

    // Opens an existing file and validates its header.
    static Result<RecordReader, RecordError> open(const std::string& path);

    // Next record, or why there are no more.
    Result<Record, ReadEnd> next();

private:
    explicit RecordReader(std::FILE* f) : f_(f) {}
    std::FILE* f_ = nullptr;
};

}  // namespace orbitguard
