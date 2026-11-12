#include "orbitguard/recording.hpp"

#include <cerrno>
#include <cstring>

#include "orbitguard/byte_io.hpp"

namespace orbitguard {

namespace {
RecordError sys_error(const std::string& what) {
    return RecordError{what + ": " + std::strerror(errno)};
}
}  // namespace

const char* to_string(ReadEnd e) {
    switch (e) {
        case ReadEnd::Eof: return "end of file";
        case ReadEnd::TruncatedTail: return "file ends partway through a record";
        case ReadEnd::BadRecord: return "corrupt record";
    }
    return "unknown";
}

// ---------------- writer ----------------

RecordWriter::~RecordWriter() { if (f_) std::fclose(f_); }

RecordWriter& RecordWriter::operator=(RecordWriter&& o) noexcept {
    if (this != &o) {
        if (f_) std::fclose(f_);
        f_ = o.f_;
        count_ = o.count_;
        o.f_ = nullptr;
    }
    return *this;
}

Result<RecordWriter, RecordError> RecordWriter::create(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "wbx");  // 'x': fail if it exists
    if (!f) return sys_error("cannot create " + path + " (the file must not already exist)");

    ByteWriter w;
    w.u32(kRecordMagic);
    w.u16(kRecordVersion);
    w.u16(0);
    if (std::fwrite(w.bytes().data(), 1, w.bytes().size(), f) != w.bytes().size() || std::fflush(f) != 0) {
        RecordError e = sys_error("cannot write " + path);
        std::fclose(f);
        return e;
    }
    return RecordWriter(f);
}

Result<bool, RecordError> RecordWriter::append(const Record& record) {
    if (!f_) return RecordError{"recording is closed"};
    if (record.bytes.size() > kMaxRecordPayload) return RecordError{"datagram too large to record"};

    ByteWriter w;
    w.u64(record.rx_time_ms);
    w.u16(static_cast<std::uint16_t>(record.bytes.size()));
    const bool ok = std::fwrite(w.bytes().data(), 1, w.bytes().size(), f_) == w.bytes().size() &&
                    (record.bytes.empty() ||
                     std::fwrite(record.bytes.data(), 1, record.bytes.size(), f_) == record.bytes.size()) &&
                    std::fflush(f_) == 0;
    if (!ok) return sys_error("cannot write recording");
    ++count_;
    return true;
}

// ---------------- reader ----------------

RecordReader::~RecordReader() { if (f_) std::fclose(f_); }

RecordReader& RecordReader::operator=(RecordReader&& o) noexcept {
    if (this != &o) {
        if (f_) std::fclose(f_);
        f_ = o.f_;
        o.f_ = nullptr;
    }
    return *this;
}

Result<RecordReader, RecordError> RecordReader::open(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return sys_error("cannot open " + path);

    std::uint8_t head[kRecordFileHeaderSize];
    if (std::fread(head, 1, sizeof head, f) != sizeof head) {
        std::fclose(f);
        return RecordError{path + " is not an OrbitGuard recording (too short)"};
    }
    ByteReader r(head, sizeof head);
    const std::uint32_t magic = r.u32();
    const std::uint16_t version = r.u16();
    if (magic != kRecordMagic) {
        std::fclose(f);
        return RecordError{path + " is not an OrbitGuard recording (bad magic)"};
    }
    if (version != kRecordVersion) {
        std::fclose(f);
        return RecordError{path + " has unsupported recording version " + std::to_string(version)};
    }
    return RecordReader(f);
}

Result<Record, ReadEnd> RecordReader::next() {
    if (!f_) return ReadEnd::BadRecord;

    std::uint8_t head[kRecordHeaderSize];
    std::size_t n = std::fread(head, 1, sizeof head, f_);
    if (n == 0) return std::ferror(f_) ? ReadEnd::BadRecord : ReadEnd::Eof;
    if (n < sizeof head) return std::ferror(f_) ? ReadEnd::BadRecord : ReadEnd::TruncatedTail;

    ByteReader r(head, n);
    Record rec;
    rec.rx_time_ms = r.u64();
    const std::uint16_t len = r.u16();
    if (len > kMaxRecordPayload) return ReadEnd::BadRecord;  // checked BEFORE allocating

    rec.bytes.resize(len);
    if (len > 0) {
        n = std::fread(rec.bytes.data(), 1, len, f_);
        if (n < len) return std::ferror(f_) ? ReadEnd::BadRecord : ReadEnd::TruncatedTail;
    }
    return rec;
}

}  // namespace orbitguard
