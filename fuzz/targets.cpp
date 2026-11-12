#include "targets.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "orbitguard/http_server.hpp"
#include "orbitguard/packet_codec.hpp"
#include "orbitguard/recording.hpp"
#include "orbitguard/secure_packet.hpp"

namespace orbitguard::fuzz {

namespace {
[[noreturn]] void invariant_failed(const char* what) {
    std::fprintf(stderr, "FUZZ INVARIANT VIOLATED: %s\n", what);
    std::abort();
}
}  // namespace

void packet_decoder(const std::uint8_t* data, std::size_t size) {
    auto r = deserialize(data, size);
    if (!r) return;
    // Anything the decoder accepts must be exactly what the encoder would produce for it, and
    // must lie inside the physical limits.
    const Telemetry& t = r.value();
    auto again = serialize(t);
    if (!again) invariant_failed("decoded packet cannot be re-encoded");
    if (again.value().size() != size) invariant_failed("re-encoded size differs");
    // Re-decoding the re-encoding must give identical fields.
    auto r2 = deserialize(again.value());
    if (!r2 || r2.value().sequence != t.sequence || r2.value().timestamp_ms != t.timestamp_ms)
        invariant_failed("decode(encode(x)) != x");
}

void secure_open(const std::uint8_t* data, std::size_t size) {
    // A fixed key: an arbitrary byte string essentially never carries a valid tag, so this mostly
    // exercises the rejection paths. The invariant is that anything it ACCEPTS is a packet that
    // really verifies, which the second call (with a different key) must then refuse.
    static const std::vector<Key> keys = {Key{1, std::vector<std::uint8_t>(32, 0x5A)}};
    static const std::vector<Key> other = {Key{1, std::vector<std::uint8_t>(32, 0xA5)}};
    auto r = open(data, size, keys);
    if (r) {
        if (size != kSecurePacketSize) invariant_failed("accepted a wrong-size secure packet");
        if (open(data, size, other)) invariant_failed("one packet verified under two different keys");
    }
    KeyRing ring;
    ring.add(keys[0]);
    (void)ring.receive(data, size);
    (void)looks_secure(data, size);
}

void http_head(const std::uint8_t* data, std::size_t size) {
    const std::string head(reinterpret_cast<const char*>(data), size);
    auto r = parse_request_head(head);
    if (r) {
        const auto& req = r.value().request;
        if (req.path.empty() || req.path[0] != '/') invariant_failed("accepted a path that does not start with '/'");
        if (r.value().host.empty()) invariant_failed("accepted a request without a Host");
        if (req.method.find(' ') != std::string::npos) invariant_failed("method contains a space");
    }
    (void)query_param(head, "n");
}

void recording_reader(const std::uint8_t* data, std::size_t size) {
    char tmpl[] = "/tmp/og_fuzz_XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) return;
    std::size_t off = 0;
    while (off < size) {
        const ssize_t n = ::write(fd, data + off, size - off);
        if (n <= 0) break;
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);

    auto reader = RecordReader::open(tmpl);
    if (reader) {
        // Bounded loop: a corrupt file must end the iteration, never spin forever.
        for (std::size_t i = 0; i <= size; ++i) {
            auto rec = reader.value().next();
            if (!rec) break;
            if (rec.value().bytes.size() > kMaxRecordPayload) invariant_failed("record larger than the maximum");
            if (i == size) invariant_failed("reader produced more records than input bytes");
        }
    }
    ::unlink(tmpl);
}

}  // namespace orbitguard::fuzz
