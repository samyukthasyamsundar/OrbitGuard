# OrbitGuard

A satellite telemetry simulation written in C++17. A **satellite simulator** streams
telemetry over UDP to a separate **ground station** receiver on localhost. The point of
the project is the engineering around the link: an explicit wire protocol, validation,
and failure handling.

**Status: Phase 1.** Simulator, ground station, protocol, tests. The dashboard is not implemented yet.

## Build and test

Requirements: a C++17 compiler (clang or gcc), CMake >= 3.16, git, and network access on
the first configure (GoogleTest v1.14.0 is fetched with `FetchContent`). POSIX sockets are
used, so this targets macOS and Linux.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Optional sanitizer build:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build build-asan -j && ./build-asan/orbitguard_tests
```

## Run

Use two terminals (start the ground station first):

```sh
./build/ground_station --port 5000
./build/satellite_sim  --port 5000 --rate-hz 2
```

Both accept `--help`. The simulator takes `--count N` and `--seed N` (reproducible
telemetry); the ground station takes `--max-packets N` and `--idle-timeout-s N` so it can
be scripted. Ctrl-C stops either one cleanly, and the ground station prints a summary
(valid, rejected, lost, duplicate and out-of-order counts).

## Layout

| Path | Responsibility |
|------|----------------|
| `include/orbitguard/telemetry.hpp` | In-memory `Telemetry` struct and physical limits (never sent raw) |
| `byte_io.hpp` | Big-endian `ByteWriter` / bounds-checked `ByteReader` |
| `crc16.hpp`, `src/crc16.cpp` | CRC-16/CCITT-FALSE |
| `packet_codec.*` | Wire format, `serialize`, `deserialize`, `CodecError` |
| `telemetry_generator.*` | Seeded orbit/eclipse model that produces samples |
| `sequence_tracker.*` | Loss, duplicate and reorder accounting (wrap-safe) |
| `udp_socket.*` | RAII POSIX UDP wrapper (the only platform-specific code) |
| `apps/` | `satellite_sim` and `ground_station` executables (thin `main`s) |
| `tests/` | GoogleTest unit and loopback integration tests |

`orbitguard_core` is a static library linked by both apps and the tests, so a future
dashboard can reuse it unchanged.

## Wire format (v1, 28 bytes, big-endian)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 2 | magic | `0x4F47` ("OG") |
| 2 | 1 | version | 1 |
| 3 | 1 | type | 1 = telemetry |
| 4 | 2 | payload_length | 20 |
| 6 | 4 | sequence | u32 |
| 10 | 8 | timestamp_ms | u64, Unix epoch ms |
| 18 | 2 | battery | u16, 0.01 % |
| 20 | 2 | temperature | i16, 0.01 C |
| 22 | 2 | cpu | u16, 0.01 % |
| 24 | 2 | signal | i16, 0.01 dBm |
| 26 | 2 | crc16 | over bytes 0..25 |

## Engineering decisions

- **Explicit serialization, no struct copying.** `memcpy`-ing a struct leaks padding,
  host endianness and `sizeof(double)` onto the wire and is undefined to read back on a
  different compiler. Each field is written individually in network byte order, so the
  format is defined by the table above, not by the compiler.
- **Fixed-point on the wire.** Doubles become 16-bit integers in 0.01 units. That is
  compact, deterministic, and gives a hard range per field. Resolution is 0.01, so a
  round trip is accurate to +/-0.005.
- **Header, version and magic.** Lets the receiver reject foreign traffic immediately and
  leaves room to evolve the protocol. The version is checked before the layout is trusted.
- **CRC-16 verified before fields are trusted.** UDP's checksum is weak and optional on
  some paths. Tests flip every single bit of a packet and assert that each one is rejected.
- **Validate on both sides.** The encoder refuses NaN, infinity and out-of-range values
  (so the sender cannot emit a bad packet), and the decoder range-checks again even when
  the CRC is valid (so a buggy or hostile sender cannot inject nonsense).
- **Errors are values, not exceptions.** `Result<T, E>` (C++17 has no `std::expected`)
  makes every failure explicit at the call site. A malformed datagram is routine input
  for a receiver, so it is logged and counted, and the loop continues.
- **Bounds-checked reads.** `ByteReader` sets a sticky failure flag instead of reading
  past the buffer. The socket buffer is fixed-size, and oversized datagrams fail the
  exact-length check.
- **Sequence numbers with wrap-safe arithmetic.** UDP loses, duplicates and reorders.
  The tracker uses signed 32-bit modular difference, so it behaves correctly across the
  2^32 wrap.
- **Deterministic generator, injected time.** The model takes a seed and a caller-supplied
  timestamp, so tests are reproducible and independent of the wall clock.
- **Platform code isolated.** Only `udp_socket.cpp` touches POSIX. The protocol and
  simulation compile and test without networking.
- **Strict warnings.** `-Wall -Wextra -Wpedantic -Wconversion -Werror` (disable with
  `-DORBITGUARD_WERROR=OFF` if a new compiler adds warnings).

## Known limitations (Phase 1)

- Loopback only, IPv4, single sender. The ground station does not authenticate the sender;
  the CRC detects corruption, not tampering.
- The ground station trusts the first sequence number it sees as the baseline, and a
  sender restart looks like an out-of-order burst rather than a reset.
- The tracker counts a gap as loss immediately, so a late-arriving packet is counted as
  both lost and out-of-order.
- No Windows support (POSIX sockets).
# OrbitGuard
