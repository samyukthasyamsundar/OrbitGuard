#pragma once
// Fuzz targets: each takes arbitrary bytes and must NEVER crash, hang, read out of bounds, or
// trip a sanitizer, whatever the input. They also assert a few invariants (a "success" must be
// self-consistent), so the fuzzer finds logic bugs as well as memory bugs.
//
// Shared by two drivers: libFuzzer (fuzz_libfuzzer.cpp, used where the runtime exists, i.e. Linux
// CI) and a portable random/mutation driver (fuzz_driver.cpp, runs anywhere, including macOS).
#include <cstddef>
#include <cstdint>

namespace orbitguard::fuzz {

void packet_decoder(const std::uint8_t* data, std::size_t size);
void secure_open(const std::uint8_t* data, std::size_t size);
void http_head(const std::uint8_t* data, std::size_t size);
void recording_reader(const std::uint8_t* data, std::size_t size);

}  // namespace orbitguard::fuzz
