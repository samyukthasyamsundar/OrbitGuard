// libFuzzer entry point. Select the target at build time with -DFUZZ_TARGET=<name>.
#include <cstddef>
#include <cstdint>

#include "targets.hpp"

#ifndef FUZZ_TARGET
#error "define FUZZ_TARGET (packet_decoder, secure_open, http_head or recording_reader)"
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    orbitguard::fuzz::FUZZ_TARGET(data, size);
    return 0;
}
