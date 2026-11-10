cmake_minimum_required(VERSION 3.16)
project(OrbitGuard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ORBITGUARD_BUILD_TESTS "Build unit tests (fetches GoogleTest)" ON)
option(ORBITGUARD_WERROR "Treat warnings as errors" ON)

add_library(orbitguard_core
    src/crc16.cpp
    src/packet_codec.cpp
    src/sequence_tracker.cpp
    src/telemetry_generator.cpp
    src/udp_socket.cpp)
target_include_directories(orbitguard_core PUBLIC include)
target_compile_options(orbitguard_core PUBLIC -Wall -Wextra -Wpedantic -Wconversion)
if(ORBITGUARD_WERROR)
    target_compile_options(orbitguard_core PUBLIC -Werror)
endif()

add_executable(satellite_sim apps/satellite_sim.cpp)
target_link_libraries(satellite_sim PRIVATE orbitguard_core)

add_executable(ground_station apps/ground_station.cpp)
target_link_libraries(ground_station PRIVATE orbitguard_core)

if(ORBITGUARD_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(orbitguard_tests
        tests/test_crc16.cpp
        tests/test_byte_io.cpp
        tests/test_packet_codec.cpp
        tests/test_sequence_tracker.cpp
        tests/test_telemetry_generator.cpp
        tests/test_udp_loopback.cpp)
    target_link_libraries(orbitguard_tests PRIVATE orbitguard_core GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(orbitguard_tests)
endif()
