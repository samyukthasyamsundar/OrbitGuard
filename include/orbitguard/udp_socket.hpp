#pragma once
// Thin RAII wrapper over POSIX UDP sockets (IPv4, loopback-oriented).
// Networking is isolated here so protocol and sim logic stay platform-free.
#include <cstdint>
#include <string>
#include <vector>

#include "orbitguard/result.hpp"

namespace orbitguard {

struct NetError {
    int err = 0;          // errno value
    std::string message;  // human-readable
};

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    UdpSocket& operator=(UdpSocket&& o) noexcept;

    // Create a socket bound to 127.0.0.1:port (port 0 = OS-assigned).
    static Result<UdpSocket, NetError> bind_loopback(std::uint16_t port);
    // Create an unbound sending socket.
    static Result<UdpSocket, NetError> create();

    // Port the socket is bound to (useful after bind with port 0). 0 on error.
    std::uint16_t local_port() const;

    Result<bool, NetError> send_to_loopback(std::uint16_t port, const std::vector<std::uint8_t>& data);

    // Receive one datagram, waiting up to timeout_ms. Returns an empty optional-like:
    // ok(vector) with timed_out == true and empty data on timeout.
    struct Received { std::vector<std::uint8_t> data; bool timed_out = false; };
    Result<Received, NetError> receive(int timeout_ms);

    bool valid() const { return fd_ >= 0; }

private:
    explicit UdpSocket(int fd) : fd_(fd) {}
    int fd_ = -1;
};

}  // namespace orbitguard
