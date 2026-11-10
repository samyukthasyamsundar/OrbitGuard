#include "orbitguard/udp_socket.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace orbitguard {

namespace {
NetError make_err(const char* what) {
    return NetError{errno, std::string(what) + ": " + std::strerror(errno)};
}
sockaddr_in loopback_addr(std::uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
}
// Largest datagram we accept. Anything bigger is truncated by the kernel and
// then rejected by the codec's length check, never overflowing our buffer.
constexpr std::size_t kMaxDatagram = 2048;
}  // namespace

UdpSocket::~UdpSocket() { if (fd_ >= 0) ::close(fd_); }

UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
    if (this != &o) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = o.fd_;
        o.fd_ = -1;
    }
    return *this;
}

Result<UdpSocket, NetError> UdpSocket::create() {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return make_err("socket");
    return UdpSocket(fd);
}

Result<UdpSocket, NetError> UdpSocket::bind_loopback(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return make_err("socket");
    sockaddr_in a = loopback_addr(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) {
        NetError e = make_err("bind");
        ::close(fd);
        return e;
    }
    return UdpSocket(fd);
}

std::uint16_t UdpSocket::local_port() const {
    sockaddr_in a{};
    socklen_t len = sizeof a;
    if (fd_ < 0 || ::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len) < 0) return 0;
    return ntohs(a.sin_port);
}

Result<bool, NetError> UdpSocket::send_to_loopback(std::uint16_t port, const std::vector<std::uint8_t>& data) {
    sockaddr_in a = loopback_addr(port);
    ssize_t n = ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
    if (n < 0) return make_err("sendto");
    if (static_cast<std::size_t>(n) != data.size()) return NetError{0, "sendto: short write"};
    return true;
}

Result<UdpSocket::Received, NetError> UdpSocket::receive(int timeout_ms) {
    pollfd p{fd_, POLLIN, 0};
    int rc;
    do { rc = ::poll(&p, 1, timeout_ms); } while (rc < 0 && errno == EINTR);
    if (rc < 0) return make_err("poll");
    if (rc == 0) return Received{{}, true};

    std::vector<std::uint8_t> buf(kMaxDatagram);
    ssize_t n = ::recvfrom(fd_, buf.data(), buf.size(), 0, nullptr, nullptr);
    if (n < 0) return make_err("recvfrom");
    buf.resize(static_cast<std::size_t>(n));
    return Received{std::move(buf), false};
}

}  // namespace orbitguard
