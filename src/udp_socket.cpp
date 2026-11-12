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

Result<UdpSocket, NetError> UdpSocket::bind_loopback(std::uint16_t port) { return bind_loopback(port, 0); }

Result<UdpSocket, NetError> UdpSocket::bind_loopback(std::uint16_t port, int recv_buffer_bytes) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return make_err("socket");
    if (recv_buffer_bytes > 0) {
        // Best effort: a refusal is not fatal, the OS default simply stays in force.
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_buffer_bytes, sizeof recv_buffer_bytes);
    }
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

int UdpSocket::receive_buffer_bytes() const {
    int v = 0;
    socklen_t len = sizeof v;
    if (fd_ < 0 || ::getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &v, &len) < 0) return 0;
    return v;
}

Result<bool, NetError> UdpSocket::send_to_loopback(std::uint16_t port, const std::vector<std::uint8_t>& data) {
    sockaddr_in a = loopback_addr(port);
    ssize_t n = ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&a), sizeof a);
    if (n < 0) return make_err("sendto");
    if (static_cast<std::size_t>(n) != data.size()) return NetError{0, "sendto: short write"};
    return true;
}

Result<UdpSocket::Received, NetError> UdpSocket::receive(int timeout_ms) {
    // One buffer per socket-read, sized to the largest datagram we accept. A fixed-size stack
    // buffer avoids a heap allocation per datagram; only the bytes actually received are copied out.
    std::uint8_t buf[kMaxDatagram];

    // Under load there is almost always a datagram already queued, so try to read first (without
    // blocking) and only fall back to poll() when the socket is empty. That removes one system
    // call per datagram exactly when the receiver is busiest.
    for (int attempt = 0; attempt < 2; ++attempt) {
        const ssize_t n = ::recvfrom(fd_, buf, sizeof buf, MSG_DONTWAIT, nullptr, nullptr);
        if (n >= 0) {
            return Received{std::vector<std::uint8_t>(buf, buf + n), false};
        }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return make_err("recvfrom");

        pollfd p{fd_, POLLIN, 0};
        int rc;
        do { rc = ::poll(&p, 1, timeout_ms); } while (rc < 0 && errno == EINTR);
        if (rc < 0) return make_err("poll");
        if (rc == 0) return Received{{}, true};
    }
    return Received{{}, true};  // woke up but another reader took the datagram: treat as a timeout
}

}  // namespace orbitguard
