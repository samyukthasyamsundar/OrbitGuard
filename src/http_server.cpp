#include "orbitguard/http_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>

namespace orbitguard {

namespace {
constexpr std::size_t kMaxHead = 8192;
constexpr int kReadTimeoutSec = 2;

NetError make_err(const char* what) {
    return NetError{errno, std::string(what) + ": " + std::strerror(errno)};
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

const char* reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 431: return "Request Header Fields Too Large";
        default: return "Error";
    }
}

bool send_all(int fd, const std::string& data) {
    std::size_t off = 0;
    while (off < data.size()) {
#ifdef MSG_NOSIGNAL
        const int flags = MSG_NOSIGNAL;
#else
        const int flags = 0;  // macOS: SO_NOSIGPIPE is set on the socket instead
#endif
        ssize_t n = ::send(fd, data.data() + off, data.size() - off, flags);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

void respond(int fd, const HttpResponse& r, bool head_only) {
    std::string out = "HTTP/1.1 " + std::to_string(r.status) + " " + reason(r.status) + "\r\n";
    out += "Content-Type: " + r.content_type + "\r\n";
    out += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    out += "Cache-Control: no-store\r\n";
    out += "X-Content-Type-Options: nosniff\r\n";
    out += "Referrer-Policy: no-referrer\r\n";
    // The page is fully self-contained: no external scripts, styles, fonts or connections.
    out += "Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline'; "
           "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'\r\n";
    out += "Connection: close\r\n\r\n";
    if (!head_only) out += r.body;
    send_all(fd, out);
}
}  // namespace

Result<ParsedHead, int> parse_request_head(const std::string& head) {
    const std::size_t line_end = head.find("\r\n");
    if (line_end == std::string::npos) return 400;
    const std::string line = head.substr(0, line_end);

    const std::size_t sp1 = line.find(' ');
    const std::size_t sp2 = line.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1) return 400;
    ParsedHead p;
    p.request.method = line.substr(0, sp1);
    std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    const std::string version = line.substr(sp2 + 1);
    if (version != "HTTP/1.1" && version != "HTTP/1.0") return 400;
    if (target.empty() || target[0] != '/') return 400;  // origin-form only

    const std::size_t q = target.find('?');
    p.request.path = target.substr(0, q);
    if (q != std::string::npos) p.request.query = target.substr(q + 1);

    // Header lines. Only Host matters, and it is required (also for 1.0, to block rebinding).
    std::size_t pos = line_end + 2;
    while (pos < head.size()) {
        const std::size_t e = head.find("\r\n", pos);
        if (e == std::string::npos || e == pos) break;
        const std::string h = head.substr(pos, e - pos);
        const std::size_t colon = h.find(':');
        if (colon != std::string::npos && lower(h.substr(0, colon)) == "host") {
            std::string v = h.substr(colon + 1);
            const std::size_t b = v.find_first_not_of(" \t");
            const std::size_t t = v.find_last_not_of(" \t");
            p.host = b == std::string::npos ? "" : lower(v.substr(b, t - b + 1));
        }
        pos = e + 2;
    }
    if (p.host.empty()) return 400;
    return p;
}

std::string query_param(const std::string& query, const std::string& key) {
    std::size_t pos = 0;
    while (pos <= query.size()) {
        std::size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        const std::string pair = query.substr(pos, amp - pos);
        const std::size_t eq = pair.find('=');
        if (pair.substr(0, eq) == key) return eq == std::string::npos ? "" : pair.substr(eq + 1);
        pos = amp + 1;
    }
    return "";
}

Result<bool, NetError> HttpServer::start(std::uint16_t port, Handler handler) {
    if (running_) return NetError{0, "http server already running"};
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return make_err("socket");
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(fd, 16) < 0) {
        NetError e = make_err("http bind/listen");
        ::close(fd);
        return e;
    }
    socklen_t len = sizeof a;
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
    port_ = ntohs(a.sin_port);
    listen_fd_ = fd;
    handler_ = std::move(handler);
    running_ = true;
    thread_ = std::thread([this] { serve(); });
    return true;
}

void HttpServer::stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
    listen_fd_ = -1;
}

void HttpServer::serve() {
    while (running_) {
        pollfd p{listen_fd_, POLLIN, 0};
        const int rc = ::poll(&p, 1, 200);  // wake regularly to notice stop()
        if (rc <= 0) continue;
        const int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) continue;
        handle_connection(fd);
        ::close(fd);
    }
}

void HttpServer::handle_connection(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    timeval tv{kReadTimeoutSec, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    std::string head;
    char buf[1024];
    while (head.find("\r\n\r\n") == std::string::npos) {
        if (head.size() >= kMaxHead) { respond(fd, {431, "text/plain; charset=utf-8", "header too large\n"}, false); return; }
        const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return;  // timeout, reset or closed before a full request: drop silently
        head.append(buf, static_cast<std::size_t>(n));
    }

    auto parsed = parse_request_head(head);
    if (!parsed) { respond(fd, {parsed.error(), "text/plain; charset=utf-8", "bad request\n"}, false); return; }
    const ParsedHead& ph = parsed.value();

    const std::string port = std::to_string(port_);
    if (ph.host != "127.0.0.1:" + port && ph.host != "localhost:" + port) {
        respond(fd, {403, "text/plain; charset=utf-8", "forbidden host\n"}, false);
        return;
    }
    const bool head_only = ph.request.method == "HEAD";
    if (ph.request.method != "GET" && !head_only) {
        respond(fd, {405, "text/plain; charset=utf-8", "method not allowed\n"}, false);
        return;
    }
    respond(fd, handler_(ph.request), head_only);
}

}  // namespace orbitguard
