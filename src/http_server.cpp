#include "orbitguard/http_server.hpp"

#include "orbitguard/sha256.hpp"   // constant_time_equal

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
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
    if (!r.set_cookie.empty()) out += "Set-Cookie: " + r.set_cookie + "\r\n";
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
        if (colon != std::string::npos && lower(h.substr(0, colon)) == "cookie") {
            std::string v = h.substr(colon + 1);
            const std::size_t b = v.find_first_not_of(" \t");
            if (b != std::string::npos && p.cookie.size() + v.size() < 4096) p.cookie += (p.cookie.empty() ? "" : "; ") + v.substr(b);
        }
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

bool token_matches(const std::string& expected, const std::string& query, const std::string& cookie_header) {
    if (expected.empty()) return false;   // no token configured can never "match"; callers check this first
    auto eq = [&](const std::string& got) {
        // Compare in time that does not depend on where the first difference is. A length difference is
        // not secret (the token length is public), so it can return early.
        return got.size() == expected.size() &&
               constant_time_equal(reinterpret_cast<const std::uint8_t*>(got.data()),
                                   reinterpret_cast<const std::uint8_t*>(expected.data()), expected.size());
    };
    if (eq(query_param(query, "k"))) return true;
    std::size_t pos = 0;
    while (pos < cookie_header.size()) {
        std::size_t semi = cookie_header.find(';', pos);
        if (semi == std::string::npos) semi = cookie_header.size();
        std::string part = cookie_header.substr(pos, semi - pos);
        const std::size_t b = part.find_first_not_of(" \t");
        if (b != std::string::npos) {
            part = part.substr(b);
            const std::string name = "og_token=";
            if (part.compare(0, name.size(), name) == 0 && eq(part.substr(name.size()))) return true;
        }
        pos = semi + 1;
    }
    return false;
}

std::vector<std::string> local_ipv4_addresses() {
    std::vector<std::string> out;
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) return out;
    for (const ifaddrs* it = list; it != nullptr; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
        if (!(it->ifa_flags & IFF_UP) || (it->ifa_flags & IFF_LOOPBACK)) continue;
        char buf[INET_ADDRSTRLEN] = {0};
        const auto* sin = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
        if (!::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) continue;
        const std::string addr = buf;
        if (addr.rfind("169.254.", 0) == 0) continue;   // link-local: not reachable from a phone
        out.push_back(addr);
    }
    ::freeifaddrs(list);
    return out;
}

std::string random_token_hex(std::size_t bytes) {
    if (bytes == 0 || bytes > 1024) return "";
    std::vector<std::uint8_t> buf(bytes);
    // arc4random_buf is the OS CSPRNG on macOS/BSD and in glibc 2.36+. Where it is missing we fall
    // back to reading /dev/urandom directly, and give up (empty string) if even that fails.
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    ::arc4random_buf(buf.data(), buf.size());
#else
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) return "";
    const std::size_t got = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    if (got != buf.size()) return "";
#endif
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (std::uint8_t b : buf) { out += digits[b >> 4]; out += digits[b & 0xF]; }
    return out;
}

Result<bool, NetError> HttpServer::start(std::uint16_t port, Handler handler) {
    return start(port, std::move(handler), Options{});
}

Result<bool, NetError> HttpServer::start(std::uint16_t port, Handler handler, const Options& options) {
    if (running_) return NetError{0, "http server already running"};
    if (options.workers < 1 || options.workers > 32 || options.max_pending < 1 || options.max_pending > 4096 ||
        options.head_deadline_ms < 100 || options.head_deadline_ms > 60000)
        return NetError{0, "invalid http server options"};
    opt_ = options;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return make_err("socket");
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(opt_.allow_lan ? INADDR_ANY : INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0 || ::listen(fd, 64) < 0) {
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
    for (int i = 0; i < opt_.workers; ++i) workers_.emplace_back([this] { worker_loop(); });
    acceptor_ = std::thread([this] { accept_loop(); });
    return true;
}

std::string HttpServer::bound_address() const {
    if (listen_fd_ < 0) return "";
    sockaddr_in a{};
    socklen_t len = sizeof a;
    if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&a), &len) < 0) return "";
    char buf[INET_ADDRSTRLEN] = {0};
    if (!::inet_ntop(AF_INET, &a.sin_addr, buf, sizeof buf)) return "";
    return buf;
}

void HttpServer::stop() {
    if (!running_.exchange(false)) return;
    cv_.notify_all();
    if (acceptor_.joinable()) acceptor_.join();
    for (auto& w : workers_) if (w.joinable()) w.join();
    workers_.clear();
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (int fd : pending_) ::close(fd);
        pending_.clear();
    }
    if (listen_fd_ >= 0) ::close(listen_fd_);
    listen_fd_ = -1;
}

void HttpServer::accept_loop() {
    while (running_) {
        pollfd p{listen_fd_, POLLIN, 0};
        if (::poll(&p, 1, 200) <= 0) continue;   // wake regularly to notice stop()
        const int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) continue;
        bool queued = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (static_cast<int>(pending_.size()) < opt_.max_pending) { pending_.push_back(fd); queued = true; }
        }
        if (queued) cv_.notify_one();
        else ::close(fd);   // too many waiting: refuse rather than queue without bound
    }
}

void HttpServer::worker_loop() {
    for (;;) {
        int fd = -1;
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return !pending_.empty() || !running_; });
            if (pending_.empty()) return;   // stopping and nothing left to serve
            fd = pending_.front();
            pending_.pop_front();
        }
        handle_connection(fd);
        ::close(fd);
    }
}

void HttpServer::handle_connection(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    timeval send_tv{kReadTimeoutSec, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send_tv, sizeof send_tv);

    // The whole request head must arrive before this instant. A per-read timeout is not enough: a
    // client sending one byte every second would reset it forever and hold a worker indefinitely.
    using clock = std::chrono::steady_clock;
    const auto deadline = clock::now() + std::chrono::milliseconds(opt_.head_deadline_ms);

    std::string head;
    char buf[1024];
    while (head.find("\r\n\r\n") == std::string::npos) {
        if (head.size() >= kMaxHead) { respond(fd, {431, "text/plain; charset=utf-8", "header too large\n"}, false); return; }
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now()).count();
        if (left <= 0) return;   // too slow: drop without a response
        pollfd p{fd, POLLIN, 0};
        const int rc = ::poll(&p, 1, static_cast<int>(std::min<long long>(left, 1000)));
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return;
        if (rc == 0) continue;   // nothing yet; the deadline check above ends this loop in time
        const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return;      // closed or reset before a full request
        head.append(buf, static_cast<std::size_t>(n));
    }

    auto parsed = parse_request_head(head);
    if (!parsed) { respond(fd, {parsed.error(), "text/plain; charset=utf-8", "bad request\n"}, false); return; }
    const ParsedHead& ph = parsed.value();

    if (!opt_.access_token.empty()) {
        // LAN mode: the secret token is the gate. A bare 403 reveals nothing about the service, and the
        // body is the same for "no token" and "wrong token".
        if (!token_matches(opt_.access_token, ph.request.query, ph.cookie)) {
            respond(fd, {403, "text/plain; charset=utf-8", "forbidden\n"}, false);
            return;
        }
    } else {
        // Loopback mode: the Host header must name this server (blocks DNS rebinding from a web page).
        const std::string port = std::to_string(port_);
        if (ph.host != "127.0.0.1:" + port && ph.host != "localhost:" + port) {
            respond(fd, {403, "text/plain; charset=utf-8", "forbidden host\n"}, false);
            return;
        }
    }
    const bool head_only = ph.request.method == "HEAD";
    if (ph.request.method != "GET" && !head_only) {
        respond(fd, {405, "text/plain; charset=utf-8", "method not allowed\n"}, false);
        return;
    }
    HttpResponse r = handler_(ph.request);
    // Remember the token in a cookie so the page's own polling (/api/telemetry) keeps working after the
    // first load. HttpOnly keeps it away from page scripts; SameSite=Strict keeps other sites from
    // making the browser send it; Path=/ covers the API.
    if (!opt_.access_token.empty() && !query_param(ph.request.query, "k").empty()) r.set_cookie = "og_token=" + opt_.access_token + "; Path=/; HttpOnly; SameSite=Strict";
    respond(fd, r, head_only);
}

}  // namespace orbitguard
