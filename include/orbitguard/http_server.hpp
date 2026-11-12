#pragma once
// Minimal read-only HTTP/1.1 server for the dashboard.
//
// Deliberately tiny and defensive rather than general:
//  * binds to 127.0.0.1 by default; an explicit option opens it to the local network;
//  * slow clients cannot starve others: the WHOLE request head must arrive within a fixed deadline
//    (not per read, which a client dribbling one byte at a time defeats), connections are served by
//    a small pool of worker threads, and concurrent connections are capped;
//  * GET/HEAD only, one request per connection (Connection: close);
//  * routes are decided by the caller's handler, the server never touches the
//    filesystem, so there is no path traversal surface;
//  * request head is capped at 8 KiB and each connection has a read timeout;
//  * the Host header must name this server (blocks DNS-rebinding from a web page);
//  * no CORS headers are sent, so other origins cannot read responses.
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>
#include <functional>
#include <string>
#include <thread>

#include "orbitguard/result.hpp"
#include "orbitguard/udp_socket.hpp"  // NetError

namespace orbitguard {

struct HttpRequest {
    std::string method;
    std::string path;   // without query string
    std::string query;  // text after '?', may be empty
};

struct HttpResponse {
    int status = 200;
    std::string content_type = "text/plain; charset=utf-8";
    std::string body;
    std::string set_cookie = {};   // if non-empty, sent as a Set-Cookie header
};

// Parses an HTTP request head ("GET /x?y HTTP/1.1\r\nHost: ...\r\n\r\n").
// Returns the HTTP status to answer with when the head is unacceptable.
struct ParsedHead {
    HttpRequest request;
    std::string host;
    std::string cookie;   // the raw Cookie header value, or empty
};
Result<ParsedHead, int> parse_request_head(const std::string& head);

// Value of `key` in a query string like "a=1&b=2"; empty if absent.
std::string query_param(const std::string& query, const std::string& key);

// Looks for the access token in a request: the ?k= query parameter, or an "og_token" cookie.
// Returns true only on an exact, constant-time match with a non-empty expected token.
bool token_matches(const std::string& expected, const std::string& query, const std::string& cookie_header);

// IPv4 addresses of this machine's non-loopback, up network interfaces, as dotted strings, in the
// order the OS lists them. Empty if there are none (e.g. no network). Link-local (169.254.x.x)
// addresses are skipped because a phone cannot usefully reach them.
std::vector<std::string> local_ipv4_addresses();

// Generates a random token of `bytes` random bytes as lowercase hex, from the operating system's
// secure random source. Returns an empty string if that source is unavailable (callers must refuse
// to run unauthenticated in that case).
std::string random_token_hex(std::size_t bytes);

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    HttpServer() = default;
    ~HttpServer() { stop(); }
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    struct Options {
        bool allow_lan = false;                 // false: bind 127.0.0.1 only; true: bind all interfaces
        std::string access_token;               // non-empty: every request must present it (see below)
        int workers = 4;                        // threads serving connections, 1..32
        int max_pending = 64;                   // connections allowed to wait for a worker; extras are refused
        int head_deadline_ms = 3000;            // total time allowed to receive the whole request head
    };

    // Bind (127.0.0.1, or every interface if allow_lan) and start serving on background threads.
    // port 0 = OS-assigned. With a non-empty access_token, a request is served only if it carries the
    // token as ?k=TOKEN or the cookie "og_token=TOKEN"; anything else gets a bare 403 and the Host
    // check is skipped (a LAN client reaches the server by IP or hostname, not by "localhost").
    Result<bool, NetError> start(std::uint16_t port, Handler handler);
    Result<bool, NetError> start(std::uint16_t port, Handler handler, const Options& options);
    void stop();
    std::uint16_t port() const { return port_; }
    // True if the server accepts connections from other machines (bound to all interfaces).
    bool listening_on_network() const { return opt_.allow_lan && running_; }
    // The address actually bound by the operating system, e.g. "127.0.0.1" or "0.0.0.0". Empty if stopped.
    std::string bound_address() const;

private:
    void accept_loop();
    void worker_loop();
    void handle_connection(int fd);

    int listen_fd_ = -1;
    std::uint16_t port_ = 0;
    Handler handler_;
    Options opt_;
    std::atomic<bool> running_{false};
    std::thread acceptor_;
    std::vector<std::thread> workers_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<int> pending_;           // accepted sockets waiting for a worker
};

}  // namespace orbitguard
