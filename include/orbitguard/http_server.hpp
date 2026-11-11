#pragma once
// Minimal read-only HTTP/1.1 server for the dashboard.
//
// Deliberately tiny and defensive rather than general:
//  * binds to 127.0.0.1 only;
//  * GET/HEAD only, one request per connection (Connection: close);
//  * routes are decided by the caller's handler, the server never touches the
//    filesystem, so there is no path traversal surface;
//  * request head is capped at 8 KiB and each connection has a read timeout;
//  * the Host header must name this server (blocks DNS-rebinding from a web page);
//  * no CORS headers are sent, so other origins cannot read responses.
#include <atomic>
#include <cstdint>
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
};

// Parses an HTTP request head ("GET /x?y HTTP/1.1\r\nHost: ...\r\n\r\n").
// Returns the HTTP status to answer with when the head is unacceptable.
struct ParsedHead {
    HttpRequest request;
    std::string host;
};
Result<ParsedHead, int> parse_request_head(const std::string& head);

// Value of `key` in a query string like "a=1&b=2"; empty if absent.
std::string query_param(const std::string& query, const std::string& key);

class HttpServer {
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    HttpServer() = default;
    ~HttpServer() { stop(); }
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    // Bind 127.0.0.1:port (0 = OS-assigned) and start serving on a background thread.
    Result<bool, NetError> start(std::uint16_t port, Handler handler);
    void stop();
    std::uint16_t port() const { return port_; }

private:
    void serve();
    void handle_connection(int fd);

    int listen_fd_ = -1;
    std::uint16_t port_ = 0;
    Handler handler_;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

}  // namespace orbitguard
