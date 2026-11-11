// HTTP parser unit tests plus real-socket tests of the dashboard server,
// including hostile and malformed requests.
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <string>

#include "orbitguard/dashboard_routes.hpp"
#include "orbitguard/http_server.hpp"

using namespace orbitguard;

// ---------- parser ----------
TEST(HttpParse, ValidGet) {
    auto r = parse_request_head("GET /api/telemetry?n=5 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().request.method, "GET");
    EXPECT_EQ(r.value().request.path, "/api/telemetry");
    EXPECT_EQ(r.value().request.query, "n=5");
    EXPECT_EQ(r.value().host, "127.0.0.1:8080");
}

TEST(HttpParse, HostIsCaseInsensitiveAndTrimmed) {
    auto r = parse_request_head("GET / HTTP/1.1\r\nhOsT:   LocalHost:80  \r\n\r\n");
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().host, "localhost:80");
}

TEST(HttpParse, RejectsMalformed) {
    EXPECT_FALSE(parse_request_head("").ok());
    EXPECT_FALSE(parse_request_head("GET\r\n\r\n").ok());
    EXPECT_FALSE(parse_request_head("GET / HTTP/9.9\r\nHost: a\r\n\r\n").ok());
    EXPECT_FALSE(parse_request_head("GET noslash HTTP/1.1\r\nHost: a\r\n\r\n").ok());
    EXPECT_FALSE(parse_request_head("GET http://evil/ HTTP/1.1\r\nHost: a\r\n\r\n").ok());  // absolute-form
    EXPECT_FALSE(parse_request_head("GET / HTTP/1.1\r\n\r\n").ok());                          // no Host
}

TEST(HttpParse, QueryParam) {
    EXPECT_EQ(query_param("a=1&n=42&b=2", "n"), "42");
    EXPECT_EQ(query_param("n=7", "n"), "7");
    EXPECT_EQ(query_param("x=1", "n"), "");
    EXPECT_EQ(query_param("", "n"), "");
    EXPECT_EQ(query_param("nn=5", "n"), "");
}

// ---------- live server ----------
namespace {
std::string raw_request(std::uint16_t port, const std::string& request, bool shutdown_write = false) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) { ::close(fd); return "CONNECT_FAILED"; }
    timeval tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::send(fd, request.data(), request.size(), 0);
    if (shutdown_write) ::shutdown(fd, SHUT_WR);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof buf, 0)) > 0) out.append(buf, static_cast<std::size_t>(n));
    ::close(fd);
    return out;
}

struct Fixture : ::testing::Test {
    TelemetryStore store;
    HttpServer server;
    std::string host;
    void SetUp() override {
        Telemetry t;
        t.sequence = 3; t.timestamp_ms = 1000;
        t.battery_pct = 80; t.temperature_c = 5; t.cpu_pct = 30; t.signal_dbm = -90;
        store.ingest(t, 2000);
        auto r = server.start(0, make_dashboard_handler(store, "<html>PAGE</html>"));
        ASSERT_TRUE(r.ok()) << r.error().message;
        host = "127.0.0.1:" + std::to_string(server.port());
    }
    std::string get(const std::string& target, const std::string& hostHeader) {
        return raw_request(server.port(), "GET " + target + " HTTP/1.1\r\nHost: " + hostHeader + "\r\n\r\n");
    }
};
}  // namespace

TEST_F(Fixture, ServesDashboardPage) {
    const std::string r = get("/", host);
    EXPECT_NE(r.find("HTTP/1.1 200 OK"), std::string::npos);
    EXPECT_NE(r.find("text/html"), std::string::npos);
    EXPECT_NE(r.find("<html>PAGE</html>"), std::string::npos);
    EXPECT_NE(r.find("Content-Security-Policy:"), std::string::npos);
    EXPECT_NE(r.find("X-Content-Type-Options: nosniff"), std::string::npos);
    EXPECT_EQ(r.find("Access-Control-Allow-Origin"), std::string::npos);  // no CORS
}

TEST_F(Fixture, ServesTelemetryJson) {
    const std::string r = get("/api/telemetry?n=10", host);
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_NE(r.find("application/json"), std::string::npos);
    EXPECT_NE(r.find("\"seq\":3"), std::string::npos);
    EXPECT_NE(r.find("\"valid\":1"), std::string::npos);
}

TEST_F(Fixture, LocalhostHostHeaderAccepted) {
    EXPECT_NE(get("/healthz", "localhost:" + std::to_string(server.port())).find("200 OK"), std::string::npos);
}

TEST_F(Fixture, RejectsForeignHostHeader) {  // DNS-rebinding defence
    EXPECT_NE(get("/api/telemetry", "evil.example.com").find("403"), std::string::npos);
    EXPECT_NE(get("/api/telemetry", "127.0.0.1:1").find("403"), std::string::npos);
}

TEST_F(Fixture, UnknownPathIs404AndNeverTouchesFilesystem) {
    EXPECT_NE(get("/nope", host).find("404"), std::string::npos);
    EXPECT_NE(get("/../../etc/passwd", host).find("404"), std::string::npos);
    EXPECT_NE(get("/%2e%2e/%2e%2e/etc/passwd", host).find("404"), std::string::npos);
    EXPECT_EQ(get("/../../etc/passwd", host).find("root:"), std::string::npos);
}

TEST_F(Fixture, MethodsOtherThanGetAndHeadAreRejected) {
    const std::string r = raw_request(server.port(), "POST /api/telemetry HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: 0\r\n\r\n");
    EXPECT_NE(r.find("405"), std::string::npos);
}

TEST_F(Fixture, HeadReturnsNoBody) {
    const std::string r = raw_request(server.port(), "HEAD / HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_EQ(r.find("PAGE"), std::string::npos);
}

TEST_F(Fixture, GarbageGets400) {
    EXPECT_NE(raw_request(server.port(), "\x01\x02\x03 nonsense\r\n\r\n").find("400"), std::string::npos);
}

TEST_F(Fixture, OversizedHeaderIsRefused) {
    const std::string big = "GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Pad: " + std::string(20000, 'a') + "\r\n\r\n";
    EXPECT_NE(raw_request(server.port(), big).find("431"), std::string::npos);
}

TEST_F(Fixture, SurvivesIncompleteAndAbortedRequests) {
    // Half a request, then close: the server must drop it and keep serving.
    raw_request(server.port(), "GET / HTTP/1.1\r\nHost: " + host, true);
    raw_request(server.port(), "", true);
    EXPECT_NE(get("/healthz", host).find("200 OK"), std::string::npos);
}

TEST_F(Fixture, HugeCountIsClampedNotFatal) {
    EXPECT_NE(get("/api/telemetry?n=99999999999999999999", host).find("200 OK"), std::string::npos);
    EXPECT_NE(get("/api/telemetry?n=-5", host).find("200 OK"), std::string::npos);
    EXPECT_NE(get("/api/telemetry?n=abc", host).find("200 OK"), std::string::npos);
}

TEST(HttpServer, BindingTakenPortFails) {
    TelemetryStore store;
    HttpServer a, b;
    ASSERT_TRUE(a.start(0, make_dashboard_handler(store, "x")).ok());
    EXPECT_FALSE(b.start(a.port(), make_dashboard_handler(store, "x")).ok());
}

TEST(HttpServer, StopIsIdempotent) {
    TelemetryStore store;
    HttpServer s;
    ASSERT_TRUE(s.start(0, make_dashboard_handler(store, "x")).ok());
    s.stop();
    s.stop();
}
