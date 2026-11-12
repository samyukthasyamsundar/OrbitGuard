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

// ================= LAN mode, slow clients, and the access token =================

#include <chrono>
#include <set>
#include <thread>

namespace {
double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

// Opens a connection and returns the fd (or -1).
int open_conn(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) { ::close(fd); return -1; }
    return fd;
}

HttpServer::Options lan_opts(const std::string& token) {
    HttpServer::Options o;
    o.access_token = token;
    return o;
}

const char* kTok = "0123456789abcdef0123456789abcdef";
}  // namespace

// ---------- token_matches ----------
TEST(Token, QueryAndCookieBothWork) {
    EXPECT_TRUE(token_matches(kTok, std::string("k=") + kTok, ""));
    EXPECT_TRUE(token_matches(kTok, "a=1&k=" + std::string(kTok) + "&b=2", ""));
    EXPECT_TRUE(token_matches(kTok, "", std::string("og_token=") + kTok));
    EXPECT_TRUE(token_matches(kTok, "", "theme=dark; og_token=" + std::string(kTok) + "; x=y"));
}

TEST(Token, WrongMissingAndNearMissAreRefused) {
    EXPECT_FALSE(token_matches(kTok, "", ""));
    EXPECT_FALSE(token_matches(kTok, "k=", ""));
    EXPECT_FALSE(token_matches(kTok, "k=wrong", ""));
    EXPECT_FALSE(token_matches(kTok, "x=" + std::string(kTok), ""));                       // right value, wrong name
    EXPECT_FALSE(token_matches(kTok, "", "other=" + std::string(kTok)));                   // wrong cookie name
    std::string off_by_one = kTok;
    off_by_one.back() = 'e';
    EXPECT_FALSE(token_matches(kTok, "k=" + off_by_one, ""));
    EXPECT_FALSE(token_matches(kTok, std::string("k=") + kTok + "0", ""));                 // one char too long
    EXPECT_FALSE(token_matches(kTok, std::string("k=") + std::string(kTok).substr(1), "")); // one char too short
}

TEST(Token, AnEmptyExpectedTokenNeverMatchesAnything) {
    EXPECT_FALSE(token_matches("", "k=", ""));          // "no token configured" must not mean "empty token accepted"
    EXPECT_FALSE(token_matches("", "k=anything", "og_token=anything"));
}

TEST(Token, ACookieThatMerelyContainsTheTokenIsNotAMatch) {
    EXPECT_FALSE(token_matches(kTok, "", "og_token=prefix" + std::string(kTok)));
    EXPECT_FALSE(token_matches(kTok, "", "xog_token=" + std::string(kTok)));
}

// ---------- random_token_hex ----------
TEST(RandomToken, HasTheRightShapeAndDoesNotRepeat) {
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i) {
        const std::string t = random_token_hex(16);
        ASSERT_EQ(t.size(), 32u);
        for (char c : t) ASSERT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) << t;
        EXPECT_TRUE(seen.insert(t).second) << "duplicate token " << t;
    }
}

TEST(RandomToken, BadSizesGiveNothing) {
    EXPECT_TRUE(random_token_hex(0).empty());
    EXPECT_TRUE(random_token_hex(1025).empty());
}

TEST(RandomToken, EveryHexDigitAppearsAcrossManyTokens) {
    // A crude sanity check that the output is not stuck on a few values; not a randomness proof.
    std::set<char> digits;
    for (int i = 0; i < 100; ++i) for (char c : random_token_hex(16)) digits.insert(c);
    EXPECT_EQ(digits.size(), 16u);
}

// ---------- the server in token mode ----------
struct TokenFixture : ::testing::Test {
    TelemetryStore store;
    HttpServer server;
    void SetUp() override {
        auto r = server.start(0, make_dashboard_handler(store, "<html>PAGE</html>"), lan_opts(kTok));
        ASSERT_TRUE(r.ok()) << r.error().message;
    }
    std::string get(const std::string& target, const std::string& extra = "", const std::string& host = "") {
        const std::string h = host.empty() ? "192.168.1.50:" + std::to_string(server.port()) : host;
        return raw_request(server.port(), "GET " + target + " HTTP/1.1\r\nHost: " + h + "\r\n" + extra + "\r\n");
    }
};

TEST_F(TokenFixture, NoTokenIsForbiddenAndRevealsNothing) {
    for (const char* path : {"/", "/api/telemetry", "/healthz", "/anything"}) {
        const std::string r = get(path);
        EXPECT_NE(r.find("403"), std::string::npos) << path;
        EXPECT_EQ(r.find("PAGE"), std::string::npos) << path;
        EXPECT_EQ(r.find("\"stats\""), std::string::npos) << path;
        EXPECT_EQ(r.find("Set-Cookie"), std::string::npos) << path;
    }
}

TEST_F(TokenFixture, WrongTokenGetsTheSameResponseAsNoToken) {
    // The body and status must not differ, so the response does not say whether a token was "close".
    const std::string none = get("/");
    const std::string wrong = get(std::string("/?k=") + "ffffffffffffffffffffffffffffffff");
    auto body_of = [](const std::string& r) { return r.substr(r.find("\r\n\r\n") + 4); };
    EXPECT_EQ(body_of(none), body_of(wrong));
    EXPECT_NE(wrong.find("403"), std::string::npos);
}

TEST_F(TokenFixture, CorrectTokenServesThePageAndSetsAHardenedCookie) {
    const std::string r = get(std::string("/?k=") + kTok);
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_NE(r.find("PAGE"), std::string::npos);
    EXPECT_NE(r.find("Set-Cookie: og_token=" + std::string(kTok)), std::string::npos);
    EXPECT_NE(r.find("HttpOnly"), std::string::npos);
    EXPECT_NE(r.find("SameSite=Strict"), std::string::npos);
}

TEST_F(TokenFixture, TheCookieAloneUnlocksTheApiSoThePagesPollingKeepsWorking) {
    const std::string r = get("/api/telemetry?n=1", std::string("Cookie: og_token=") + kTok + "\r\n");
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_NE(r.find("\"stats\""), std::string::npos);
    EXPECT_EQ(r.find("Set-Cookie"), std::string::npos);     // the cookie is only issued when the URL token is used
}

TEST_F(TokenFixture, AnyHostHeaderIsAcceptedBecauseTheTokenIsTheGate) {
    // A phone reaches the server by IP or by a .local name, never by "localhost".
    EXPECT_NE(get(std::string("/?k=") + kTok, "", "myMac.local:" + std::to_string(server.port())).find("200 OK"), std::string::npos);
    EXPECT_NE(get(std::string("/?k=") + kTok, "", "10.0.0.7:" + std::to_string(server.port())).find("200 OK"), std::string::npos);
}

TEST_F(TokenFixture, OtherMethodsAreStillRefusedEvenWithTheToken) {
    const std::string r = raw_request(server.port(), std::string("POST /?k=") + kTok + " HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    EXPECT_NE(r.find("405"), std::string::npos);
}

// ---------- slow clients (the slowloris weakness found before this was written) ----------
TEST(SlowClients, OneDribblingClientCannotBlockOthers) {
    TelemetryStore store;
    HttpServer server;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x")).ok());
    const std::string host = "127.0.0.1:" + std::to_string(server.port());

    int slow = open_conn(server.port());               // starts a request and then dribbles one byte at a time
    ASSERT_GE(slow, 0);
    std::atomic<bool> stop{false};
    std::thread dribble([&] {
        const std::string part = "GET /healthz HTTP/1.1\r\nHost: " + host + "\r\nX-Slow: ";
        for (char c : part) { if (stop) return; ::send(slow, &c, 1, 0); std::this_thread::sleep_for(std::chrono::milliseconds(300)); }
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    const auto t0 = std::chrono::steady_clock::now();
    const std::string r = raw_request(server.port(), "GET /healthz HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
    const double took = ms_since(t0);
    stop = true;
    dribble.join();
    ::close(slow);
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_LT(took, 1000.0) << "a normal request waited " << took << " ms behind a slow client";
}

TEST(SlowClients, ADribblerIsCutOffAtTheTotalDeadlineNotPerRead) {
    TelemetryStore store;
    HttpServer server;
    HttpServer::Options o;
    o.head_deadline_ms = 600;
    o.workers = 1;                                    // with ONE worker, a stuck connection would block everything
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x"), o).ok());
    const std::string host = "127.0.0.1:" + std::to_string(server.port());

    int slow = open_conn(server.port());
    ASSERT_GE(slow, 0);
    std::atomic<bool> stop{false};
    std::thread dribble([&] {                         // one byte every 200 ms: each read is "fast", the total is not
        const std::string part = "GET /healthz HTTP/1.1\r\nHost: " + host + "\r\nX-Pad: ";
        for (char c : part) { if (stop) return; if (::send(slow, &c, 1, MSG_NOSIGNAL) < 0) return; std::this_thread::sleep_for(std::chrono::milliseconds(200)); }
    });
    // After the deadline passes, the single worker must be free again.
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    const auto t0 = std::chrono::steady_clock::now();
    const std::string r = raw_request(server.port(), "GET /healthz HTTP/1.1\r\nHost: " + host + "\r\n\r\n");
    EXPECT_NE(r.find("200 OK"), std::string::npos);
    EXPECT_LT(ms_since(t0), 800.0);
    stop = true;
    dribble.join();
    ::close(slow);
}

TEST(SlowClients, ManyIdleConnectionsDoNotStopRealRequests) {
    TelemetryStore store;
    HttpServer server;
    HttpServer::Options o;
    o.workers = 4;
    o.head_deadline_ms = 800;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x"), o).ok());
    std::vector<int> idle;
    for (int i = 0; i < 12; ++i) { int fd = open_conn(server.port()); if (fd >= 0) idle.push_back(fd); }   // connect, say nothing
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));      // let the deadline clear them
    const std::string r = raw_request(server.port(), "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(server.port()) + "\r\n\r\n");
    for (int fd : idle) ::close(fd);
    EXPECT_NE(r.find("200 OK"), std::string::npos);
}

TEST(SlowClients, AFloodBeyondTheQueueIsRefusedWithoutUnboundedGrowth) {
    TelemetryStore store;
    HttpServer server;
    HttpServer::Options o;
    o.workers = 1;
    o.max_pending = 4;
    o.head_deadline_ms = 5000;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x"), o).ok());
    std::vector<int> fds;
    for (int i = 0; i < 40; ++i) { int fd = open_conn(server.port()); if (fd >= 0) fds.push_back(fd); }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    // Count how many were closed by the server (recv returns 0) versus held open.
    int closed = 0;
    for (int fd : fds) {
        char c;
        const ssize_t n = ::recv(fd, &c, 1, MSG_DONTWAIT);
        if (n == 0) ++closed;
    }
    for (int fd : fds) ::close(fd);
    EXPECT_GE(closed, 25) << "excess connections should be refused, not queued without bound (closed " << closed << " of 40)";
}

// ---------- options and mode ----------
TEST(HttpOptions, InvalidValuesAreRejected) {
    TelemetryStore store;
    auto start = [&](HttpServer::Options o) { HttpServer s; return s.start(0, make_dashboard_handler(store, "x"), o).ok(); };
    HttpServer::Options ok;
    EXPECT_TRUE(start(ok));
    for (auto mut : std::vector<void (*)(HttpServer::Options&)>{
             [](HttpServer::Options& o) { o.workers = 0; },
             [](HttpServer::Options& o) { o.workers = 33; },
             [](HttpServer::Options& o) { o.max_pending = 0; },
             [](HttpServer::Options& o) { o.head_deadline_ms = 99; },
             [](HttpServer::Options& o) { o.head_deadline_ms = 60001; }}) {
        HttpServer::Options o;
        mut(o);
        EXPECT_FALSE(start(o));
    }
}

TEST(HttpOptions, DefaultIsBoundToLoopbackOnlyAsReportedByTheOperatingSystem) {
    TelemetryStore store;
    HttpServer server;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x")).ok());
    EXPECT_EQ(server.bound_address(), "127.0.0.1");     // asked of the socket itself, not assumed
    EXPECT_FALSE(server.listening_on_network());
}

TEST(HttpOptions, LanModeBindsAllInterfacesAndSaysSo) {
    TelemetryStore store;
    HttpServer server;
    HttpServer::Options o;
    o.allow_lan = true;
    o.access_token = kTok;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x"), o).ok());
    EXPECT_EQ(server.bound_address(), "0.0.0.0");
    EXPECT_TRUE(server.listening_on_network());
}

TEST(HttpOptions, BoundAddressIsEmptyWhenStopped) {
    HttpServer server;
    EXPECT_EQ(server.bound_address(), "");
    TelemetryStore store;
    ASSERT_TRUE(server.start(0, make_dashboard_handler(store, "x")).ok());
    server.stop();
    EXPECT_EQ(server.bound_address(), "");
}

TEST(LocalAddresses, AreWellFormedNonLoopbackAndNotLinkLocal) {
    for (const std::string& a : local_ipv4_addresses()) {
        in_addr addr{};
        ASSERT_EQ(::inet_pton(AF_INET, a.c_str(), &addr), 1) << a;      // a valid dotted quad
        EXPECT_NE(a.rfind("127.", 0), 0u) << a;                         // not loopback
        EXPECT_NE(a.rfind("169.254.", 0), 0u) << a;                     // not link-local
        EXPECT_NE(a, "0.0.0.0");
    }
}

// ---------- installable-app files ----------
TEST_F(Fixture, ServesAValidManifestAndIcon) {
    const std::string m = get("/manifest.webmanifest", host);
    EXPECT_NE(m.find("200 OK"), std::string::npos);
    EXPECT_NE(m.find("application/manifest+json"), std::string::npos);
    EXPECT_NE(m.find("\"display\": \"standalone\""), std::string::npos);
    EXPECT_NE(m.find("\"start_url\": \"/\""), std::string::npos);
    const std::string i = get("/icon.svg", host);
    EXPECT_NE(i.find("image/svg+xml"), std::string::npos);
    EXPECT_NE(i.find("<svg"), std::string::npos);
}

TEST_F(Fixture, TheManifestDoesNotEmbedAnySecret) {
    const std::string m = get("/manifest.webmanifest", host);
    EXPECT_EQ(m.find("?k="), std::string::npos);
    EXPECT_EQ(m.find("og_token"), std::string::npos);
}

TEST_F(TokenFixture, ManifestAndIconAreBehindTheTokenToo) {
    for (const char* path : {"/manifest.webmanifest", "/icon.svg"}) {
        EXPECT_NE(get(path).find("403"), std::string::npos) << path;                       // no token: refused
        EXPECT_NE(get(path, std::string("Cookie: og_token=") + kTok + "\r\n").find("200 OK"), std::string::npos) << path;
    }
}
