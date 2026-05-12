#include "doctest.h"
#include "proxy/url.hpp"

using namespace wrangler::proxy;

TEST_CASE("url: parses socks5 with explicit port") {
    auto u = url::parse("socks5://127.0.0.1:1080");
    REQUIRE(u.has_value());
    CHECK(u->scheme == url::Scheme::Socks5);
    CHECK(u->host   == "127.0.0.1");
    CHECK(u->port   == 1080);
    CHECK(u->user.empty());
    CHECK(u->pass.empty());
}

TEST_CASE("url: parses socks5h:// as alias of socks5://") {
    auto u = url::parse("socks5h://host:9050");
    REQUIRE(u.has_value());
    CHECK(u->scheme == url::Scheme::Socks5);
    CHECK(u->host   == "host");
    CHECK(u->port   == 9050);
}

TEST_CASE("url: parses http with credentials") {
    auto u = url::parse("http://alice:s3cret@corp-proxy:3128");
    REQUIRE(u.has_value());
    CHECK(u->scheme == url::Scheme::HttpConnect);
    CHECK(u->host   == "corp-proxy");
    CHECK(u->port   == 3128);
    CHECK(u->user   == "alice");
    CHECK(u->pass   == "s3cret");
}

TEST_CASE("url: percent-decodes credentials") {
    auto u = url::parse("http://user%40domain:p%40ss%20word@host:8080");
    REQUIRE(u.has_value());
    CHECK(u->user == "user@domain");
    CHECK(u->pass == "p@ss word");
}

TEST_CASE("url: IPv6 host literal in brackets") {
    auto u = url::parse("socks5://[::1]:1080");
    REQUIRE(u.has_value());
    CHECK(u->host == "::1");
    CHECK(u->port == 1080);
}

TEST_CASE("url: default ports per scheme") {
    auto s = url::parse("socks5://host");
    REQUIRE(s.has_value());
    CHECK(s->port == 1080);

    auto h = url::parse("http://host");
    REQUIRE(h.has_value());
    CHECK(h->port == 8080);
}

TEST_CASE("url: missing scheme rejected") {
    CHECK_FALSE(url::parse("host:1080").has_value());
    CHECK_FALSE(url::parse("//host:1080").has_value());
}

TEST_CASE("url: unsupported scheme rejected") {
    CHECK_FALSE(url::parse("https://host:443").has_value());
    CHECK_FALSE(url::parse("socks4://host:1080").has_value());
    CHECK_FALSE(url::parse("socks4a://host:1080").has_value());
    CHECK_FALSE(url::parse("ftp://host:21").has_value());
}

TEST_CASE("url: empty input rejected") {
    CHECK_FALSE(url::parse("").has_value());
}

TEST_CASE("url: garbage rejected") {
    CHECK_FALSE(url::parse("http://").has_value());
    CHECK_FALSE(url::parse("socks5://:1080").has_value());     // empty host
    CHECK_FALSE(url::parse("socks5://host:abc").has_value());  // non-numeric port
    CHECK_FALSE(url::parse("socks5://host:99999").has_value()); // out-of-range port
}

TEST_CASE("url: has_credentials") {
    auto a = url::parse("socks5://host:1080").value();
    auto b = url::parse("socks5://u:p@host:1080").value();
    CHECK_FALSE(url::has_credentials(a));
    CHECK(url::has_credentials(b));
}

TEST_CASE("url: unterminated IPv6 bracket rejected") {
    // The `[` opens an IPv6 literal but there is no `]` anywhere.
    // Without the guard, rfind('@') would happily treat "[::1" as a username
    // and accept the input as valid.
    CHECK_FALSE(url::parse("socks5://[::1@host:1080").has_value());
}

TEST_CASE("url: NUL in percent-decoded credentials rejected") {
    // %00 would smuggle a NUL into "user:pass", which the HTTP CONNECT path
    // base64-encodes whole — silently truncating the credential payload.
    CHECK_FALSE(url::parse("http://us%00er:pass@host:8080").has_value());
    CHECK_FALSE(url::parse("http://user:pa%00ss@host:8080").has_value());
}
