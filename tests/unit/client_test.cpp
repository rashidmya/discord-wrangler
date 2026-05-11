#include "doctest.h"
#include "proxy/client.hpp"
#include "proxy/url.hpp"

using namespace wrangler::proxy;

TEST_CASE("redact_url: no credentials -- preserved") {
    auto u = url::parse("socks5://host:1080").value();
    CHECK(client::redact_url(u) == "socks5://host:1080");
}

TEST_CASE("redact_url: credentials replaced with ***") {
    auto u = url::parse("socks5://alice:s3cret@host:1080").value();
    CHECK(client::redact_url(u) == "socks5://***@host:1080");
}

TEST_CASE("redact_url: http scheme preserved") {
    auto u = url::parse("http://corp-proxy:3128").value();
    CHECK(client::redact_url(u) == "http://corp-proxy:3128");
}

TEST_CASE("redact_url: IPv6 host bracketed in output") {
    auto u = url::parse("socks5://[::1]:1080").value();
    CHECK(client::redact_url(u) == "socks5://[::1]:1080");
}
