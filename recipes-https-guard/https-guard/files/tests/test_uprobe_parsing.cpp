#include <cstdint>
#include <cstdio>

#include <doctest/doctest.h>

#include "parse_uprobe_event.hpp"

using namespace https_guard;

namespace {

uprobe_event makeRaw(hg_uprobe_direction direction, uint16_t tls_version,
                      const char* process, const char* payload)
{
    uprobe_event raw{};
    raw.event_source = HG_SOURCE_UPROBE;
    raw.direction = direction;
    raw.pid = 4242;
    raw.tgid = 4242;
    raw.tls_version = tls_version;
    std::snprintf(raw.process, sizeof(raw.process), "%s", process);
    std::snprintf(raw.payload_snippet, sizeof(raw.payload_snippet), "%s", payload);
    return raw;
}

}  // namespace

TEST_CASE("parseUprobeEventFields tags SSL_write events as outbound")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");
    const hg_event evt = parseUprobeEventFields(raw);

    CHECK(evt.is_inbound == false);
    CHECK(evt.pid == 4242);
    CHECK(evt.tls_version == 0x0304);
    CHECK(evt.process == "bmcweb");
    CHECK(evt.payload_snippet == "HTTP/1.1 200 OK");
}

TEST_CASE("parseUprobeEventFields tags SSL_read events as inbound")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_READ, 0x0304, "bmcweb",
                              "GET /redfish/v1?id=1 union select * from users");
    const hg_event evt = parseUprobeEventFields(raw);

    CHECK(evt.is_inbound == true);
    CHECK(evt.payload_snippet == "GET /redfish/v1?id=1 union select * from users");
}

TEST_CASE("parseUprobeEventFields does not truncate short fields early")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_READ, 0x0303, "curl", "");
    const hg_event evt = parseUprobeEventFields(raw);

    CHECK(evt.process == "curl");
    CHECK(evt.payload_snippet == "");
}
