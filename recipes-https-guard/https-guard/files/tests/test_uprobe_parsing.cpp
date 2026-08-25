#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>

#include <doctest/doctest.h>

#include "IPeerResolver.hpp"
#include "PayloadAnomalyDetection.hpp"
#include "TlsVersionDetection.hpp"
#include "TrafficObservedDetection.hpp"
#include "ssl_uprobe_event.h"
#include "xdp_tls_event.h"

using namespace https_guard;

namespace {

uprobe_event makeRaw(hg_uprobe_direction direction, uint16_t tls_version,
                     const char* process, const char* payload)
{
    uprobe_event raw{};
    raw.hdr.event_source = HG_SOURCE_UPROBE;
    raw.hdr.timestamp_ns = 1700000000000000000ULL;
    raw.hdr.pid  = 4242;
    raw.hdr.tgid = 4242;
    std::snprintf(raw.hdr.comm, sizeof(raw.hdr.comm), "%s", process);

    raw.direction   = direction;
    raw.tls.version = tls_version;
    std::snprintf(raw.tls.payload_snippet, sizeof(raw.tls.payload_snippet), "%s", payload);
    return raw;
}

}  // namespace

// A detection parses and evaluates in one step, so what a test can observe is
// the EventMeta it filled and the Verdict it returned. That is the whole of what
// the daemon acts on, and it is the real code path rather than a reimplementation
// of it -- which is why inspect() must stay linkable without the actions.

TEST_CASE("a detection fills the shared envelope from the raw record")
{
    // Regression: the header fields were being dropped. timestamp_ns in
    // particular went nowhere, so RedfishEventMessage built every event's "Id"
    // and "EventId" from 0 -- meaning every emitted Redfish event shared the
    // same Id, which is exactly what an Id is for. The BPF side had been
    // capturing it correctly the whole time.
    const auto raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0303, "bmcweb", "ok");

    EventMeta meta;
    const TrafficObservedDetection<struct uprobe_event> detection;
    const auto verdict = detection.inspect(&raw, sizeof(raw), meta);

    REQUIRE(verdict.has_value());
    CHECK(meta.timestamp_ns == 1700000000000000000ULL);
    CHECK(meta.pid  == 4242);
    CHECK(meta.tgid == 4242);
    CHECK(meta.process == "bmcweb");
}

TEST_CASE("the payload detection reads the plaintext the uprobe captured")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_READ, 0x0304, "bmcweb",
                             "GET /redfish/v1?id=1 union select * from users");

    EventMeta meta;
    const PayloadAnomalyDetection<struct uprobe_event> detection;
    const auto verdict = detection.inspect(&raw, sizeof(raw), meta);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected");
    CHECK(verdict->message.find("union select") != std::string::npos);
    CHECK(verdict->message.find("bmcweb") != std::string::npos);
}

TEST_CASE("clean traffic is claimed only by the terminal traffic-observed entry")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");

    EventMeta meta;
    CHECK(TlsVersionDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta)
              .has_value() == false);
    CHECK(PayloadAnomalyDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta)
              .has_value() == false);

    const auto observed = TrafficObservedDetection<struct uprobe_event>{}
                              .inspect(&raw, sizeof(raw), meta);
    REQUIRE(observed.has_value());
    CHECK(observed->message_id == "OemSecurityEvent.1.0.HttpsTrafficObserved");
    CHECK(observed->severity == "OK");
    CHECK(observed->actionable == false);
    CHECK(observed->message.find("TLS 1.3") != std::string::npos);
}

TEST_CASE("a record too short for the layout is declined, not misread")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0301, "curl", "x");

    EventMeta meta;
    const TlsVersionDetection<struct uprobe_event> detection;
    // A byte short of the struct: must decline rather than read past the record.
    CHECK(detection.inspect(&raw, sizeof(raw) - 1, meta).has_value() == false);
    CHECK(detection.inspect(nullptr, sizeof(raw), meta).has_value() == false);
    // The full record does violate, so the decline above was about length.
    CHECK(detection.inspect(&raw, sizeof(raw), meta).has_value() == true);
}

TEST_CASE("a ClientHello detection declines a uprobe record, and vice versa")
{
    // Not a type-system claim -- these are different template instantiations --
    // but a runtime one: each checks the record is long enough for ITS layout,
    // so a hook cannot accidentally feed the wrong one a short record and have
    // it read garbage. xdp_event is much larger than uprobe_event.
    const auto uprobe_raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0301, "curl", "x");

    EventMeta meta;
    const TlsVersionDetection<struct xdp_event> xdp_detection;
    CHECK(xdp_detection.inspect(&uprobe_raw, sizeof(uprobe_raw), meta).has_value() == false);
}

// --- the connection tuple, named by role ------------------------------------

TEST_CASE("both sources agree on which field holds the peer, despite opposite wire views")
{
    // Given the same real connection observed either way, remote_* names the
    // same host. Under src/dst it did not: the uprobe read /proc's local
    // address into src_*, while the XDP ingress hook put the packet's sender
    // there -- so the blocklist received the BMC's own address for one of them.
    constexpr uint32_t kPeer = 0x0100000A;
    constexpr uint32_t kUs   = 0x0F00000A;

    struct xdp_event raw{};
    raw.hdr.event_source = HG_SOURCE_XDP;
    raw.conn.src_ip_v4 = kPeer;    // ingress: src is the peer
    raw.conn.dst_ip_v4 = kUs;
    raw.conn.src_port  = 51000;
    raw.conn.dst_port  = 443;

    EventMeta meta;
    (void)TrafficObservedDetection<struct xdp_event>{}.inspect(&raw, sizeof(raw), meta);

    CHECK(meta.remote_ip_v4 == kPeer);
    CHECK(meta.local_ip_v4  == kUs);
    CHECK(meta.local_port   == 443);
    CHECK(meta.remote_port  == 51000);
}

// --- lazy peer resolution ---------------------------------------------------

namespace {

class CountingResolver final : public IPeerResolver
{
public:
    explicit CountingResolver(bool succeed) noexcept : succeed_(succeed) {}

    bool resolvePeer(EventMeta& meta) const noexcept override
    {
        ++calls;
        if (!succeed_) {
            return false;   // leaves the tuple zeroed, as the real one does
        }
        meta.local_ip_v4  = 0x0F00000A;
        meta.remote_ip_v4 = 0x0100000A;
        meta.local_port   = 443;
        meta.remote_port  = 51000;
        return true;
    }

    mutable int calls = 0;

private:
    bool succeed_;
};

}  // namespace

TEST_CASE("peer resolution does not happen during parsing")
{
    // The whole saving: reading /proc is the most expensive thing in the
    // pipeline, and only the enforcing path needs the result.
    CountingResolver resolver{true};
    const auto raw = makeRaw(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");

    EventMeta meta;
    const TrafficObservedDetection<struct uprobe_event> detection{&resolver};
    (void)detection.inspect(&raw, sizeof(raw), meta);

    CHECK(resolver.calls == 0);
    CHECK(meta.peer_resolver == &resolver);
    CHECK(meta.remote_ip_v4 == 0);
}

TEST_CASE("peer resolution is memoised: repeated asks cost one /proc read")
{
    CountingResolver resolver{true};
    EventMeta meta;
    meta.peer_resolver = &resolver;

    CHECK(meta.ensurePeerResolved() == true);
    CHECK(meta.ensurePeerResolved() == true);
    CHECK(meta.ensurePeerResolved() == true);
    CHECK(resolver.calls == 1);
    CHECK(meta.remote_ip_v4 == 0x0100000A);
}

TEST_CASE("a failed resolution is remembered, not retried")
{
    CountingResolver resolver{false};
    EventMeta meta;
    meta.peer_resolver = &resolver;

    CHECK(meta.ensurePeerResolved() == false);
    CHECK(meta.ensurePeerResolved() == false);
    CHECK(resolver.calls == 1);
    CHECK(meta.remote_ip_v4 == 0);   // fail-closed: nothing to enforce against
}

TEST_CASE("an event that already knows its address needs no resolver to enforce")
{
    // Pins the regression that silently disabled enforcement for XDP and
    // connection-rate events: both fill remote_ip_v4 directly and carry no
    // resolver, so gating enforcement on ensurePeerResolved() returning true
    // skipped them entirely.
    EventMeta meta;
    meta.remote_ip_v4 = 0x0100000A;
    meta.local_ip_v4  = 0x0F00000A;

    CHECK(meta.peer_resolver == nullptr);
    CHECK(meta.ensurePeerResolved() == false);   // nothing to resolve...
    CHECK(meta.remote_ip_v4 != 0);               // ...but the address is there
}
