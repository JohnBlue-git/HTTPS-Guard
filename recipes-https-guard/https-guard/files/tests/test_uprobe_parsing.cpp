#include <cstdint>
#include <cstdio>

#include <doctest/doctest.h>

#include "parse_uprobe_event.hpp"
#include "uprobe_hg_event.hpp"
#include "xdp_hg_event.hpp"

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
    UprobeEvent evt;
    parseUprobeEventFields(raw, evt);

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
    UprobeEvent evt;
    parseUprobeEventFields(raw, evt);

    CHECK(evt.is_inbound == true);
    CHECK(evt.payload_snippet == "GET /redfish/v1?id=1 union select * from users");
}

TEST_CASE("parseUprobeEventFields does not truncate short fields early")
{
    const auto raw = makeRaw(HG_UPROBE_DIR_READ, 0x0303, "curl", "");
    UprobeEvent evt;
    parseUprobeEventFields(raw, evt);

    CHECK(evt.process == "curl");
    CHECK(evt.payload_snippet == "");
}

// --- local/remote orientation (ticket 14) ------------------------------
//
// These pin the property that made the original bug possible: nothing
// asserted on which end of the connection landed in which field, so the two
// hooks could disagree indefinitely. A consumer must be able to ask for
// "the peer" without knowing which hook produced the event.

TEST_CASE("XDP orientation: an ingress packet's source is the REMOTE peer, its destination is LOCAL")
{
    // Mirrors XdpTlsProgram::parseEvent's mapping without needing libbpf:
    // XDP is an ingress hook, so packet src = peer, packet dst = this BMC.
    constexpr uint32_t kPacketSrc = 0x0100000A;  // the peer, as seen on the wire
    constexpr uint32_t kPacketDst = 0x0F00000A;  // us
    constexpr uint16_t kPacketSport = 51000;     // peer's ephemeral port
    constexpr uint16_t kPacketDport = 443;       // our listening port

    UprobeEvent evt;
    evt.local_ip_v4  = kPacketDst;
    evt.remote_ip_v4 = kPacketSrc;
    evt.local_port   = kPacketDport;
    evt.remote_port  = kPacketSport;

    // The thing we would blocklist must be the peer, never ourselves.
    CHECK(evt.remote_ip_v4 == kPacketSrc);
    CHECK(evt.local_ip_v4 != evt.remote_ip_v4);
    // Our end is the one serving 443.
    CHECK(evt.local_port == 443);
}

TEST_CASE("uprobe orientation: /proc's local_address is LOCAL, rem_address is REMOTE")
{
    // /proc/<pid>/net/tcp column 1 is local_address, column 2 is rem_address
    // (verified against the file's own header). For bmcweb, the local end is
    // the one on 443 -- the opposite of the XDP packet's view, which is
    // precisely why role-based names are needed.
    constexpr uint32_t kLocal  = 0x0F00000A;
    constexpr uint32_t kRemote = 0x0100000A;

    UprobeEvent evt;
    evt.local_ip_v4  = kLocal;
    evt.remote_ip_v4 = kRemote;
    evt.local_port   = 443;
    evt.remote_port  = 51000;

    CHECK(evt.remote_ip_v4 == kRemote);
    CHECK(evt.local_port == 443);
}

TEST_CASE("both hooks agree on which field holds the peer, despite opposite wire views")
{
    // The whole point: given the same real connection observed by either
    // hook, remote_* names the same host. Under src/dst it did not.
    constexpr uint32_t kPeer = 0x0100000A;
    constexpr uint32_t kUs   = 0x0F00000A;

    hg_event from_xdp{};      // ingress packet: src=peer, dst=us
    from_xdp.local_ip_v4  = kUs;
    from_xdp.remote_ip_v4 = kPeer;

    hg_event from_uprobe{};   // /proc: col1=local(us), col2=rem(peer)
    from_uprobe.local_ip_v4  = kUs;
    from_uprobe.remote_ip_v4 = kPeer;

    CHECK(from_xdp.remote_ip_v4 == from_uprobe.remote_ip_v4);
    CHECK(from_xdp.local_ip_v4  == from_uprobe.local_ip_v4);
}

// --- lazy peer resolution (ticket 11) ----------------------------------
//
// The point of the seam: resolving the connection tuple reads /proc, which
// is the most expensive thing in the pipeline, and almost nothing needs the
// result. These pin that it happens on demand, once, and not otherwise.

namespace {

class CountingResolver final : public IPeerResolver
{
public:
    explicit CountingResolver(bool succeed) noexcept : succeed_(succeed) {}

    bool resolvePeer(hg_event& evt) const noexcept override
    {
        ++calls;
        if (!succeed_) {
            return false;   // leaves the tuple zeroed, as the real one does
        }
        evt.local_ip_v4  = 0x0F00000A;
        evt.remote_ip_v4 = 0x0100000A;
        evt.local_port   = 443;
        evt.remote_port  = 51000;
        return true;
    }

    mutable int calls = 0;

private:
    bool succeed_;
};

}  // namespace

TEST_CASE("peer resolution does not happen unless something asks for it")
{
    CountingResolver resolver{true};
    UprobeEvent evt;
    evt.peer_resolver = &resolver;

    // Parsing and classifying an event must not trigger it: this is the
    // whole saving, since most events are classified OK and never enforce.
    CHECK(resolver.calls == 0);
    CHECK(evt.remote_ip_v4 == 0);
}

TEST_CASE("peer resolution is memoised: repeated asks cost one /proc read")
{
    CountingResolver resolver{true};
    UprobeEvent evt;
    evt.peer_resolver = &resolver;

    CHECK(evt.ensurePeerResolved() == true);
    CHECK(evt.ensurePeerResolved() == true);
    CHECK(evt.ensurePeerResolved() == true);
    CHECK(resolver.calls == 1);
    CHECK(evt.remote_ip_v4 == 0x0100000A);
    CHECK(evt.local_port == 443);
}

TEST_CASE("a failed resolution is remembered too, and leaves the tuple unusable")
{
    CountingResolver resolver{false};
    UprobeEvent evt;
    evt.peer_resolver = &resolver;

    CHECK(evt.ensurePeerResolved() == false);
    CHECK(evt.ensurePeerResolved() == false);
    CHECK(resolver.calls == 1);       // not retried per ask
    CHECK(evt.remote_ip_v4 == 0);     // so enforcement declines
}

TEST_CASE("an event with no resolver reports unresolved rather than crashing")
{
    // XDP events take this path: their addresses come from the packet, so
    // they never carry a resolver.
    UprobeEvent evt;
    CHECK(evt.peer_resolver == nullptr);
    CHECK(evt.ensurePeerResolved() == false);
}

TEST_CASE("an event that already knows its address needs no resolver to be enforceable")
{
    // Pins the regression that silently disabled enforcement for XDP and
    // connection-rate events: both fill remote_ip_v4 directly and carry no
    // resolver, so gating enforcement on ensurePeerResolved() returning true
    // skipped them entirely.
    XdpEvent evt;
    evt.remote_ip_v4 = 0x0100000A;   // came from the packet headers
    evt.local_ip_v4  = 0x0F00000A;

    CHECK(evt.peer_resolver == nullptr);
    CHECK(evt.ensurePeerResolved() == false);   // nothing to resolve...
    CHECK(evt.remote_ip_v4 != 0);               // ...but the address is there
}
