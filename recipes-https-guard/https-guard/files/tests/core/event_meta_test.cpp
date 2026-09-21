#include <gmock/gmock.h>

#include <arpa/inet.h>

#include <cstdint>
#include <cstring>

#include "IPeerResolver.hpp"
#include "TrafficObservedDetection.hpp"
#include "ssl_uprobe_event.h"
#include "xdp_tls_event.h"

#include "../support/make_uprobe_event.hpp"

using namespace https_guard;
using https_guard::test_support::makeUprobeEvent;

// --- the connection tuple, named by role ------------------------------------

TEST(EventMetaTest, BothSourcesAgreeOnWhichFieldHoldsThePeerDespiteOppositeWireViews)
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

    EXPECT_EQ(meta.remote_ip.v4(), kPeer);
    EXPECT_EQ(meta.local_ip.v4(), kUs);
    EXPECT_EQ(meta.remote_ip.family, IpFamily::kV4);
    EXPECT_EQ(meta.local_ip.family, IpFamily::kV4);
    EXPECT_EQ(meta.local_port, 443);
    EXPECT_EQ(meta.remote_port, 51000);
}

// --- ssl_uprobe's optionally-resolved tuple ---------------------------------

TEST(EventMetaTest, AResolvedUprobeTupleIsUsedDirectlyWithNoResolverCall)
{
    // The kernel-side session binding (a later ticket) sets resolved_conn
    // when it managed to bind this SSL session to a socket. This is the
    // fill step's half of that contract: present -> use it, and leave the
    // event in the same "already resolved" state an XDP event is in.
    auto raw = makeUprobeEvent(HG_UPROBE_DIR_READ, 0x0304, "bmcweb", "GET / HTTP/1.1");
    raw.resolved_conn.resolved = 1;
    raw.resolved_conn.is_ipv6  = 0;
    raw.resolved_conn.local_addr[0]  = 10; raw.resolved_conn.local_addr[1]  = 0;
    raw.resolved_conn.local_addr[2]  = 2;  raw.resolved_conn.local_addr[3]  = 15;
    raw.resolved_conn.remote_addr[0] = 10; raw.resolved_conn.remote_addr[1] = 0;
    raw.resolved_conn.remote_addr[2] = 2;  raw.resolved_conn.remote_addr[3] = 2;
    raw.resolved_conn.local_port  = 443;
    raw.resolved_conn.remote_port = 59690;

    EventMeta meta;
    (void)TrafficObservedDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta);

    EXPECT_EQ(meta.peer_resolver, nullptr);
    EXPECT_EQ(meta.local_ip.family, IpFamily::kV4);
    EXPECT_EQ(meta.local_ip.v4(), htonl(0x0A00020F));   // 10.0.2.15, network order
    EXPECT_EQ(meta.remote_ip.v4(), htonl(0x0A000202));  // 10.0.2.2, network order
    EXPECT_EQ(meta.local_port, 443);
    EXPECT_EQ(meta.remote_port, 59690);
}

TEST(EventMetaTest, AResolvedUprobeTupleCanBeIpv6)
{
    auto raw = makeUprobeEvent(HG_UPROBE_DIR_READ, 0x0304, "bmcweb", "GET / HTTP/1.1");
    raw.resolved_conn.resolved = 1;
    raw.resolved_conn.is_ipv6  = 1;
    const std::uint8_t local[16]  = {0x20, 0x01, 0x0d, 0xb8, 0,0,0,0,0,0,0,0,0,0,0, 0x01};
    const std::uint8_t remote[16] = {0x20, 0x01, 0x0d, 0xb8, 0,0,0,0,0,0,0,0,0,0,0, 0x02};
    std::memcpy(raw.resolved_conn.local_addr, local, 16);
    std::memcpy(raw.resolved_conn.remote_addr, remote, 16);
    raw.resolved_conn.local_port  = 443;
    raw.resolved_conn.remote_port = 59690;

    EventMeta meta;
    (void)TrafficObservedDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta);

    EXPECT_EQ(meta.peer_resolver, nullptr);
    EXPECT_EQ(meta.local_ip.family, IpFamily::kV6);
    EXPECT_EQ(meta.remote_ip.family, IpFamily::kV6);
    EXPECT_EQ(std::memcmp(meta.local_ip.bytes.data(), local, 16), 0);
    EXPECT_EQ(std::memcmp(meta.remote_ip.bytes.data(), remote, 16), 0);
}

TEST(EventMetaTest, AnUnresolvedUprobeTuplePreservesTodaysProcFallback)
{
    // resolved defaults to 0 (makeUprobeEvent value-initialises the whole
    // struct) -- this is every uprobe event today, before the kernel-side
    // binding ships. The fallback must be exactly what it is now: hand the
    // hook's own resolver to EventMeta, untouched.
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");
    ASSERT_EQ(raw.resolved_conn.resolved, 0);

    class StubResolver final : public IPeerResolver {
    public:
        bool resolvePeer(EventMeta&) const noexcept override { return false; }
    } resolver;

    EventMeta meta;
    (void)TrafficObservedDetection<struct uprobe_event>{&resolver}.inspect(&raw, sizeof(raw), meta);

    EXPECT_EQ(meta.peer_resolver, &resolver);
    EXPECT_FALSE(meta.remote_ip.isSet());
}

TEST(IpAddressTest, SetV4RoundTripsTheAddressAndTagsTheFamily)
{
    IpAddress addr;
    EXPECT_FALSE(addr.isSet());   // default-constructed: nothing written yet

    addr.setV4(0x0100000A);

    EXPECT_EQ(addr.family, IpFamily::kV4);
    EXPECT_EQ(addr.v4(), 0x0100000A);
    EXPECT_TRUE(addr.isSet());
}

TEST(IpAddressTest, CanRepresentAnIpv6AddressDistinctFromIpv4)
{
    // Exercises the representation directly, independent of any one
    // producer -- see EventMetaTest.AResolvedUprobeTupleCanBeIpv6 for the
    // producer that actually sets one via the fill step.
    IpAddress addr;
    addr.family = IpFamily::kV6;
    addr.bytes  = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};  // 2001:db8::1

    EXPECT_EQ(addr.family, IpFamily::kV6);
    EXPECT_TRUE(addr.isSet());
    // The first 4 bytes alone must not be mistaken for a v4 reading -- v4()
    // is only meaningful when family is kV4, which callers must check first.
    EXPECT_NE(addr.bytes[15], 0);  // the address's last byte carries real data
}

// --- lazy peer resolution ---------------------------------------------------

namespace {

class MockPeerResolver final : public IPeerResolver
{
public:
    MOCK_METHOD(bool, resolvePeer, (EventMeta&), (const, noexcept, override));
};

}  // namespace

TEST(EventMetaTest, PeerResolutionDoesNotHappenDuringParsing)
{
    // The whole saving: reading /proc is the most expensive thing in the
    // pipeline, and only the enforcing path needs the result.
    MockPeerResolver resolver;
    EXPECT_CALL(resolver, resolvePeer(::testing::_)).Times(0);
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");

    EventMeta meta;
    const TrafficObservedDetection<struct uprobe_event> detection{&resolver};
    (void)detection.inspect(&raw, sizeof(raw), meta);

    EXPECT_EQ(meta.peer_resolver, &resolver);
    EXPECT_FALSE(meta.remote_ip.isSet());
}

TEST(EventMetaTest, PeerResolutionIsMemoisedRepeatedAsksCostOneProcRead)
{
    MockPeerResolver resolver;
    EventMeta meta;
    meta.peer_resolver = &resolver;

    EXPECT_CALL(resolver, resolvePeer(::testing::_))
        .Times(1)
        .WillOnce(::testing::Invoke([](EventMeta& resolved) noexcept {
            resolved.local_ip.setV4(0x0F00000A);
            resolved.remote_ip.setV4(0x0100000A);
            resolved.local_port  = 443;
            resolved.remote_port = 51000;
            return true;
        }));

    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_EQ(meta.remote_ip.v4(), 0x0100000A);
}

TEST(EventMetaTest, AFailedResolutionIsRememberedNotRetried)
{
    MockPeerResolver resolver;
    EventMeta meta;
    meta.peer_resolver = &resolver;

    EXPECT_CALL(resolver, resolvePeer(::testing::_))
        .Times(1)
        .WillOnce(::testing::Return(false));

    EXPECT_FALSE(meta.ensurePeerResolved());
    EXPECT_FALSE(meta.ensurePeerResolved());
    EXPECT_FALSE(meta.remote_ip.isSet());   // fail-closed: nothing to enforce against
}

TEST(EventMetaTest, AnEventThatAlreadyKnowsItsAddressNeedsNoResolverToEnforce)
{
    // Pins the regression that silently disabled enforcement for XDP and
    // connection-rate events: both fill remote_ip directly and carry no
    // resolver, so gating enforcement on ensurePeerResolved() returning true
    // skipped them entirely.
    EventMeta meta;
    meta.remote_ip.setV4(0x0100000A);
    meta.local_ip.setV4(0x0F00000A);

    EXPECT_EQ(meta.peer_resolver, nullptr);
    EXPECT_FALSE(meta.ensurePeerResolved());   // nothing to resolve...
    EXPECT_TRUE(meta.remote_ip.isSet());       // ...but the address is there
}
