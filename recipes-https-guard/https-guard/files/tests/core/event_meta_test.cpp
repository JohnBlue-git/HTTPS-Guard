#include <gtest/gtest.h>

#include <cstdint>

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

    EXPECT_EQ(meta.remote_ip_v4, kPeer);
    EXPECT_EQ(meta.local_ip_v4, kUs);
    EXPECT_EQ(meta.local_port, 443);
    EXPECT_EQ(meta.remote_port, 51000);
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

TEST(EventMetaTest, PeerResolutionDoesNotHappenDuringParsing)
{
    // The whole saving: reading /proc is the most expensive thing in the
    // pipeline, and only the enforcing path needs the result.
    CountingResolver resolver{true};
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");

    EventMeta meta;
    const TrafficObservedDetection<struct uprobe_event> detection{&resolver};
    (void)detection.inspect(&raw, sizeof(raw), meta);

    EXPECT_EQ(resolver.calls, 0);
    EXPECT_EQ(meta.peer_resolver, &resolver);
    EXPECT_EQ(meta.remote_ip_v4, 0u);
}

TEST(EventMetaTest, PeerResolutionIsMemoisedRepeatedAsksCostOneProcRead)
{
    CountingResolver resolver{true};
    EventMeta meta;
    meta.peer_resolver = &resolver;

    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_TRUE(meta.ensurePeerResolved());
    EXPECT_EQ(resolver.calls, 1);
    EXPECT_EQ(meta.remote_ip_v4, 0x0100000A);
}

TEST(EventMetaTest, AFailedResolutionIsRememberedNotRetried)
{
    CountingResolver resolver{false};
    EventMeta meta;
    meta.peer_resolver = &resolver;

    EXPECT_FALSE(meta.ensurePeerResolved());
    EXPECT_FALSE(meta.ensurePeerResolved());
    EXPECT_EQ(resolver.calls, 1);
    EXPECT_EQ(meta.remote_ip_v4, 0u);   // fail-closed: nothing to enforce against
}

TEST(EventMetaTest, AnEventThatAlreadyKnowsItsAddressNeedsNoResolverToEnforce)
{
    // Pins the regression that silently disabled enforcement for XDP and
    // connection-rate events: both fill remote_ip_v4 directly and carry no
    // resolver, so gating enforcement on ensurePeerResolved() returning true
    // skipped them entirely.
    EventMeta meta;
    meta.remote_ip_v4 = 0x0100000A;
    meta.local_ip_v4  = 0x0F00000A;

    EXPECT_EQ(meta.peer_resolver, nullptr);
    EXPECT_FALSE(meta.ensurePeerResolved());   // nothing to resolve...
    EXPECT_NE(meta.remote_ip_v4, 0u);          // ...but the address is there
}
