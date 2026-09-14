#include <gtest/gtest.h>

#include "PayloadAnomalyDetection.hpp"
#include "TlsVersionDetection.hpp"
#include "TrafficObservedDetection.hpp"
#include "ssl_uprobe_event.h"

#include "../support/make_uprobe_event.hpp"

using namespace https_guard;
using https_guard::test_support::makeUprobeEvent;

// A detection parses and evaluates in one step, so what a test can observe is
// the EventMeta it filled and the Verdict it returned. That is the whole of what
// the daemon acts on, and it is the real code path rather than a reimplementation
// of it -- which is why inspect() must stay linkable without the actions.

TEST(TrafficObservedDetectionTest, FillsTheSharedEnvelopeFromTheRawRecord)
{
    // Regression: the header fields were being dropped. timestamp_ns in
    // particular went nowhere, so RedfishEventMessage built every event's "Id"
    // and "EventId" from 0 -- meaning every emitted Redfish event shared the
    // same Id, which is exactly what an Id is for. The BPF side had been
    // capturing it correctly the whole time.
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0303, "bmcweb", "ok");

    EventMeta meta;
    const TrafficObservedDetection<struct uprobe_event> detection;
    const auto verdict = detection.inspect(&raw, sizeof(raw), meta);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(meta.timestamp_ns, 1700000000000000000ULL);
    EXPECT_EQ(meta.pid, 4242);
    EXPECT_EQ(meta.tgid, 4242);
    EXPECT_EQ(meta.process, "bmcweb");
}

TEST(TrafficObservedDetectionTest, CleanTrafficIsClaimedOnlyByTheTerminalEntry)
{
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0304, "bmcweb", "HTTP/1.1 200 OK");

    EventMeta meta;
    EXPECT_FALSE(TlsVersionDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta)
                     .has_value());
    EXPECT_FALSE(PayloadAnomalyDetection<struct uprobe_event>{}.inspect(&raw, sizeof(raw), meta)
                     .has_value());

    const auto observed = TrafficObservedDetection<struct uprobe_event>{}
                              .inspect(&raw, sizeof(raw), meta);
    ASSERT_TRUE(observed.has_value());
    EXPECT_EQ(observed->message_id, "OemSecurityEvent.1.0.HttpsTrafficObserved");
    EXPECT_EQ(observed->severity, "OK");
    EXPECT_FALSE(observed->actionable);
    EXPECT_NE(observed->message.find("TLS 1.3"), std::string::npos);
}
