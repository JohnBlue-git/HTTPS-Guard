#include <gtest/gtest.h>

#include "PayloadAnomalyDetector.hpp"
#include "PayloadEvent.hpp"
#include "PayloadAnomalyDetection.hpp"
#include "ssl_uprobe_event.h"

#include "../support/make_uprobe_event.hpp"

using namespace https_guard;
using https_guard::test_support::makeUprobeEvent;

TEST(PayloadAnomalyDetectorTest, FlagsSqlInjectionLookingPayloadAsWarning)
{
    PayloadEvent evt;
    evt.payload_snippet = "GET /redfish/v1?id=1 union select * from users";
    evt.meta.process = "bmcweb";
    evt.meta.pid = 42;

    PayloadAnomalyDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Warning");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected");
    EXPECT_TRUE(verdict->actionable);
}

TEST(PayloadAnomalyDetectorTest, DoesNotFlagOrdinaryRedfishRequest)
{
    PayloadEvent evt;
    evt.payload_snippet = "GET /redfish/v1/Managers/BMC HTTP/1.1";

    PayloadAnomalyDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(PayloadAnomalyDetectorTest, BoundaryMatchingIsCaseInsensitive)
{
    PayloadEvent evt;
    evt.payload_snippet = "GET /x?id=1 UNION SELECT password FROM users";

    PayloadAnomalyDetector detector;
    EXPECT_TRUE(detector.evaluate(evt).has_value());
}

TEST(PayloadAnomalyDetectorTest, BoundaryEmptyPayloadDoesNotMatch)
{
    PayloadEvent evt;
    evt.payload_snippet = "";

    PayloadAnomalyDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(PayloadAnomalyDetectionTest, ReadsThePlaintextTheUprobeCaptured)
{
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_READ, 0x0304, "bmcweb",
                                      "GET /redfish/v1?id=1 union select * from users");

    EventMeta meta;
    const PayloadAnomalyDetection<struct uprobe_event> detection;
    const auto verdict = detection.inspect(&raw, sizeof(raw), meta);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected");
    EXPECT_NE(verdict->message.find("union select"), std::string::npos);
    EXPECT_NE(verdict->message.find("bmcweb"), std::string::npos);
}
