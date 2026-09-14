#include <gtest/gtest.h>

#include "ConnRateEvent.hpp"
#include "ConnRateDetector.hpp"
#include "SlowlorisEvent.hpp"
#include "SlowlorisDetector.hpp"
#include "RenegotiationEvent.hpp"
#include "RenegotiationDetector.hpp"

using namespace https_guard;

// The counting itself lives in BPF, so what is testable here is the
// threshold decision and the message. These use the event structs directly,
// exactly as ConnRateSweeper synthesises them.

// --- ConnRateDetector (ticket 05) ---------------------------------------

TEST(ConnRateDetectorTest, FlagsASourceOverTheConfiguredThreshold)
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 250;
    evt.window_seconds = 10;
    evt.threshold = 200;
    evt.meta.source_ip      = "10.0.0.9";

    ConnRateDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Warning");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsConnectionRateViolation");
    // Actionable, unlike the cipher-suite and SNI rules: a flood is ongoing
    // harm, so an alert that doesn't stop it is of little use.
    EXPECT_TRUE(verdict->actionable);
    EXPECT_NE(verdict->message.find("250"), std::string::npos);
    EXPECT_NE(verdict->message.find("200"), std::string::npos);
    EXPECT_NE(verdict->message.find("10.0.0.9"), std::string::npos);
}

TEST(ConnRateDetectorTest, BoundaryExactlyAtTheThresholdCountsAsOver)
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 200;
    evt.window_seconds = 10;
    evt.threshold = 200;

    ConnRateDetector detector;
    EXPECT_TRUE(detector.evaluate(evt).has_value());
}

TEST(ConnRateDetectorTest, BoundaryOneBelowTheThresholdIsNotFlagged)
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 199;
    evt.window_seconds = 10;
    evt.threshold = 200;

    ConnRateDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(ConnRateDetectorTest, ZeroThresholdMeansDisabledNeverEverythingViolates)
{
    // The daemon uses 0 to mean "not configured". Treating that as a
    // threshold everything exceeds would blocklist every source that ever
    // connects, so this is the most consequential boundary in the class.
    ConnRateEvent evt;
    evt.attempts_in_window  = 5000;
    evt.window_seconds = 10;
    evt.threshold = 0;

    ConnRateDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

// Covered at compile time by the !ConnectionRateEvent<UprobeEvent> assertion
// that used to live alongside these: a rate rule can no longer be handed a
// uprobe event at all.

// --- SlowlorisDetector / RenegotiationDetector (ticket 06) --------------
//
// Both rules need cross-event state, and neither detector holds any: the
// counting lives in a BPF map and is aggregated before it gets here. That is
// what lets these tests be plain value assertions with no kernel involved --
// the property the architecture decision was made to preserve.

TEST(SlowlorisDetectorTest, FlagsASourceHoldingTooManyConnectionsOpen)
{
    SlowlorisEvent evt;
    evt.open_connections = 150;
    evt.threshold = 100;
    evt.meta.source_ip = "10.0.0.9";

    SlowlorisDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Warning");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsSlowlorisDetected");
    EXPECT_TRUE(verdict->actionable);
    EXPECT_NE(verdict->message.find("150"), std::string::npos);
}

TEST(SlowlorisDetectorTest, BoundaryNTriggersNMinusOneDoesNot)
{
    SlowlorisDetector detector;

    SlowlorisEvent at;
    at.open_connections = 100;
    at.threshold = 100;
    EXPECT_TRUE(detector.evaluate(at).has_value());

    SlowlorisEvent below;
    below.open_connections = 99;
    below.threshold = 100;
    EXPECT_FALSE(detector.evaluate(below).has_value());
}

TEST(SlowlorisDetectorTest, ZeroThresholdMeansDisabled)
{
    SlowlorisEvent evt;
    evt.open_connections = 100000;
    evt.threshold = 0;

    SlowlorisDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(RenegotiationDetectorTest, FlagsAHandshakeStorm)
{
    RenegotiationEvent evt;
    evt.handshakes_in_window = 250;
    evt.window_seconds  = 10;
    evt.threshold = 200;
    evt.meta.source_ip = "10.0.0.9";

    RenegotiationDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm");
    EXPECT_TRUE(verdict->actionable);
    EXPECT_NE(verdict->message.find("250"), std::string::npos);
}

TEST(RenegotiationDetectorTest, BoundaryNWithinWindowTriggersNMinusOneDoesNot)
{
    RenegotiationDetector detector;

    RenegotiationEvent at;
    at.handshakes_in_window = 200; at.window_seconds = 10; at.threshold = 200;
    EXPECT_TRUE(detector.evaluate(at).has_value());

    RenegotiationEvent below;
    below.handshakes_in_window = 199; below.window_seconds = 10; below.threshold = 200;
    EXPECT_FALSE(detector.evaluate(below).has_value());
}

TEST(RateSweepDetectorsTest, EachPerSourceRuleFiresOnItsOwnEventType)
{
    ConnRateEvent      rate; rate.attempts_in_window   = 999; rate.threshold = 1;
    SlowlorisEvent     slow; slow.open_connections     = 999; slow.threshold = 1;
    RenegotiationEvent rn;   rn.handshakes_in_window   = 999; rn.threshold   = 1;

    EXPECT_TRUE(ConnRateDetector{}.evaluate(rate).has_value());
    EXPECT_TRUE(SlowlorisDetector{}.evaluate(slow).has_value());
    EXPECT_TRUE(RenegotiationDetector{}.evaluate(rn).has_value());
}
