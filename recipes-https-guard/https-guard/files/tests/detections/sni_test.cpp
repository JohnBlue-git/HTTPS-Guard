#include <gtest/gtest.h>

#include "SniDetector.hpp"
#include "SniEvent.hpp"

using namespace https_guard;

TEST(SniDetectorTest, DoesNotFlagAnAbsentSni)
{
    // The normal case for a BMC reached by IP address — must stay silent,
    // or every legitimate connection would raise a Warning.
    SniEvent evt;
    evt.sni_present = false;

    SniDetector detector("bmc.example.com");
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(SniDetectorTest, FlagsAMalformedSniEvenWithNoExpectedHostnameConfigured)
{
    SniEvent evt;
    evt.sni_malformed = true;
    evt.meta.source_ip = "192.0.2.5";

    SniDetector detector;  // no expected hostname: mismatch checking off
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Warning");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsSniAnomalyDetected");
    EXPECT_FALSE(verdict->actionable);  // alert only, same rationale as CipherSuiteDetector
    EXPECT_NE(verdict->message.find("malformed"), std::string::npos);
}

TEST(SniDetectorTest, DoesNotFlagAMismatchWhenNoExpectedHostnameIsConfigured)
{
    // Opt-in by design: unset means "any hostname is acceptable".
    SniEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "something.else.invalid";

    SniDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(SniDetectorTest, FlagsAMismatchAgainstAConfiguredExpectedHostname)
{
    SniEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "attacker.example.net";
    evt.meta.source_ip = "198.51.100.7";

    SniDetector detector("bmc.example.com");
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_NE(verdict->message.find("attacker.example.net"), std::string::npos);
    EXPECT_NE(verdict->message.find("bmc.example.com"), std::string::npos);
}

TEST(SniDetectorTest, BoundaryHostnameComparisonIsCaseInsensitive)
{
    // DNS names are case-insensitive; flagging on case alone would be noise.
    SniEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "BMC.Example.COM";

    SniDetector detector("bmc.example.com");
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}
