#include <gtest/gtest.h>

#include <cstdint>

#include "TlsVersionDetector.hpp"
#include "TlsVersionEvent.hpp"
#include "TlsVersionDetection.hpp"
#include "ssl_uprobe_event.h"
#include "xdp_tls_event.h"

#include "../support/make_uprobe_event.hpp"

using namespace https_guard;
using https_guard::test_support::makeUprobeEvent;

TEST(TlsVersionDetectorTest, FlagsVersionBelowTls12AsCritical)
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0302;  // TLS 1.1
    evt.meta.process = "bmcweb";
    evt.meta.pid = 1234;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Critical");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsTlsVersionViolation");
    EXPECT_TRUE(verdict->actionable);
}

TEST(TlsVersionDetectorTest, DoesNotFlagTls13)
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0304;  // TLS 1.3

    TlsVersionDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(TlsVersionDetectorTest, BoundaryExactlyTls12IsNotViolation)
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0303;  // TLS 1.2, the threshold itself

    TlsVersionDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(TlsVersionDetectorTest, BoundaryZeroTlsVersionMeansNoData)
{
    TlsVersionEvent evt;
    evt.tls_version = 0;  // ssl->version was never resolved

    TlsVersionDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(TlsVersionDetectorTest, ViolationHintOverridesZeroTlsVersion)
{
    // A hook that classifies on the wire (XDP) can see a genuinely parsed
    // legacy_version of 0x0000 — that's a real violation, not "no data".
    TlsVersionEvent evt;
    evt.tls_version = 0;
    evt.violation_hint = true;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Critical");
    EXPECT_TRUE(verdict->actionable);
}

TEST(TlsVersionDetectionTest, DeclinesRecordTooShortForLayoutRatherThanMisreadingIt)
{
    const auto raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0301, "curl", "x");

    EventMeta meta;
    const TlsVersionDetection<struct uprobe_event> detection;
    // A byte short of the struct: must decline rather than read past the record.
    EXPECT_FALSE(detection.inspect(&raw, sizeof(raw) - 1, meta).has_value());
    EXPECT_FALSE(detection.inspect(nullptr, sizeof(raw), meta).has_value());
    // The full record does violate, so the decline above was about length.
    EXPECT_TRUE(detection.inspect(&raw, sizeof(raw), meta).has_value());
}

TEST(TlsVersionDetectionTest, DeclinesARecordFromTheOtherHook)
{
    // Not a type-system claim -- these are different template instantiations --
    // but a runtime one: each checks the record is long enough for ITS layout,
    // so a hook cannot accidentally feed the wrong one a short record and have
    // it read garbage. xdp_event is much larger than uprobe_event.
    const auto uprobe_raw = makeUprobeEvent(HG_UPROBE_DIR_WRITE, 0x0301, "curl", "x");

    EventMeta meta;
    const TlsVersionDetection<struct xdp_event> xdp_detection;
    EXPECT_FALSE(xdp_detection.inspect(&uprobe_raw, sizeof(uprobe_raw), meta).has_value());
}
