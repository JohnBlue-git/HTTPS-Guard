#include <gtest/gtest.h>

#include "CertAccessDetector.hpp"
#include "CertAccessEvent.hpp"

using namespace https_guard;

TEST(CertAccessDetectorTest, DoesNotFlagBmcwebsOwnRecognizedAccess)
{
    CertAccessEvent evt;
    evt.meta.process = "bmcweb";
    evt.real_exe_path = "/usr/bin/bmcweb";
    evt.identity_mismatch = false;

    CertAccessDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(CertAccessDetectorTest, FlagsAnUnrecognizedProcessAsCritical)
{
    CertAccessEvent evt;
    evt.meta.process = "evil";
    evt.meta.pid = 999;
    evt.real_exe_path = "/tmp/evil";
    evt.cgroup_id = 7;
    evt.identity_mismatch = true;
    evt.shadow_mode = true;

    CertAccessDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Critical");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsCertificateAccessViolation");
    EXPECT_NE(verdict->message.find("/tmp/evil"), std::string::npos);
    EXPECT_NE(verdict->message.find("Shadow mode"), std::string::npos);
    // Not actionable: there's no TCP 4-tuple to blocklist for a local file
    // access, and any enforcement already happened in-kernel, before this
    // detector ever ran.
    EXPECT_FALSE(verdict->actionable);
}

TEST(CertAccessDetectorTest, BoundaryMessageDiffersOnceShadowModeIsOff)
{
    CertAccessEvent evt;
    evt.identity_mismatch = true;
    evt.shadow_mode = false;

    CertAccessDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_NE(verdict->message.find("denied"), std::string::npos);
}

TEST(CertAccessDetectorTest, TheRuleMatchingACertificateAccessEventStillFires)
{
    // Capability-boundary check (ticket 15): a detector asks for a
    // capability, not for a hook. Each rule now takes one concrete struct,
    // so "this rule cannot read that event" is an ordinary type mismatch the
    // compiler reports at the call site rather than something to assert here.
    CertAccessEvent evt;
    evt.identity_mismatch = true;

    CertAccessDetector cert;
    EXPECT_TRUE(cert.evaluate(evt).has_value());
}
