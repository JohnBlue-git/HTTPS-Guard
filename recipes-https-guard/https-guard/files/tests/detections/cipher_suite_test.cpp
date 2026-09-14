#include <gtest/gtest.h>

#include "CipherSuiteDetector.hpp"
#include "CipherSuiteEvent.hpp"

using namespace https_guard;

TEST(CipherSuiteDetectorTest, FlagsAnOfferedRc4SuiteAsWarning)
{
    CipherSuiteEvent evt;
    evt.cipher_suites = {0x1301, 0x0005};  // TLS_AES_128_GCM_SHA256, RC4_128_SHA
    evt.cipher_suites_offered = 2;
    evt.meta.source_ip = "10.0.0.9";

    CipherSuiteDetector detector;
    const auto verdict = detector.evaluate(evt);

    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->severity, "Warning");
    EXPECT_EQ(verdict->message_id, "OemSecurityEvent.1.0.HttpsWeakCipherSuiteDetected");
    // Alert, never blocklist: the XDP blocklist is per source IP across all
    // ports, so enforcing here would lock admins out of SSH over a handshake
    // bmcweb refuses anyway. Live QEMU testing established this the hard way.
    EXPECT_FALSE(verdict->actionable);
    EXPECT_NE(verdict->message.find("RC4"), std::string::npos);
    EXPECT_NE(verdict->message.find("0x0005"), std::string::npos);
}

TEST(CipherSuiteDetectorTest, DoesNotFlagAModernOnlySuiteList)
{
    CipherSuiteEvent evt;
    evt.cipher_suites = {0x1301, 0x1302, 0x1303, 0xC02F, 0xC030};
    evt.cipher_suites_offered = 5;

    CipherSuiteDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(CipherSuiteDetectorTest, BoundaryAnEmptySuiteListMatchesNothing)
{
    // A non-XDP event never populates cipher_suites at all; the detector is
    // registered for XDP only, but must be inert rather than crash if it
    // ever sees one.
    CipherSuiteEvent evt;

    CipherSuiteDetector detector;
    EXPECT_FALSE(detector.evaluate(evt).has_value());
}

TEST(CipherSuiteDetectorTest, BoundaryFlagsNullEncryptionAndAnonymousKexSuitesToo)
{
    CipherSuiteEvent null_cipher;
    null_cipher.cipher_suites = {0x0002};  // TLS_RSA_WITH_NULL_SHA
    null_cipher.cipher_suites_offered = 1;

    CipherSuiteEvent anon_kex;
    anon_kex.cipher_suites = {0x0018};  // TLS_DH_anon_WITH_RC4_128_MD5
    anon_kex.cipher_suites_offered = 1;

    CipherSuiteDetector detector;
    const auto null_verdict = detector.evaluate(null_cipher);
    const auto anon_verdict = detector.evaluate(anon_kex);

    ASSERT_TRUE(null_verdict.has_value());
    EXPECT_NE(null_verdict->message.find("no encryption"), std::string::npos);
    ASSERT_TRUE(anon_verdict.has_value());
    EXPECT_NE(anon_verdict->message.find("anonymous"), std::string::npos);
}
