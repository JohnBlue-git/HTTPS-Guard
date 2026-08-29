#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "TlsVersionDetector.hpp"
#include "PayloadAnomalyDetector.hpp"
#include "CertAccessDetector.hpp"

// Detectors bind to capability interfaces, so a test must build the
// concrete event a real hook would produce -- constructing a bare
// hg_event no longer compiles, which is the point of the split.
#include "uprobe_hg_event.hpp"
#include "xdp_hg_event.hpp"
#include "cert_access_hg_event.hpp"
#include "CipherSuiteDetector.hpp"
#include "SniDetector.hpp"

using namespace https_guard;

TEST_CASE("TlsVersionDetector flags a version below TLS 1.2 as a Critical violation")
{
    UprobeEvent evt;
    evt.tls_version = 0x0302;  // TLS 1.1
    evt.process = "bmcweb";
    evt.pid = 1234;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Critical");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsTlsVersionViolation");
    CHECK(verdict->actionable == true);
}

TEST_CASE("TlsVersionDetector does not flag TLS 1.3")
{
    UprobeEvent evt;
    evt.tls_version = 0x0304;  // TLS 1.3

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: exactly TLS 1.2 is not a violation")
{
    UprobeEvent evt;
    evt.tls_version = 0x0303;  // TLS 1.2, the threshold itself

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: tls_version 0 means no data, not a violation")
{
    UprobeEvent evt;
    evt.tls_version = 0;  // ssl->version was never resolved

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector: tls_violation_hint overrides tls_version==0 (XDP-parsed 0x0000 legacy_version)")
{
    // A hook that classifies on the wire (XDP) can see a genuinely parsed
    // legacy_version of 0x0000 — that's a real violation, not "no data".
    XdpEvent evt;
    evt.tls_version = 0;
    evt.violation_hint = true;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Critical");
    CHECK(verdict->actionable == true);
}

// --- PayloadAnomalyDetector -------------------------------------------

TEST_CASE("PayloadAnomalyDetector flags a SQL-injection-looking payload as a Warning")
{
    UprobeEvent evt;
    evt.payload_snippet = "GET /redfish/v1?id=1 union select * from users";
    evt.process = "bmcweb";
    evt.pid = 42;

    PayloadAnomalyDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected");
    CHECK(verdict->actionable == true);
}

TEST_CASE("PayloadAnomalyDetector does not flag an ordinary Redfish request")
{
    UprobeEvent evt;
    evt.payload_snippet = "GET /redfish/v1/Managers/BMC HTTP/1.1";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("PayloadAnomalyDetector boundary: matching is case-insensitive")
{
    UprobeEvent evt;
    evt.payload_snippet = "GET /x?id=1 UNION SELECT password FROM users";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == true);
}

TEST_CASE("PayloadAnomalyDetector boundary: empty payload does not match")
{
    UprobeEvent evt;
    evt.payload_snippet = "";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

// --- CertAccessDetector -------------------------------------------------

TEST_CASE("CertAccessDetector does not flag bmcweb's own recognized access")
{
    CertAccessEvent evt;
    evt.process = "bmcweb";
    evt.real_exe_path = "/usr/bin/bmcweb";
    evt.identity_mismatch = false;

    CertAccessDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CertAccessDetector flags an unrecognized process as Critical")
{
    CertAccessEvent evt;
    evt.process = "evil";
    evt.pid = 999;
    evt.real_exe_path = "/tmp/evil";
    evt.cgroup_id = 7;
    evt.identity_mismatch = true;
    evt.shadow_mode = true;

    CertAccessDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Critical");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsCertificateAccessViolation");
    CHECK(verdict->message.find("/tmp/evil") != std::string::npos);
    CHECK(verdict->message.find("Shadow mode") != std::string::npos);
    // Not actionable: there's no TCP 4-tuple to blocklist for a local file
    // access, and any enforcement already happened in-kernel, before this
    // detector ever ran.
    CHECK(verdict->actionable == false);
}

TEST_CASE("CertAccessDetector boundary: message differs once shadow mode is off")
{
    CertAccessEvent evt;
    evt.identity_mismatch = true;
    evt.shadow_mode = false;

    CertAccessDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message.find("denied") != std::string::npos);
}

// --- CipherSuiteDetector ------------------------------------------------

TEST_CASE("CipherSuiteDetector flags an offered RC4 suite as a Warning")
{
    XdpEvent evt;
    evt.cipher_suites = {0x1301, 0x0005};  // TLS_AES_128_GCM_SHA256, RC4_128_SHA
    evt.cipher_suites_offered = 2;
    evt.source_ip = "10.0.0.9";

    CipherSuiteDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsWeakCipherSuiteDetected");
    // Alert, never blocklist: the XDP blocklist is per source IP across all
    // ports, so enforcing here would lock admins out of SSH over a handshake
    // bmcweb refuses anyway. Live QEMU testing established this the hard way.
    CHECK(verdict->actionable == false);
    CHECK(verdict->message.find("RC4") != std::string::npos);
    CHECK(verdict->message.find("0x0005") != std::string::npos);
}

TEST_CASE("CipherSuiteDetector does not flag a modern-only suite list")
{
    XdpEvent evt;
    evt.cipher_suites = {0x1301, 0x1302, 0x1303, 0xC02F, 0xC030};
    evt.cipher_suites_offered = 5;

    CipherSuiteDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CipherSuiteDetector boundary: an empty suite list matches nothing")
{
    // A non-XDP event never populates cipher_suites at all; the detector is
    // registered for XDP only, but must be inert rather than crash if it
    // ever sees one.
    XdpEvent evt;

    CipherSuiteDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CipherSuiteDetector boundary: flags NULL-encryption and anonymous-KEX suites too")
{
    XdpEvent null_cipher;
    null_cipher.cipher_suites = {0x0002};  // TLS_RSA_WITH_NULL_SHA
    null_cipher.cipher_suites_offered = 1;

    XdpEvent anon_kex;
    anon_kex.cipher_suites = {0x0018};  // TLS_DH_anon_WITH_RC4_128_MD5
    anon_kex.cipher_suites_offered = 1;

    CipherSuiteDetector detector;
    const auto null_verdict = detector.evaluate(null_cipher);
    const auto anon_verdict = detector.evaluate(anon_kex);

    REQUIRE(null_verdict.has_value());
    CHECK(null_verdict->message.find("no encryption") != std::string::npos);
    REQUIRE(anon_verdict.has_value());
    CHECK(anon_verdict->message.find("anonymous") != std::string::npos);
}

// --- SniDetector --------------------------------------------------------

TEST_CASE("SniDetector does not flag an absent SNI")
{
    // The normal case for a BMC reached by IP address — must stay silent,
    // or every legitimate connection would raise a Warning.
    XdpEvent evt;
    evt.sni_present = false;

    SniDetector detector("bmc.example.com");
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("SniDetector flags a malformed SNI even with no expected hostname configured")
{
    XdpEvent evt;
    evt.sni_malformed = true;
    evt.source_ip = "192.0.2.5";

    SniDetector detector;  // no expected hostname: mismatch checking off
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsSniAnomalyDetected");
    CHECK(verdict->actionable == false);  // alert only, same rationale as CipherSuiteDetector
    CHECK(verdict->message.find("malformed") != std::string::npos);
}

TEST_CASE("SniDetector does not flag a mismatch when no expected hostname is configured")
{
    // Opt-in by design: unset means "any hostname is acceptable".
    XdpEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "something.else.invalid";

    SniDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("SniDetector flags a mismatch against a configured expected hostname")
{
    XdpEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "attacker.example.net";
    evt.source_ip = "198.51.100.7";

    SniDetector detector("bmc.example.com");
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message.find("attacker.example.net") != std::string::npos);
    CHECK(verdict->message.find("bmc.example.com") != std::string::npos);
}

TEST_CASE("SniDetector boundary: hostname comparison is case-insensitive")
{
    // DNS names are case-insensitive; flagging on case alone would be noise.
    XdpEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "BMC.Example.COM";

    SniDetector detector("bmc.example.com");
    CHECK(detector.evaluate(evt).has_value() == false);
}

// --- capability boundary (ticket 15) -----------------------------------
//
// The property the split exists to provide: a detector asks for a
// capability, not for a hook. These assert that an event which cannot
// supply a capability is declined rather than misread — and that a rule
// tied to one capability ignores events carrying only the other.

TEST_CASE("a certificate-access event has no TLS capability, so TLS rules decline it")
{
    // Previously this event would have carried tls_version = 0 and a
    // cipher-suite vector, and the TLS detector would have evaluated them.
    CertAccessEvent evt;
    evt.identity_mismatch = true;

    TlsVersionDetector tls;
    PayloadAnomalyDetector payload;
    CHECK(tls.evaluate(evt).has_value() == false);
    CHECK(payload.evaluate(evt).has_value() == false);

    // ...while the rule that does match its capability still fires.
    CertAccessDetector cert;
    CHECK(cert.evaluate(evt).has_value() == true);
}

TEST_CASE("a uprobe event has no ClientHello capability, so those rules decline it")
{
    UprobeEvent evt;
    evt.tls_version = 0x0304;
    evt.payload_snippet = "GET / HTTP/1.1";

    CipherSuiteDetector cipher;
    SniDetector sni{"bmc.example.com"};
    CHECK(cipher.evaluate(evt).has_value() == false);
    CHECK(sni.evaluate(evt).has_value() == false);
}

TEST_CASE("an XDP event supplies both capabilities, so both families apply")
{
    XdpEvent evt;
    evt.tls_version = 0x0301;             // TLS 1.0 on the wire
    evt.cipher_suites = {0x0005};         // and RC4 offered
    evt.cipher_suites_offered = 1;

    TlsVersionDetector tls;
    CipherSuiteDetector cipher;
    CHECK(tls.evaluate(evt).has_value() == true);
    CHECK(cipher.evaluate(evt).has_value() == true);
}
