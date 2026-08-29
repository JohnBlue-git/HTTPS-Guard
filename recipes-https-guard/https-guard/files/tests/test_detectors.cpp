#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "TlsVersionDetector.hpp"
#include "PayloadAnomalyDetector.hpp"
#include "CertAccessDetector.hpp"

using namespace https_guard;

TEST_CASE("TlsVersionDetector flags a version below TLS 1.2 as a Critical violation")
{
    hg_event evt{};
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
    hg_event evt{};
    evt.tls_version = 0x0304;  // TLS 1.3

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: exactly TLS 1.2 is not a violation")
{
    hg_event evt{};
    evt.tls_version = 0x0303;  // TLS 1.2, the threshold itself

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: tls_version 0 means no data, not a violation")
{
    hg_event evt{};
    evt.tls_version = 0;  // ssl->version was never resolved

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector: tls_violation_hint overrides tls_version==0 (XDP-parsed 0x0000 legacy_version)")
{
    // A hook that classifies on the wire (XDP) can see a genuinely parsed
    // legacy_version of 0x0000 — that's a real violation, not "no data".
    hg_event evt{};
    evt.tls_version = 0;
    evt.tls_violation_hint = true;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Critical");
    CHECK(verdict->actionable == true);
}

// --- PayloadAnomalyDetector -------------------------------------------

TEST_CASE("PayloadAnomalyDetector flags a SQL-injection-looking payload as a Warning")
{
    hg_event evt{};
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
    hg_event evt{};
    evt.payload_snippet = "GET /redfish/v1/Managers/BMC HTTP/1.1";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("PayloadAnomalyDetector boundary: matching is case-insensitive")
{
    hg_event evt{};
    evt.payload_snippet = "GET /x?id=1 UNION SELECT password FROM users";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == true);
}

TEST_CASE("PayloadAnomalyDetector boundary: empty payload does not match")
{
    hg_event evt{};
    evt.payload_snippet = "";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

// --- CertAccessDetector -------------------------------------------------

TEST_CASE("CertAccessDetector does not flag bmcweb's own recognized access")
{
    hg_event evt{};
    evt.process = "bmcweb";
    evt.real_exe_path = "/usr/bin/bmcweb";
    evt.cert_identity_mismatch = false;

    CertAccessDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CertAccessDetector flags an unrecognized process as Critical")
{
    hg_event evt{};
    evt.process = "evil";
    evt.pid = 999;
    evt.real_exe_path = "/tmp/evil";
    evt.cgroup_id = 7;
    evt.cert_identity_mismatch = true;
    evt.cert_shadow_mode = true;

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
    hg_event evt{};
    evt.cert_identity_mismatch = true;
    evt.cert_shadow_mode = false;

    CertAccessDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message.find("denied") != std::string::npos);
}
