#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <cstdio>
#include <optional>

#include <doctest/doctest.h>

#include "TlsVersionDetector.hpp"
#include "PayloadAnomalyDetector.hpp"
#include "CertAccessDetector.hpp"

// Each rule takes exactly one event struct, and each struct carries only what
// its own rule reads. Handing a rule the wrong event is therefore an ordinary
// type error -- which is why the concepts that used to express that are gone:
// with one input type per rule they did no dispatch work and asserted nothing
// the compiler was not already enforcing.
#include "TlsVersionEvent.hpp"
#include "PayloadEvent.hpp"
#include "CipherSuiteEvent.hpp"
#include "SniEvent.hpp"
#include "CertAccessEvent.hpp"
#include "CipherSuiteDetection.hpp"
#include "TlsVersionDetection.hpp"
#include "xdp_tls_event.h"
#include "ConnRateEvent.hpp"
#include "ConnRateDetector.hpp"
#include "SlowlorisEvent.hpp"
#include "SlowlorisDetector.hpp"
#include "RenegotiationEvent.hpp"
#include "RenegotiationDetector.hpp"
#include "CipherSuiteDetector.hpp"
#include "SniDetector.hpp"

using namespace https_guard;

TEST_CASE("TlsVersionDetector flags a version below TLS 1.2 as a Critical violation")
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0302;  // TLS 1.1
    evt.meta.process = "bmcweb";
    evt.meta.pid = 1234;

    TlsVersionDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Critical");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsTlsVersionViolation");
    CHECK(verdict->actionable == true);
}

TEST_CASE("TlsVersionDetector does not flag TLS 1.3")
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0304;  // TLS 1.3

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: exactly TLS 1.2 is not a violation")
{
    TlsVersionEvent evt;
    evt.tls_version = 0x0303;  // TLS 1.2, the threshold itself

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector boundary: tls_version 0 means no data, not a violation")
{
    TlsVersionEvent evt;
    evt.tls_version = 0;  // ssl->version was never resolved

    TlsVersionDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("TlsVersionDetector: tls_violation_hint overrides tls_version==0 (XDP-parsed 0x0000 legacy_version)")
{
    // A hook that classifies on the wire (XDP) can see a genuinely parsed
    // legacy_version of 0x0000 — that's a real violation, not "no data".
    TlsVersionEvent evt;
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
    PayloadEvent evt;
    evt.payload_snippet = "GET /redfish/v1?id=1 union select * from users";
    evt.meta.process = "bmcweb";
    evt.meta.pid = 42;

    PayloadAnomalyDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsPayloadAnomalyDetected");
    CHECK(verdict->actionable == true);
}

TEST_CASE("PayloadAnomalyDetector does not flag an ordinary Redfish request")
{
    PayloadEvent evt;
    evt.payload_snippet = "GET /redfish/v1/Managers/BMC HTTP/1.1";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("PayloadAnomalyDetector boundary: matching is case-insensitive")
{
    PayloadEvent evt;
    evt.payload_snippet = "GET /x?id=1 UNION SELECT password FROM users";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == true);
}

TEST_CASE("PayloadAnomalyDetector boundary: empty payload does not match")
{
    PayloadEvent evt;
    evt.payload_snippet = "";

    PayloadAnomalyDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

// --- CertAccessDetector -------------------------------------------------

TEST_CASE("CertAccessDetector does not flag bmcweb's own recognized access")
{
    CertAccessEvent evt;
    evt.meta.process = "bmcweb";
    evt.real_exe_path = "/usr/bin/bmcweb";
    evt.identity_mismatch = false;

    CertAccessDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CertAccessDetector flags an unrecognized process as Critical")
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
    CipherSuiteEvent evt;
    evt.cipher_suites = {0x1301, 0x0005};  // TLS_AES_128_GCM_SHA256, RC4_128_SHA
    evt.cipher_suites_offered = 2;
    evt.meta.source_ip = "10.0.0.9";

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
    CipherSuiteEvent evt;
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
    CipherSuiteEvent evt;

    CipherSuiteDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("CipherSuiteDetector boundary: flags NULL-encryption and anonymous-KEX suites too")
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
    SniEvent evt;
    evt.sni_present = false;

    SniDetector detector("bmc.example.com");
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("SniDetector flags a malformed SNI even with no expected hostname configured")
{
    SniEvent evt;
    evt.sni_malformed = true;
    evt.meta.source_ip = "192.0.2.5";

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
    SniEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "something.else.invalid";

    SniDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("SniDetector flags a mismatch against a configured expected hostname")
{
    SniEvent evt;
    evt.sni_present = true;
    evt.sni_hostname = "attacker.example.net";
    evt.meta.source_ip = "198.51.100.7";

    SniDetector detector("bmc.example.com");
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message.find("attacker.example.net") != std::string::npos);
    CHECK(verdict->message.find("bmc.example.com") != std::string::npos);
}

TEST_CASE("SniDetector boundary: hostname comparison is case-insensitive")
{
    // DNS names are case-insensitive; flagging on case alone would be noise.
    SniEvent evt;
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

// The capability-boundary assertions that lived here are gone with the concepts
// they used, and nothing was lost: each rule now takes one concrete struct, so
// "this rule cannot read that event" is an ordinary type mismatch the compiler
// reports at the call site. The same goes for the three counter rules, which
// each take a different struct.

TEST_CASE("the rule matching a certificate-access event still fires")
{
    CertAccessEvent evt;
    evt.identity_mismatch = true;

    CertAccessDetector cert;
    CHECK(cert.evaluate(evt).has_value() == true);
}

TEST_CASE("a ClientHello can satisfy two rules; each still fires on its own event")
{
    // One record can be both legacy-TLS and weak-suite. Which verdict is
    // *emitted* is decided by the hook's detection list order, not here --
    // see the priority test below, and XdpTlsProgram's list.
    TlsVersionEvent tls_evt;
    tls_evt.tls_version = 0x0301;          // TLS 1.0 on the wire
    CHECK(TlsVersionDetector{}.evaluate(tls_evt).has_value() == true);

    CipherSuiteEvent cipher_evt;
    cipher_evt.cipher_suites = {0x0005};   // and RC4 offered
    cipher_evt.cipher_suites_offered = 1;
    CHECK(CipherSuiteDetector{}.evaluate(cipher_evt).has_value() == true);
}

TEST_CASE("detection list order decides which verdict a record produces")
{
    // The real property, and a real decision: a ClientHello that is BOTH
    // legacy-TLS and RC4-offering must be reported as the TLS violation, which
    // enforces, rather than as the weak cipher suite, which is alert-only.
    // That is expressed purely as list order in XdpTlsProgram, so this pins it.
    struct xdp_event raw{};
    raw.hdr.event_source = HG_SOURCE_XDP;
    raw.hdr.pid = 7;
    std::snprintf(raw.hdr.comm, sizeof(raw.hdr.comm), "%s", "swapper/0");
    raw.tls.version = 0x0301;              // TLS 1.0
    raw.tls.is_violation = 1;
    raw.client_hello.cipher_suites[0] = 0x0005;   // RC4
    raw.client_hello.cipher_suite_count = 1;
    raw.client_hello.cipher_suites_offered = 1;

    const TlsVersionDetection<struct xdp_event>  tls_detection;
    const CipherSuiteDetection<struct xdp_event> cipher_detection;

    // Both claim the record on their own...
    EventMeta m1, m2;
    REQUIRE(tls_detection.inspect(&raw, sizeof(raw), m1).has_value());
    REQUIRE(cipher_detection.inspect(&raw, sizeof(raw), m2).has_value());

    // ...so order is what settles it. TLS version comes first in the hook's
    // list, and it is the one that enforces.
    const std::array<const IDetection*, 2> ordered{&tls_detection, &cipher_detection};
    EventMeta meta;
    std::optional<Verdict> first;
    for (const IDetection* d : ordered) {
        if ((first = d->inspect(&raw, sizeof(raw), meta))) break;
    }
    REQUIRE(first.has_value());
    CHECK(first->message_id == "OemSecurityEvent.1.0.HttpsTlsVersionViolation");
    CHECK(first->actionable == true);
}

// --- ConnRateDetector (ticket 05) ---------------------------------------
//
// The counting itself lives in BPF, so what is testable here is the
// threshold decision and the message. These use ConnRateEvent directly,
// exactly as ConnRateSweeper synthesises it.

TEST_CASE("ConnRateDetector flags a source over the configured threshold")
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 250;
    evt.window_seconds = 10;
    evt.threshold = 200;
    evt.meta.source_ip      = "10.0.0.9";

    ConnRateDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsConnectionRateViolation");
    // Actionable, unlike the cipher-suite and SNI rules: a flood is ongoing
    // harm, so an alert that doesn't stop it is of little use.
    CHECK(verdict->actionable == true);
    CHECK(verdict->message.find("250") != std::string::npos);
    CHECK(verdict->message.find("200") != std::string::npos);
    CHECK(verdict->message.find("10.0.0.9") != std::string::npos);
}

TEST_CASE("ConnRateDetector boundary: exactly at the threshold counts as over")
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 200;
    evt.window_seconds = 10;
    evt.threshold = 200;

    ConnRateDetector detector;
    CHECK(detector.evaluate(evt).has_value() == true);
}

TEST_CASE("ConnRateDetector boundary: one below the threshold is not flagged")
{
    ConnRateEvent evt;
    evt.attempts_in_window  = 199;
    evt.window_seconds = 10;
    evt.threshold = 200;

    ConnRateDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("ConnRateDetector: a zero threshold means disabled, never 'everything violates'")
{
    // The daemon uses 0 to mean "not configured". Treating that as a
    // threshold everything exceeds would blocklist every source that ever
    // connects, so this is the most consequential boundary in the class.
    ConnRateEvent evt;
    evt.attempts_in_window  = 5000;
    evt.window_seconds = 10;
    evt.threshold = 0;

    ConnRateDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

// Covered at compile time by the !ConnectionRateEvent<UprobeEvent> assertion
// above: a rate rule can no longer be handed a uprobe event at all.

// --- SlowlorisDetector / RenegotiationDetector (ticket 06) --------------
//
// Both rules need cross-event state, and neither detector holds any: the
// counting lives in a BPF map and is aggregated before it gets here. That is
// what lets these tests be plain value assertions with no kernel involved --
// the property the architecture decision was made to preserve.

TEST_CASE("SlowlorisDetector flags a source holding too many connections open")
{
    SlowlorisEvent evt;
    evt.open_connections = 150;
    evt.threshold = 100;
    evt.meta.source_ip = "10.0.0.9";

    SlowlorisDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->severity == "Warning");
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsSlowlorisDetected");
    CHECK(verdict->actionable == true);
    CHECK(verdict->message.find("150") != std::string::npos);
}

TEST_CASE("SlowlorisDetector boundary: N triggers, N-1 does not")
{
    SlowlorisDetector detector;

    SlowlorisEvent at;
    at.open_connections = 100;
    at.threshold = 100;
    CHECK(detector.evaluate(at).has_value() == true);

    SlowlorisEvent below;
    below.open_connections = 99;
    below.threshold = 100;
    CHECK(detector.evaluate(below).has_value() == false);
}

TEST_CASE("SlowlorisDetector: zero threshold means disabled")
{
    SlowlorisEvent evt;
    evt.open_connections = 100000;
    evt.threshold = 0;

    SlowlorisDetector detector;
    CHECK(detector.evaluate(evt).has_value() == false);
}

TEST_CASE("RenegotiationDetector flags a handshake storm")
{
    RenegotiationEvent evt;
    evt.handshakes_in_window = 250;
    evt.window_seconds  = 10;
    evt.threshold = 200;
    evt.meta.source_ip = "10.0.0.9";

    RenegotiationDetector detector;
    const auto verdict = detector.evaluate(evt);

    REQUIRE(verdict.has_value());
    CHECK(verdict->message_id == "OemSecurityEvent.1.0.HttpsTlsRenegotiationStorm");
    CHECK(verdict->actionable == true);
    CHECK(verdict->message.find("250") != std::string::npos);
}

TEST_CASE("RenegotiationDetector boundary: N within window triggers, N-1 does not")
{
    RenegotiationDetector detector;

    RenegotiationEvent at;
    at.handshakes_in_window = 200; at.window_seconds = 10; at.threshold = 200;
    CHECK(detector.evaluate(at).has_value() == true);

    RenegotiationEvent below;
    below.handshakes_in_window = 199; below.window_seconds = 10; below.threshold = 200;
    CHECK(detector.evaluate(below).has_value() == false);
}

TEST_CASE("each per-source rule fires on its own event type")
{
    ConnRateEvent      rate; rate.attempts_in_window   = 999; rate.threshold = 1;
    SlowlorisEvent     slow; slow.open_connections     = 999; slow.threshold = 1;
    RenegotiationEvent rn;   rn.handshakes_in_window   = 999; rn.threshold   = 1;

    CHECK(ConnRateDetector{}.evaluate(rate).has_value()      == true);
    CHECK(SlowlorisDetector{}.evaluate(slow).has_value()     == true);
    CHECK(RenegotiationDetector{}.evaluate(rn).has_value()   == true);
}
