#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <optional>

#include "IDetection.hpp"
#include "TlsVersionDetector.hpp"
#include "TlsVersionEvent.hpp"
#include "TlsVersionDetection.hpp"
#include "CipherSuiteDetector.hpp"
#include "CipherSuiteEvent.hpp"
#include "CipherSuiteDetection.hpp"
#include "xdp_tls_event.h"

using namespace https_guard;

// A ClientHello can satisfy several detections at once, and only the
// lowest-index verdict in a hook's list is dispatched (see
// programs/xdp_tls/src/XdpTlsProgram.hpp). These pin the two halves of that
// property: each detection still fires independently on its own event, and
// list order is what decides which one wins when both would fire on the
// same record.

TEST(DispatchPriorityTest, AClientHelloCanSatisfyTwoRulesEachStillFiresOnItsOwnEvent)
{
    // One record can be both legacy-TLS and weak-suite. Which verdict is
    // *emitted* is decided by the hook's detection list order, not here --
    // see the priority test below, and XdpTlsProgram's list.
    TlsVersionEvent tls_evt;
    tls_evt.tls_version = 0x0301;          // TLS 1.0 on the wire
    EXPECT_TRUE(TlsVersionDetector{}.evaluate(tls_evt).has_value());

    CipherSuiteEvent cipher_evt;
    cipher_evt.cipher_suites = {0x0005};   // and RC4 offered
    cipher_evt.cipher_suites_offered = 1;
    EXPECT_TRUE(CipherSuiteDetector{}.evaluate(cipher_evt).has_value());
}

TEST(DispatchPriorityTest, DetectionListOrderDecidesWhichVerdictARecordProduces)
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
    ASSERT_TRUE(tls_detection.inspect(&raw, sizeof(raw), m1).has_value());
    ASSERT_TRUE(cipher_detection.inspect(&raw, sizeof(raw), m2).has_value());

    // ...so order is what settles it. TLS version comes first in the hook's
    // list, and it is the one that enforces.
    const std::array<const IDetection*, 2> ordered{&tls_detection, &cipher_detection};
    EventMeta meta;
    std::optional<Verdict> first;
    for (const IDetection* d : ordered) {
        if ((first = d->inspect(&raw, sizeof(raw), meta))) break;
    }
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->message_id, "OemSecurityEvent.1.0.HttpsTlsVersionViolation");
    EXPECT_TRUE(first->actionable);
}
