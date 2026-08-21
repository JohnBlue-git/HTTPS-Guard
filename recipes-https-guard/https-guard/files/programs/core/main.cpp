/*
 * HTTPS-Guard daemon - main entry point
 *
 */
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include "HttpGuardProgram.hpp"
#include "hg_event_source.h"
#include "core/ActionLoop.hpp"
#include "log/LogAction.hpp"
#include "TlsVersionDetector.hpp"
#include "PayloadAnomalyDetector.hpp"
#include "CertAccessDetector.hpp"
#include "ConnRateDetector.hpp"
#include "SlowlorisDetector.hpp"
#include "RenegotiationDetector.hpp"
#include "CipherSuiteDetector.hpp"
#include "SniDetector.hpp"
#include "SslUprobeProgram.hpp"
#include "XdpTlsProgram.hpp"
#include "LsmCertGuardProgram.hpp"

namespace {

volatile std::sig_atomic_t g_stop = 0;
constexpr auto kDefaultBlocklistTtl = std::chrono::minutes(5);

void on_signal(int)
{
    g_stop = 1;
}

struct runtime_config {
    std::string bpf_object_path;
    std::string iface;
    std::string openssl_lib_path;
    std::string output_path;
    std::string expected_sni;
    std::uint32_t rate_threshold      = 0;  /* 0 disables that rule */
    std::uint32_t slowloris_threshold = 0;
    std::uint32_t reneg_threshold     = 0;
};

// Composition root: this is the one place that knows about every concrete
// detector. Ordering within each source's vector is the priority order —
// first match wins — so the more severe/specific rules come first.
https_guard::HttpGuardProgram::DetectorRegistry buildDetectorRegistry(
    const std::string& expected_sni)
{
    auto sharedRules = [](std::vector<std::unique_ptr<https_guard::IDetector>>& rules) {
        rules.push_back(std::make_unique<https_guard::TlsVersionDetector>());
        rules.push_back(std::make_unique<https_guard::PayloadAnomalyDetector>());
    };

    https_guard::HttpGuardProgram::DetectorRegistry registry;

    std::vector<std::unique_ptr<https_guard::IDetector>> uprobeRules;
    sharedRules(uprobeRules);
    registry[HG_SOURCE_UPROBE] = std::move(uprobeRules);

    // XDP additionally gets the ClientHello-derived rules: only this hook
    // sees ClientHello bytes at all, so registering them elsewhere would
    // just evaluate permanently-empty fields.
    std::vector<std::unique_ptr<https_guard::IDetector>> xdpRules;
    sharedRules(xdpRules);
    xdpRules.push_back(std::make_unique<https_guard::CipherSuiteDetector>());
    xdpRules.push_back(std::make_unique<https_guard::SniDetector>(expected_sni));
    registry[HG_SOURCE_XDP] = std::move(xdpRules);

    std::vector<std::unique_ptr<https_guard::IDetector>> certAccessRules;
    certAccessRules.push_back(std::make_unique<https_guard::CertAccessDetector>());
    registry[HG_SOURCE_LSM_CERT_GUARD] = std::move(certAccessRules);

    // Connection-rate events have no hook module: they are synthesised in
    // userspace by ConnRateSweeper from the BPF counter map, then run through
    // this same registry. See conn_rate.bpf.h for why the decision is not
    // made in BPF.
    // All three per-source rules share this source: the sweeper synthesises a
    // different concrete event per rule, each carrying only its own
    // capability, so first-match-wins picks the right one -- the others see an
    // event without their capability and decline.
    std::vector<std::unique_ptr<https_guard::IDetector>> perSourceRules;
    perSourceRules.push_back(std::make_unique<https_guard::ConnRateDetector>());
    perSourceRules.push_back(std::make_unique<https_guard::SlowlorisDetector>());
    perSourceRules.push_back(std::make_unique<https_guard::RenegotiationDetector>());
    registry[HG_SOURCE_CONN_RATE] = std::move(perSourceRules);

    return registry;
}

// Composition root: this is the one place that knows about every concrete
// hook module. HttpGuardProgram only ever sees them through IHookModule —
// adding a new hook (e.g. an LSM cert-access guard) means adding one line
// here, not touching HttpGuardProgram's attach or dispatch logic.
std::vector<std::unique_ptr<https_guard::IHookModule>> buildHookModules(
    const std::string& openssl_lib_path, unsigned int ifindex)
{
    std::vector<std::unique_ptr<https_guard::IHookModule>> hooks;
    hooks.push_back(std::make_unique<https_guard::SslUprobeProgram>(openssl_lib_path));
    hooks.push_back(std::make_unique<https_guard::XdpTlsProgram>(ifindex));
    hooks.push_back(std::make_unique<https_guard::LsmCertGuardProgram>());
    return hooks;
}

}  // namespace

int main(int argc, char** argv)
{
    runtime_config cfg {
        .bpf_object_path = "./build/https_guard.bpf.o",
        .iface = "eth0",
        .openssl_lib_path = "/usr/lib/libssl.so.3",
        .output_path = "/var/log/redfish/https_guard_events.log",
    };

    if (argc > 1) {
        cfg.iface = argv[1];
    }
    if (argc > 2) {
        cfg.openssl_lib_path = argv[2];
    }
    if (argc > 3) {
        cfg.output_path = argv[3];
    }
    if (argc > 4) {
        cfg.bpf_object_path = argv[4];
    }
    // Optional: leaving this empty disables SNI *mismatch* checking (the
    // safe default — see SniDetector's class comment); malformed-SNI
    // detection is unconditional either way.
    if (argc > 5) {
        cfg.expected_sni = argv[5];
    }
    // Optional: connection-rate threshold. 0 (and anything unparseable)
    // leaves rate detection off, which is the safe default given a crossing
    // is actionable and blocklists the source on every port.
    if (argc > 6) {
        cfg.rate_threshold = static_cast<std::uint32_t>(std::strtoul(argv[6], nullptr, 10));
    }
    if (argc > 7) {
        cfg.slowloris_threshold = static_cast<std::uint32_t>(std::strtoul(argv[7], nullptr, 10));
    }
    if (argc > 8) {
        cfg.reneg_threshold = static_cast<std::uint32_t>(std::strtoul(argv[8], nullptr, 10));
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::filesystem::create_directories(std::filesystem::path(cfg.output_path).parent_path());

    https_guard::ActionLoop& action_loop = https_guard::ActionLoop::getInstance();
    action_loop.pushAction(std::make_unique<https_guard::LogAction>("HTTPS_GUARD_EVENT", cfg.output_path));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    https_guard::HttpGuardProgram program(
        cfg.bpf_object_path,
        action_loop,
        buildHookModules(cfg.openssl_lib_path, if_nametoindex(cfg.iface.c_str())),
        std::chrono::duration_cast<std::chrono::seconds>(kDefaultBlocklistTtl),
        cfg.output_path,
        buildDetectorRegistry(cfg.expected_sni));
    if (!program.loadFilter()) {
        std::cerr << "failed to initialize HTTPS Guard program\n";
        return 1;
    }

    /* After load, so the counter map exists to be swept. A zero threshold
     * leaves this inert. */
    program.enableRateSweeps(https_guard::ConnRateSweeper::Thresholds{
        cfg.rate_threshold, cfg.slowloris_threshold, cfg.reneg_threshold});

    std::cerr << "HTTPS-Guard daemon started\n"
              << "  interface: " << cfg.iface << "\n"
              << "  ssl lib:   " << cfg.openssl_lib_path << "\n"
              << "  bpf obj:   " << cfg.bpf_object_path << "\n"
              << "  output:    " << cfg.output_path << "\n"
              << "  expected SNI: "
              << (cfg.expected_sni.empty() ? "(unset — mismatch checking disabled)"
                                           : cfg.expected_sni)
              << "\n"
              << "  rate threshold: "
              << (cfg.rate_threshold == 0
                      ? std::string("(unset — connection-rate detection disabled)")
                      : std::to_string(cfg.rate_threshold))
              << "\n";

    while (!g_stop) {
        const int rc = program.pollEvents(200);
        if (rc == -EINTR) {
            break;
        }
        if (rc < 0) {
            std::cerr << "https_guard: pollEvents error: " << rc << " (" << strerror(-rc) << ")\n";
        }
    }

    return 0;
}
