#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

#include "https_guard_program.hpp"
#include "core/ActionLoop.hpp"
#include "log/LogAction.hpp"

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
};

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

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::filesystem::create_directories(std::filesystem::path(cfg.output_path).parent_path());

    https_guard::ActionLoop& action_loop = https_guard::ActionLoop::getInstance();
    action_loop.pushAction(std::make_unique<https_guard::LogAction>("HTTPS_GUARD_EVENT", cfg.output_path));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    https_guard::HttpGuardProgram program(
        cfg.bpf_object_path,
        action_loop,
        cfg.openssl_lib_path,
        if_nametoindex(cfg.iface.c_str()),
        std::chrono::duration_cast<std::chrono::seconds>(kDefaultBlocklistTtl),
        cfg.output_path);
    if (!program.loadFilter()) {
        std::cerr << "failed to initialize HTTPS Guard program\n";
        return 1;
    }

    std::cout << "HTTPS-Guard daemon started\n"
              << "  interface: " << cfg.iface << "\n"
              << "  ssl lib:   " << cfg.openssl_lib_path << "\n"
              << "  bpf obj:   " << cfg.bpf_object_path << "\n"
              << "  output:    " << cfg.output_path << "\n";

    while (!g_stop) {
        const int rc = program.pollEvents(200);
        if (rc == -EINTR) {
            break;
        }
    }

    return 0;
}
