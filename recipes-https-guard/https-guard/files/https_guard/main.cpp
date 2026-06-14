#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <string>
#include <vector>

#include "ActionLoop.hpp"
#include "LogAction.hpp"
#include "bpf_program.hpp"
#include "events.h"

namespace {

volatile std::sig_atomic_t g_stop = 0;

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

int on_event(void* ctx, void* data, size_t data_sz)
{
	if (data_sz < sizeof(hg_event)) {
		return 0;
	}

	const auto* evt = static_cast<const hg_event*>(data);
	auto* loop = static_cast<https_guard::ActionLoop*>(ctx);
	loop->handle(*evt);
	return 0;
}

}  // namespace

int main(int argc, char** argv)
{
	runtime_config cfg {
		.bpf_object_path = "./build/https_guard.bpf.o",
		.iface = "eth0",
		.openssl_lib_path = "/usr/lib/x86_64-linux-gnu/libssl.so.3",
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

	https_guard::ActionLoop action_loop;
	action_loop.add_action(std::make_unique<https_guard::LogAction>(cfg.output_path));

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	auto bpf_object = https_guard::BpfObject::openFile(cfg.bpf_object_path);
	if (!bpf_object) {
		std::cerr << "failed to open BPF object: " << cfg.bpf_object_path << "\n";
		return 1;
	}

	if (!bpf_object->load()) {
		std::cerr << "failed to load BPF object\n";
		return 1;
	}

	const unsigned int ifindex = if_nametoindex(cfg.iface.c_str());
	if (ifindex == 0) {
		std::cerr << "invalid interface: " << cfg.iface << "\n";
		return 1;
	}

	std::vector<https_guard::BpfProgram> programs;

	auto xdp_program = bpf_object->findProgramByName("https_guard_xdp");
	if (!xdp_program) {
		std::cerr << "xdp program not found\n";
		return 1;
	}
	if (!xdp_program->attachXdp(ifindex)) {
		std::cerr << "failed to attach xdp on " << cfg.iface << ": " << std::strerror(errno) << "\n";
		return 1;
	}
	programs.push_back(std::move(*xdp_program));

	auto uprobe_program = bpf_object->findProgramByName("https_guard_ssl_write");
	if (!uprobe_program) {
		std::cerr << "uprobe program not found\n";
		return 1;
	}
	if (!uprobe_program->attachUprobe(false, -1, cfg.openssl_lib_path, 0)) {
		std::cerr << "failed to attach uprobe on " << cfg.openssl_lib_path << ": " << std::strerror(errno) << "\n";
		return 1;
	}
	programs.push_back(std::move(*uprobe_program));

	bpf_map* events_map = bpf_object->findMapByName("events");
	if (!events_map) {
		std::cerr << "events map not found\n";
		return 1;
	}

	ring_buffer* rb = ring_buffer__new(
		bpf_map__fd(events_map),
		[](void* ctx, void* data, size_t size) -> int { return on_event(ctx, data, size); },
		&action_loop, nullptr);

	if (!rb) {
		std::cerr << "failed to create ring buffer\n";
		return 1;
	}

	std::cout << "HTTPS-Guard daemon started\n"
		  << "  interface: " << cfg.iface << "\n"
		  << "  ssl lib:   " << cfg.openssl_lib_path << "\n"
		  << "  bpf obj:   " << cfg.bpf_object_path << "\n"
		  << "  output:    " << cfg.output_path << "\n";

	while (!g_stop) {
		const int rc = ring_buffer__poll(rb, 200);
		if (rc == -EINTR) {
			break;
		}
	}

	ring_buffer__free(rb);
	return 0;
}
