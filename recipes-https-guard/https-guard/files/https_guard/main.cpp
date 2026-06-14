#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <net/if.h>
#include <string>
#include <vector>

#include "events.h"
#include "string_utils.hpp"
#include "pattern_detector.hpp"
#include "redfish_formatter.hpp"

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int)
{
	g_stop = 1;
}

void append_line(const std::string& output_path, const std::string& line)
{
	std::ofstream ofs(output_path, std::ios::app);
	ofs << line << "\n";
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

	const auto* evt = static_cast<hg_event*>(data);
	const std::string output_path = static_cast<const char*>(ctx);

	std::string severity = "OK";
	std::string message_id;
	std::string message;

	if (evt->event_type == HG_EVENT_TLS_VERSION_VIOLATION) {
		severity = "Critical";
		message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
		message = "Security violation: Process '" + std::string(evt->process) + "' (PID " +
				  std::to_string(evt->pid) + ") attempted an HTTPS connection using an insecure TLS version (" +
				  https_guard::tls_version_to_string(evt->tls_version) + "). Packet was blocked.";
	} else if (evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED ||
			   evt->event_type == HG_EVENT_HTTP_PAYLOAD_OBSERVED) {
		std::string matched_rule;
		const bool suspicious = https_guard::is_http_payload_suspicious(evt->payload_snippet, matched_rule) ||
								evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED;

		if (!suspicious) {
			return 0;
		}
		if (matched_rule.empty()) {
			matched_rule = "kernel-signature";
		}

		severity = "Warning";
		message_id = "OemSecurityEvent.1.0.0.HttpsPayloadAnomalyDetected";
		message = "Attack signature detected from process '" + std::string(evt->process) + "' (PID " +
				  std::to_string(evt->pid) + "), rule '" + matched_rule +
				  "'. Connection should be terminated or quarantined.";
	} else {
		return 0;
	}

	std::string redfish_payload = https_guard::format_redfish_event(*evt, message_id, message, severity);
	append_line(output_path, redfish_payload);

	std::cout << "[HTTPS-Guard] " << message << "\n";
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

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	bpf_object* obj = bpf_object__open_file(cfg.bpf_object_path.c_str(), nullptr);
	if (!obj) {
		std::cerr << "failed to open BPF object: " << cfg.bpf_object_path << "\n";
		return 1;
	}

	if (bpf_object__load(obj) != 0) {
		std::cerr << "failed to load BPF object\n";
		bpf_object__close(obj);
		return 1;
	}

	std::vector<bpf_link*> links;

	const unsigned int ifindex = if_nametoindex(cfg.iface.c_str());
	if (ifindex == 0) {
		std::cerr << "invalid interface: " << cfg.iface << "\n";
		bpf_object__close(obj);
		return 1;
	}

	bpf_program* xdp_prog = bpf_object__find_program_by_name(obj, "https_guard_xdp");
	if (!xdp_prog) {
		std::cerr << "xdp program not found\n";
		bpf_object__close(obj);
		return 1;
	}
	if (bpf_link* xdp_link = bpf_program__attach_xdp(xdp_prog, ifindex)) {
		links.push_back(xdp_link);
	} else {
		std::cerr << "failed to attach xdp on " << cfg.iface << ": " << std::strerror(errno) << "\n";
	}

	bpf_program* uprobe_prog = bpf_object__find_program_by_name(obj, "https_guard_ssl_write");
	if (!uprobe_prog) {
		std::cerr << "uprobe program not found\n";
		bpf_object__close(obj);
		return 1;
	}
	if (bpf_link* uprobe_link =
			bpf_program__attach_uprobe(uprobe_prog, false, -1, cfg.openssl_lib_path.c_str(), 0)) {
		links.push_back(uprobe_link);
	} else {
		std::cerr << "failed to attach uprobe on " << cfg.openssl_lib_path << ": "
				  << std::strerror(errno) << "\n";
	}

	if (links.empty()) {
		std::cerr << "no bpf program attached\n";
		bpf_object__close(obj);
		return 1;
	}

	bpf_map* events_map = bpf_object__find_map_by_name(obj, "events");
	if (!events_map) {
		std::cerr << "events map not found\n";
		bpf_object__close(obj);
		return 1;
	}

	ring_buffer* rb = ring_buffer__new(
		bpf_map__fd(events_map),
		[](void* ctx, void* data, size_t size) -> int { return on_event(ctx, data, size); },
		const_cast<char*>(cfg.output_path.c_str()), nullptr);

	if (!rb) {
		std::cerr << "failed to create ring buffer\n";
		bpf_object__close(obj);
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
	for (bpf_link* link : links) {
		bpf_link__destroy(link);
	}
	bpf_object__close(obj);
	return 0;
}