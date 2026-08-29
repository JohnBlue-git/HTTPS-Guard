#include <cstring>
#include <iostream>
#include <utility>

#include "SslUprobeProgram.hpp"
#include "ssl_uprobe_event.h"
#include "proc_peer_resolver.hpp"
#include "parse_uprobe_event.hpp"

namespace https_guard {

SslUprobeProgram::SslUprobeProgram(std::string openssl_lib_path) noexcept
    : openssl_lib_path_(std::move(openssl_lib_path))
{
}

namespace {

/* Attaches one uprobe/uretprobe by BPF program name + target function,
 * appending the resulting link on success. Shared by SSL_write and the
 * SSL_read entry/exit pair, which differ only in these four things. */
bool attachOneUprobe(bpf_object* obj, std::vector<bpf_link*>& links,
                      const char* bpf_prog_name, const char* target_func,
                      const std::string& lib_path, bool retprobe) noexcept
{
    bpf_program* prog = bpf_object__find_program_by_name(obj, bpf_prog_name);
    if (!prog) {
        std::cerr << "https_guard: uprobe program '" << bpf_prog_name
                  << "' not found in BPF object\n";
        return false;
    }

    bpf_uprobe_opts opts = {};
    opts.sz = sizeof(opts);
    opts.retprobe = retprobe;
    opts.func_name = target_func;

    bpf_link* link = bpf_program__attach_uprobe_opts(prog, -1, lib_path.c_str(), 0, &opts);
    if (!link || libbpf_get_error(link)) {
        int err = libbpf_get_error(link);
        std::cerr << "https_guard: failed to attach " << target_func
                  << (retprobe ? " (return)" : "") << " uprobe at '"
                  << lib_path << "' (err=" << err << ", " << strerror(-err) << ")\n";
        return false;
    }

    std::cerr << "https_guard: " << bpf_prog_name << " attached to " << lib_path
              << " (link fd=" << bpf_link__fd(link) << ")\n";
    links.push_back(link);
    return true;
}

}  // namespace

bool SslUprobeProgram::attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept
{
    // SSL_write is the PRIMARY detection mechanism on BMC platforms where
    // XDP may not be available (ASpeed AST2600 ftgmac100 NICs) -- its
    // attach outcome is this hook module's overall required signal.
    const bool have_write = attachOneUprobe(
        obj, links, "https_guard_ssl_write", "SSL_write", openssl_lib_path_, false);

    // SSL_read (the request-side mirror) is a bonus on top of SSL_write,
    // not a strict dependency -- if either half of its entry+return pair
    // fails to attach, log it but don't fail the whole hook module, since
    // SSL_write's detection still works fine without it.
    const bool have_read_entry = attachOneUprobe(
        obj, links, "https_guard_ssl_read_entry", "SSL_read", openssl_lib_path_, false);
    const bool have_read_exit = attachOneUprobe(
        obj, links, "https_guard_ssl_read_exit", "SSL_read", openssl_lib_path_, true);
    if (!have_read_entry || !have_read_exit) {
        std::cerr << "https_guard: SSL_read mirror did not fully attach"
                     " (non-fatal, SSL_write detection is unaffected)\n";
    }

    return have_write;
}

hg_event_source SslUprobeProgram::eventSource() const noexcept
{
    return HG_SOURCE_UPROBE;
}

std::optional<hg_event> SslUprobeProgram::parseEvent(const void* data, size_t size) const noexcept
{
    if (size < sizeof(struct uprobe_event)) {
        std::cerr << "https_guard: uprobe event too small: " << size << " bytes\n";
        return std::nullopt;
    }

    const auto* raw = static_cast<const struct uprobe_event*>(data);

    hg_event evt = parseUprobeEventFields(*raw);

    /* Resolve socket 4-tuple from /proc early so evt carries the full
     * picture for both logging and enforcement.  Prefer a connection to
     * port 443; fall back to the first entry if none match. */
    {
        const auto sockets = ProcPeerResolver::getTcpSockets(static_cast<pid_t>(evt.pid));
        if (!sockets.empty()) {
            const TcpSocketEntry* best = &sockets[0];
            for (const auto& sock : sockets) {
                if (sock.dst_port == 443) { best = &sock; break; }
            }
            evt.src_ip_v4 = best->src_ip_v4;
            evt.dst_ip_v4 = best->dst_ip_v4;
            evt.src_port  = best->src_port;
            evt.dst_port  = best->dst_port;
        }
    }

    std::cout << "https_guard: uprobe event received: process='" << evt.process
              << "' (PID " << evt.pid << "), direction=" << (evt.is_inbound ? "read" : "write")
              << ", tls_version=" << evt.tls_version << "\n";

    return evt;
}

}  // namespace https_guard
