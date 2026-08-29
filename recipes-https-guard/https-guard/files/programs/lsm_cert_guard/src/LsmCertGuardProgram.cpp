#include <array>
#include <cstring>
#include <memory>
#include <iostream>
#include <unistd.h>

/* Explicit now that IHookModule.hpp forward-declares bpf_object/bpf_link
 * instead of including libbpf -- the hooks are where libbpf is actually
 * used, so this is where the dependency belongs. */
#include <bpf/libbpf.h>

#include "LsmCertGuardProgram.hpp"
#include "lsm_cert_guard_event.h"
#include "cert_access_hg_event.hpp"
#include "bounded_string.hpp"

static_assert(sizeof(struct lsm_cert_guard_event) <= HG_MAX_RAW_EVENT_SIZE,
              "lsm_cert_guard_event outgrew HG_MAX_RAW_EVENT_SIZE; raise the cap in "
              "hg_event_source.h -- DetectLoop sizes its queue slots from it");

namespace https_guard {

namespace {

constexpr const char* kExpectedBmcwebExe = "/usr/bin/bmcweb";

// The one identity check strong enough to trust: the accessing process's
// REAL executable, resolved via /proc/<pid>/exe (a kernel-backed symlink
// to the same dentry task->mm->exe_file points at — not anything the
// process itself can spoof, unlike its self-reported comm). Can only run
// here, in userspace, after the fact — see lsm_cert_guard.bpf.h for why
// this can't run inside the BPF hook itself on this platform.
std::string resolveRealExePath(uint32_t pid)
{
    std::array<char, 256> buf{};
    const std::string procExePath = "/proc/" + std::to_string(pid) + "/exe";
    const ssize_t len = readlink(procExePath.c_str(), buf.data(), buf.size() - 1);
    if (len <= 0) {
        return {};  // process likely exited already; nothing to resolve
    }
    return std::string(buf.data(), static_cast<size_t>(len));
}

}  // namespace

bool LsmCertGuardProgram::attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept
{
    bpf_program* prog = bpf_object__find_program_by_name(obj, "https_guard_cert_open");
    if (!prog) {
        std::cerr << "https_guard: LSM cert-access-guard program not found; "
                     "certificate access will not be observed\n";
        return false;
    }

    bpf_link* link = bpf_program__attach_lsm(prog);
    if (!link) {
        std::cerr << "https_guard: failed to attach LSM cert-access-guard (non-fatal): "
                  << strerror(errno) << "\n";
        return false;
    }

    links.push_back(link);
    std::cout << "https_guard: LSM cert-access-guard attached (shadow mode)\n";
    return true;
}

hg_event_source LsmCertGuardProgram::eventSource() const noexcept
{
    return HG_SOURCE_LSM_CERT_GUARD;
}

std::unique_ptr<hg_event> LsmCertGuardProgram::parseEvent(const void* data, size_t size) const noexcept
{
    if (size < sizeof(struct lsm_cert_guard_event)) {
        std::cerr << "https_guard: lsm cert-guard event too small: " << size << " bytes\n";
        return nullptr;
    }

    const auto* raw = static_cast<const struct lsm_cert_guard_event*>(data);

    auto owned = std::make_unique<CertAccessEvent>();
    CertAccessEvent& evt = *owned;
    evt.pid              = raw->pid;
    evt.tgid             = raw->tgid;
    evt.cgroup_id        = raw->cgroup_id;
    evt.shadow_mode      = (raw->shadow_mode != 0);
    evt.process          = boundedString(raw->comm);

    evt.real_exe_path = resolveRealExePath(raw->pid);
    // The real check: trust the kernel-backed /proc/<pid>/exe resolution,
    // not the BPF hook's own comm-based pre-check (raw->comm_mismatch),
    // which exists only to give the (never-enabled) shadow-mode
    // enforcement branch something real to gate on — see
    // lsm_cert_guard.bpf.h. An empty real_exe_path (process already
    // exited by the time we got here) can't be trusted either way, so
    // it's treated as a mismatch: silently trusting "unknown" would
    // defeat the point of this detector.
    evt.identity_mismatch      = (evt.real_exe_path != kExpectedBmcwebExe);

    std::cout << "https_guard: certificate access observed: process='" << evt.process
              << "' (PID " << evt.pid << "), real_exe='" << evt.real_exe_path
              << "', identity_mismatch=" << evt.identity_mismatch << "\n";

    return owned;
}

}  // namespace https_guard
