#include <array>
#include <cstring>
#include <memory>
#include <iostream>
#include <unistd.h>

/* Explicit now that BpfProgram.hpp forward-declares bpf_object/bpf_link
 * instead of including libbpf -- the hooks are where libbpf is actually
 * used, so this is where the dependency belongs. */
#include <bpf/libbpf.h>

#include <cstddef>   // offsetof, for the ABI static_asserts below
#include "DetectLoop.hpp"
#include "LsmCertGuardProgram.hpp"
#include "lsm_cert_guard_event.h"

/* DetectLoop::process() reads a uint32 at offset 0 of the raw record to find
 * the owning hook, before it knows the type. Nesting hg_event_hdr must not
 * move that, so pin it here rather than trusting that nobody reorders the
 * members. */
static_assert(offsetof(struct lsm_cert_guard_event, hdr) == 0,
              "hg_event_hdr must be the first member of lsm_cert_guard_event");
static_assert(offsetof(struct hg_event_hdr, event_source) == 0,
              "event_source must be the first member of hg_event_hdr");

static_assert(sizeof(struct lsm_cert_guard_event) <= HG_MAX_RAW_EVENT_SIZE,
              "lsm_cert_guard_event outgrew HG_MAX_RAW_EVENT_SIZE; raise the cap in "
              "hg_event_source.h -- DetectLoop sizes its queue slots from it");

namespace https_guard {

void LsmCertGuardProgram::ringBufferHandler(const void* data, std::size_t size) noexcept
{
    DetectLoop::getInstance().submit(data, size, detections_);
}


namespace {

constexpr const char* kExpectedBmcwebExe = "/usr/bin/bmcweb";

// The one identity check strong enough to trust: the accessing process's
// REAL executable, resolved via /proc/<pid>/exe (a kernel-backed symlink
// to the same dentry task->mm->exe_file points at — not anything the
// process itself can spoof, unlike its self-reported comm). Can only run
// here, in userspace, after the fact — see lsm_cert_guard.bpf.h for why
// this can't run inside the BPF hook itself on this platform.

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


}  // namespace https_guard
