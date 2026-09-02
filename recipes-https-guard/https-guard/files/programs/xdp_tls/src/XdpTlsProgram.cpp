#include <cstring>
#include <memory>
#include <iostream>
#include <utility>

#include <linux/if_link.h>  /* XDP_FLAGS_SKB_MODE, XDP_FLAGS_UPDATE_IF_NOEXIST */

/* Explicit now that BpfProgram.hpp forward-declares bpf_object/bpf_link
 * instead of including libbpf -- the hooks are where libbpf is actually
 * used, so this is where the dependency belongs. */
#include <bpf/bpf.h>       /* bpf_prog_get_fd_by_id, bpf_prog_get_info_by_fd */
#include <bpf/libbpf.h>
#include <unistd.h>        /* close() for the queried program fd */

#include <cstddef>   // offsetof, for the ABI static_asserts below
#include "DetectLoop.hpp"
#include "XdpTlsProgram.hpp"
#include "xdp_tls_event.h"

/* DetectLoop::process() reads a uint32 at offset 0 of the raw record to find
 * the owning hook, before it knows the type. Nesting hg_event_hdr must not
 * move that, so pin it here rather than trusting that nobody reorders the
 * members. */
static_assert(offsetof(struct xdp_event, hdr) == 0,
              "hg_event_hdr must be the first member of xdp_event");
static_assert(offsetof(struct hg_event_hdr, event_source) == 0,
              "event_source must be the first member of hg_event_hdr");

static_assert(sizeof(struct xdp_event) <= HG_MAX_RAW_EVENT_SIZE,
              "xdp_event outgrew HG_MAX_RAW_EVENT_SIZE; raise the cap in "
              "hg_event_source.h -- DetectLoop sizes its queue slots from it");

namespace https_guard {

XdpTlsProgram::XdpTlsProgram(unsigned int ifindex, std::string expected_sni) noexcept
    : BpfProgram("xdp_tls")
    , ifindex_(ifindex)
    , sni_(std::move(expected_sni))
{
}

void XdpTlsProgram::ringBufferHandler(const void* data, std::size_t size) noexcept
{
    DetectLoop::getInstance().submit(data, size, detections_);
}

XdpTlsProgram::~XdpTlsProgram() noexcept
{
    if (!owns_legacy_attachment_)
    {
        return;  // link-based: the kernel detaches when the link fd closes
    }

    // Legacy path only. Without this the attachment outlives the process and
    // the next start cannot attach at all.
    const int err = bpf_xdp_detach(ifindex_, 0, nullptr);
    if (err)
    {
        std::cerr << "https_guard: failed to detach XDP program from ifindex "
                  << ifindex_ << " (" << strerror(-err)
                  << "); a restart may report 'XDP program already attached'\n";
    }
    else
    {
        std::cout << "https_guard: XDP program detached from ifindex " << ifindex_ << "\n";
    }
}

void XdpTlsProgram::clearStaleAttachment() noexcept
{
    bpf_xdp_query_opts query = {};
    query.sz = sizeof(query);

    if (bpf_xdp_query(static_cast<int>(ifindex_), 0, &query) != 0)
    {
        return;  // nothing attached, or the interface can't be queried
    }

    const __u32 prog_id = query.prog_id != 0 ? query.prog_id : query.skb_prog_id;
    if (prog_id == 0)
    {
        return;  // interface is free
    }

    // Identify it before removing it. Anything that isn't ours belongs to
    // another tool on this interface, and taking it down would swap our
    // outage for theirs.
    const int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0)
    {
        std::cerr << "https_guard: an XDP program (id " << prog_id
                  << ") is attached to ifindex " << ifindex_
                  << " but could not be identified; leaving it alone\n";
        return;
    }

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    const bool identified = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) == 0;
    const bool is_ours = identified && std::strncmp(info.name, "https_guard_xdp",
                                                    sizeof(info.name)) == 0;
    close(prog_fd);

    if (!is_ours)
    {
        std::cerr << "https_guard: ifindex " << ifindex_
                  << " already has an XDP program attached ('"
                  << (identified ? info.name : "unknown")
                  << "') that is not ours; refusing to replace it\n";
        return;
    }

    // A leaked attachment from a previous run of this daemon -- either from
    // before link-based attach was used, or a legacy-path instance that was
    // killed before its destructor ran.
    const int err = bpf_xdp_detach(static_cast<int>(ifindex_), 0, nullptr);
    if (err)
    {
        std::cerr << "https_guard: found a leaked https_guard XDP program on ifindex "
                  << ifindex_ << " but could not detach it (" << strerror(-err) << ")\n";
    }
    else
    {
        std::cout << "https_guard: cleared a leaked https_guard XDP program from ifindex "
                  << ifindex_ << " (left by a previous run)\n";
    }
}

bool XdpTlsProgram::attach(bpf_object* obj, std::vector<bpf_link*>& links) noexcept
{
    bpf_program* xdp_prog = bpf_object__find_program_by_name(obj, "https_guard_xdp");
    if (!xdp_prog)
    {
        std::cerr << "https_guard: XDP program not found; running uprobe only\n";
        return false;
    }

    clearStaleAttachment();

    // Preferred: a BPF link, so the kernel detaches automatically when this
    // process goes away for any reason. See the class comment.
    bpf_link* link = bpf_program__attach_xdp(xdp_prog, static_cast<int>(ifindex_));
    const long link_err = libbpf_get_error(link);
    if (link && !link_err)
    {
        links.push_back(link);
        std::cout << "https_guard: XDP attached via BPF link (auto-detaches on exit)\n";
        return true;
    }

    std::cerr << "https_guard: XDP link attach unavailable (" << strerror(static_cast<int>(-link_err))
              << "); falling back to the legacy netlink attach, whose attachment"
                 " this process must clean up itself\n";

    int xdp_fd = bpf_program__fd(xdp_prog);
    if (xdp_fd < 0)
    {
        std::cerr << "https_guard: failed to get XDP program fd (non-fatal): "
                  << strerror(errno) << "\n";
        return false;
    }

    struct bpf_xdp_attach_opts opts = {};
    opts.sz = sizeof(opts);

    // bpf_xdp_attach() takes the mode in its flags. Three modes exist:
    //   XDP_FLAGS_DRV_MODE  — native: runs inside the driver's Rx path on the
    //                         raw DMA buffer, before the kernel builds an
    //                         sk_buff. Fastest (an XDP_DROP costs almost
    //                         nothing), but needs driver support — the AST2600's
    //                         ftgmac100 has it.
    //   XDP_FLAGS_SKB_MODE  — generic: runs later, after the sk_buff is already
    //                         allocated. Slower, but works on any driver, veth,
    //                         or virtio-net — which is what QEMU's TAP setup uses.
    //   XDP_FLAGS_HW_MODE   — offloaded onto a SmartNIC's own processor. No BMC
    //                         NIC offers this, so it is never attempted here.
    // Native first, then generic. Passing no mode bit already defaults to
    // native, but naming XDP_FLAGS_DRV_MODE states the intent and is symmetric
    // with the SKB fallback below. On failure the kernel does NOT silently
    // downgrade DRV->SKB; we do that ourselves, explicitly, so the log says which
    // mode actually took.
    int native_err = bpf_xdp_attach(
        ifindex_, xdp_fd, XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (!native_err)
    {
        owns_legacy_attachment_ = true;
        std::cout << "https_guard: XDP attached in native mode (legacy path)\n";
        return true;
    }

    int generic_err = bpf_xdp_attach(
        ifindex_, xdp_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, &opts);
    if (generic_err)
    {
        std::cerr << "https_guard: failed to attach XDP program to ifindex "
                  << ifindex_ << " (non-fatal, continuing with uprobe only):\n"
                  << "  native XDP: " << strerror(-native_err) << "\n"
                  << "  generic XDP: " << strerror(-generic_err) << "\n";
        return false;
    }

    owns_legacy_attachment_ = true;
    std::cout << "https_guard: XDP attached in generic (SKB) mode (legacy path)\n";
    return true;
}

hg_event_source XdpTlsProgram::eventSource() const noexcept
{
    return HG_SOURCE_XDP;
}


}  // namespace https_guard
