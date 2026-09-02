#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

#include "CertAccessDetector.hpp"
#include "CertAccessEvent.hpp"
#include "IDetection.hpp"
#include "event_meta_from.hpp"

namespace https_guard {
namespace detail {

/* The strong identity check: the kernel-backed real executable, not a
 * self-reported comm the process itself can set. Can only run in userspace on
 * this platform -- resolving it in-kernel needs kfuncs the ARM32 BPF JIT cannot
 * emit. See this directory's DESIGN.md. */
inline std::string resolveRealExePath(std::uint32_t pid)
{
    std::array<char, 256> buf{};
    const std::string proc_exe = "/proc/" + std::to_string(pid) + "/exe";
    const ssize_t len = readlink(proc_exe.c_str(), buf.data(), buf.size() - 1);
    if (len <= 0)
    {
        return {};  // process likely exited already; nothing to resolve
    }
    return std::string(buf.data(), static_cast<std::size_t>(len));
}

}  // namespace detail

/**
 * Certificate-access detection, including the identity check that matters.
 *
 * The strong check runs **here**, in userspace, not in the BPF program:
 * resolving a process's real executable in-kernel needs kfuncs, and this
 * project's ARM32 target cannot JIT a kfunc call at all — so the raw record
 * carries only a weak, spoofable `comm` comparison and this reads
 * `/proc/<pid>/exe`, a symlink the process cannot rewrite.
 *
 * An empty path (the process exited before we looked) counts as a mismatch.
 * Silently trusting "unknown" would defeat the point of the detection.
 */
template <class RawT>
class CertAccessDetection final : public IDetection {
public:
    std::string_view name() const noexcept override { return "cert_access"; }

    /** The executables allowed to open the key -- bmcweb (serves it) and
     * phosphor-certificate-manager (installs/replaces it via Redfish/D-Bus;
     * see this directory's DESIGN.md for why it has to be on this list too). */
    explicit CertAccessDetection(std::vector<std::string> allowed_exes) noexcept
        : allowed_exes_(std::move(allowed_exes))
    {
    }

    std::optional<Verdict> inspect(const void* data, std::size_t size,
                                   EventMeta& meta) const override
    {
        if (data == nullptr || size < sizeof(RawT))
        {
            return std::nullopt;
        }
        const auto* raw = static_cast<const RawT*>(data);

        fillEnvelope(*raw, meta);
        /* No connection tuple and no resolver: a file open has neither, which
         * is also why this detection's verdict is not actionable. */

        // The real check: the kernel-backed /proc/<pid>/exe resolution, not the
        // BPF hook's own comm-based pre-check (raw->cert.comm_mismatch), which
        // exists only to give the (never-enabled) shadow-mode enforcement branch
        // something real to gate on. The two can disagree, and only this one is
        // worth acting on.
        std::string real_exe_path = detail::resolveRealExePath(raw->hdr.pid);
        const bool  identity_mismatch =
            std::find(allowed_exes_.begin(), allowed_exes_.end(),
                      real_exe_path) == allowed_exes_.end();

        const CertAccessEvent evt(meta, *raw, std::move(real_exe_path), identity_mismatch);

        return rule_.evaluate(evt);
    }

private:
    std::vector<std::string> allowed_exes_;
    CertAccessDetector       rule_;
};

}  // namespace https_guard
