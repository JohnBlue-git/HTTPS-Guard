#include <iostream>
#include <memory>
#include <utility>

#include "HttpGuardProgram.hpp"
#include "blocklist/Blocklist.hpp"
#include "conn_rate.bpf.h"

namespace https_guard {

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   ActionLoop& action_loop,
                                   std::vector<std::unique_ptr<IHookModule>> hooks,
                                   std::chrono::seconds blocklist_ttl,
                                   std::string output_path,
                                   DetectorRegistry detectors) noexcept
    : BpfProgram(std::move(object_path))
    , action_loop_(action_loop)
    , hooks_(std::move(hooks))
    , detect_loop_(action_loop_, hooks_, std::move(detectors),
                   blocklist_ttl, std::move(output_path))
{
}

bool HttpGuardProgram::attachProgram() noexcept
{
    int attached_count = 0;
    for (auto& hook : hooks_) {
        if (hook->attach(object_, links_)) {
            ++attached_count;
        }
    }

    // Require at least one enforcement path. Which hooks are actually
    // required vs. auxiliary is each hook's own attach() diagnostics to
    // log (see SslUprobeProgram/XdpTlsProgram) — this class only needs
    // to know whether *anything* ended up attached.
    if (attached_count == 0) {
        std::cerr << "https_guard: no hook could be attached\n";
        return false;
    }

    std::cout << "https_guard: enforcement active via " << attached_count
              << " of " << hooks_.size() << " hook(s)\n";

    /* Adopt the blocklist map so enforcement can populate it after
     * classification.  This is the only "countermeasure" touch point in the
     * attach path -- everything else stays observational. */
    if (!Blocklist::instance().adopt(getMapFd(kBlocklistMapName))) {
        std::cerr << "https_guard: failed to adopt blocklist map '"
                  << kBlocklistMapName << "' (countermeasure disabled)\n";
        /* Non-fatal: the daemon still works in pure observational mode. */
    }
    return true;
}

void HttpGuardProgram::enableRateSweeps(ConnRateSweeper::Thresholds thresholds) noexcept
{
    /* getMapFd returns < 0 if the map isn't present -- which is the case when
     * the BPF object was built without the rate counter. ConnRateSweeper
     * treats that, and a zero threshold, as "disabled". */
    detect_loop_.enableRateSweeps(getMapFd(HTTPS_GUARD_CONN_RATE_MAP_NAME), thresholds);
}

ring_buffer_sample_fn HttpGuardProgram::getRingBufferHandler() noexcept
{
    return &HttpGuardProgram::ringBufferCallback;
}

int HttpGuardProgram::ringBufferHandler(void* data, size_t size) noexcept
{
    /* Deliberately the whole body. The sample pointer is only valid for the
     * duration of this callback, so submit() copies the bytes; everything
     * else -- parse, /proc enrichment, classification, action dispatch --
     * happens on DetectLoop's Boost.Asio loop.
     *
     * This used to do all of that inline, which meant libbpf's poll thread
     * sat through a several-hundred-line /proc parse per uprobe event. A
     * callback that runs long lets the ring buffer fill, and a full ring
     * buffer drops events with nothing to report it. */
    detect_loop_.submit(data, size);
    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard
