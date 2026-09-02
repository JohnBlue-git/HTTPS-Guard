#include <cerrno>
#include <cstring>
#include <iostream>
#include <utility>

#include "HttpGuardProgram.hpp"
#include "DetectLoop.hpp"
#include "blocklist/Blocklist.hpp"
#include "conn_rate.bpf.h"

namespace https_guard {

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   std::vector<std::unique_ptr<BpfProgram>> hooks) noexcept
    : object_path_(std::move(object_path))
    , hooks_(std::move(hooks))
{
}

HttpGuardProgram::~HttpGuardProgram() noexcept
{
    detachFilter();
    closeObject();
}

bool HttpGuardProgram::loadFilter() noexcept
{
    if (!openObject())
    {
        return false;
    }

    if (bpf_object__load(object_) != 0)
    {
        closeObject();
        return false;
    }

    if (!attachHooks())
    {
        detachFilter();
        closeObject();
        return false;
    }

    if (!registerEventHandler())
    {
        detachFilter();
        closeObject();
        return false;
    }

    loaded_ = true;
    return true;
}

void HttpGuardProgram::detachFilter() noexcept
{
    releaseRingBuffer();
    destroyLinks();
    loaded_ = false;
}

bool HttpGuardProgram::openObject() noexcept
{
    if (object_)
    {
        return true;
    }

    object_ = bpf_object__open_file(object_path_.c_str(), nullptr);
    if (!object_ || libbpf_get_error(object_))
    {
        object_ = nullptr;
        return false;
    }
    return true;
}

void HttpGuardProgram::closeObject() noexcept
{
    if (object_)
    {
        bpf_object__close(object_);
        object_ = nullptr;
    }
}

bool HttpGuardProgram::attachHooks() noexcept
{
    int attached_count = 0;
    for (const auto& hook : hooks_)
    {
        if (hook->attach(object_, links_))
        {
            ++attached_count;
        }
    }

    // Require at least one enforcement path. Which hooks are actually
    // required vs. auxiliary is each hook's own attach() diagnostics to
    // log -- this class only needs to know whether *anything* attached.
    if (attached_count == 0)
    {
        std::cerr << "https_guard: no hook could be attached\n";
        return false;
    }

    std::cout << "https_guard: enforcement active via " << attached_count
              << " of " << hooks_.size() << " hook(s)\n";

    /* Adopt the blocklist map so enforcement can populate it after
     * classification. The only countermeasure touch point in the attach path;
     * everything else here stays observational. */
    if (!Blocklist::instance().adopt(getMapFd(kBlocklistMapName)))
    {
        std::cerr << "https_guard: failed to adopt blocklist map '"
                  << kBlocklistMapName << "' (countermeasure disabled)\n";
        /* Non-fatal: the daemon still works in pure observational mode. */
    }
    return true;
}

int HttpGuardProgram::pollEvents(int timeout_ms) noexcept
{
    if (!ring_buffer_)
    {
        std::cerr << "https_guard: pollEvents called but ring_buffer_ is null\n";
        return -1;
    }
    const int rc = ring_buffer__poll(ring_buffer_, timeout_ms);
    if (rc < 0 && rc != -EINTR)
    {
        std::cerr << "https_guard: ring_buffer__poll returned " << rc
                  << " (" << strerror(-rc) << ")\n";
    }
    return rc;
}

int HttpGuardProgram::getProgramFd(const std::string& prog_name) const noexcept
{
    if (!object_)
    {
        return -1;
    }

    bpf_program* prog = bpf_object__find_program_by_name(object_, prog_name.c_str());
    return prog ? bpf_program__fd(prog) : -1;
}

int HttpGuardProgram::getMapFd(const std::string& map_name) const noexcept
{
    if (!object_)
    {
        return -1;
    }

    return bpf_object__find_map_fd_by_name(object_, map_name.c_str());
}

bool HttpGuardProgram::registerEventHandler() noexcept
{
    const int map_fd = getMapFd("events");
    if (map_fd < 0)
    {
        std::cerr << "https_guard: failed to find 'events' ring buffer map\n";
        return false;
    }

    std::cerr << "https_guard: creating ring buffer (map_fd=" << map_fd << ")\n";
    ring_buffer_ = ring_buffer__new(map_fd, &HttpGuardProgram::ringBufferCallback,
                                    this, nullptr);
    if (!ring_buffer_)
    {
        std::cerr << "https_guard: ring_buffer__new failed: " << strerror(errno) << "\n";
        return false;
    }
    std::cerr << "https_guard: ring buffer created successfully\n";
    return true;
}

void HttpGuardProgram::releaseRingBuffer() noexcept
{
    if (ring_buffer_)
    {
        ring_buffer__free(ring_buffer_);
        ring_buffer_ = nullptr;
    }
}

void HttpGuardProgram::destroyLinks() noexcept
{
    for (bpf_link* link : links_)
    {
        if (link)
        {
            bpf_link__destroy(link);
        }
    }
    links_.clear();
}

void HttpGuardProgram::enableRateSweeps(ConnRateSweeper::Thresholds thresholds) noexcept
{
    /* getMapFd returns < 0 if the map isn't present -- which is the case when
     * the BPF object was built without the rate counter. ConnRateSweeper
     * treats that, and a zero threshold, as "disabled". */
    DetectLoop::getInstance().enableRateSweeps(
        getMapFd(HTTPS_GUARD_CONN_RATE_MAP_NAME), thresholds);
}

const IPeerResolver* HttpGuardProgram::peerResolver() const noexcept
{
    for (const auto& hook : hooks_)
    {
        if (const auto* resolver = dynamic_cast<const IPeerResolver*>(hook.get()))
        {
            return resolver;
        }
    }
    return nullptr;
}

BpfProgram* HttpGuardProgram::hookFor(std::uint32_t event_source) const noexcept
{
    for (const auto& hook : hooks_)
    {
        if (static_cast<std::uint32_t>(hook->eventSource()) == event_source)
        {
            return hook.get();
        }
    }
    return nullptr;
}


int HttpGuardProgram::dispatchRecord(const void* data, std::size_t size) noexcept
{
    if (data == nullptr || size < sizeof(std::uint32_t))
    {
        std::cerr << "https_guard: undersized ring-buffer record (" << size << " bytes)\n";
        return 0;
    }

    std::uint32_t event_source = 0;
    std::memcpy(&event_source, data, sizeof(event_source));

    BpfProgram* hook = hookFor(event_source);
    if (hook == nullptr)
    {
        /* Rate-limited: a mislabelled producer would otherwise flood the
         * journal at line rate, which is its own denial of service. */
        if (++unknown_source_count_ == 1 || unknown_source_count_ % 1000 == 0)
        {
            std::cerr << "https_guard: no hook owns event_source=" << event_source
                      << " (size=" << size << "); " << unknown_source_count_
                      << " such record(s) skipped\n";
        }
        return 0;
    }

    /* Straight to the owning hook's handler, whose default only submits. This
     * is the override point: a hook that must do something at poll time can,
     * and no other hook pays for it. */
    hook->ringBufferHandler(data, size);
    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, std::size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->dispatchRecord(data, size);
}

}  // namespace https_guard
