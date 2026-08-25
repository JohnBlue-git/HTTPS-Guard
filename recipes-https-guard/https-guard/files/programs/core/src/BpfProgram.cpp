#include <utility>

#include "BpfProgram.hpp"
#include "DetectLoop.hpp"

namespace https_guard {

BpfProgram::BpfProgram(std::string name) noexcept
    : name_(std::move(name))
{
}

void BpfProgram::ringBufferHandler(const void* data, std::size_t size) noexcept
{
    /* No detections: a hook that has not declared any submits nothing useful,
     * and DetectLoop counts and reports that rather than dropping it silently.
     * Every real hook overrides this and passes its own list.
     *
     * The sample pointer is only valid for the duration of libbpf's callback,
     * so submit() copies both the bytes and the pointer list; parsing, /proc
     * enrichment, classification and action dispatch all happen on DetectLoop's
     * own threads. That work used to run inline on the poll thread, which meant
     * libbpf sat through a several-hundred-line /proc parse per uprobe event. */
    DetectLoop::getInstance().submit(data, size, {});
}

}  // namespace https_guard
