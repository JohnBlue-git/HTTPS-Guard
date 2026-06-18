#include <utility>

#include "bpf_program.hpp"

namespace https_guard {

BpfProgram::BpfProgram(std::string object_path) noexcept
    : object_path_(std::move(object_path))
{
}

BpfProgram::BpfProgram(BpfProgram&& other) noexcept
    : object_path_(std::move(other.object_path_))
    , object_(other.object_)
    , loaded_(other.loaded_)
    , ring_buffer_(other.ring_buffer_)
    , links_(std::move(other.links_))
{
    other.object_ = nullptr;
    other.loaded_ = false;
    other.ring_buffer_ = nullptr;
}

BpfProgram& BpfProgram::operator=(BpfProgram&& other) noexcept
{
    if (this != &other) {
        detachFilter();
        closeObject();

        object_path_ = std::move(other.object_path_);
        object_ = other.object_;
        loaded_ = other.loaded_;
        ring_buffer_ = other.ring_buffer_;
        links_ = std::move(other.links_);

        other.object_ = nullptr;
        other.loaded_ = false;
        other.ring_buffer_ = nullptr;
    }
    return *this;
}

BpfProgram::~BpfProgram() noexcept
{
    detachFilter();
    closeObject();
}

bool BpfProgram::loadFilter() noexcept
{
    if (!openObject()) {
        return false;
    }

    if (bpf_object__load(object_) != 0) {
        closeObject();
        return false;
    }

    if (!attachProgram()) {
        detachFilter();
        closeObject();
        return false;
    }

    if (!registerEventHandler()) {
        detachFilter();
        closeObject();
        return false;
    }

    loaded_ = true;
    return true;
}

void BpfProgram::detachFilter() noexcept
{
    releaseRingBuffer();
    detachProgram();
    loaded_ = false;
}

bool BpfProgram::isLoaded() const noexcept
{
    return loaded_;
}

bool BpfProgram::openObject() noexcept
{
    if (object_) {
        return true;
    }

    object_ = bpf_object__open_file(object_path_.c_str(), nullptr);
    if (!object_ || libbpf_get_error(object_)) {
        object_ = nullptr;
        return false;
    }
    return true;
}

void BpfProgram::closeObject() noexcept
{
    if (object_) {
        bpf_object__close(object_);
        object_ = nullptr;
    }
}

int BpfProgram::pollEvents(int timeout_ms) noexcept
{
    if (!ring_buffer_) {
        return -1;
    }
    return ring_buffer__poll(ring_buffer_, timeout_ms);
}

int BpfProgram::getProgramFd(const std::string& prog_name) const noexcept
{
    if (!object_) {
        return -1;
    }

    bpf_program* prog = bpf_object__find_program_by_name(object_, prog_name.c_str());
    return prog ? bpf_program__fd(prog) : -1;
}

int BpfProgram::getMapFd(const std::string& map_name) const noexcept
{
    if (!object_) {
        return -1;
    }

    return bpf_object__find_map_fd_by_name(object_, map_name.c_str());
}

bool BpfProgram::registerEventHandler() noexcept
{
    const int map_fd = getMapFd("events");
    if (map_fd < 0) {
        return false;
    }

    ring_buffer_ = ring_buffer__new(map_fd, getRingBufferHandler(), this, nullptr);
    return ring_buffer_ != nullptr;
}

void BpfProgram::releaseRingBuffer() noexcept
{
    if (ring_buffer_) {
        ring_buffer__free(ring_buffer_);
        ring_buffer_ = nullptr;
    }
}

void BpfProgram::detachProgram() noexcept
{
    for (bpf_link* link : links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    links_.clear();
}

}  // namespace https_guard
