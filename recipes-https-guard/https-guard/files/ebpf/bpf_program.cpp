#include "bpf_program.hpp"

#include <utility>

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

HttpGuardProgram::HttpGuardProgram(std::string object_path,
                                   ActionLoop& action_loop,
                                   std::string openssl_lib_path,
                                   unsigned int ifindex) noexcept
    : BpfProgram(std::move(object_path))
    , action_loop_(action_loop)
    , openssl_lib_path_(std::move(openssl_lib_path))
    , ifindex_(ifindex)
{
}

bool HttpGuardProgram::attachProgram() noexcept
{
    bpf_program* xdp_prog = bpf_object__find_program_by_name(object_, "https_guard_xdp");
    if (!xdp_prog) {
        return false;
    }

    bpf_link* xdp_link = bpf_program__attach_xdp(xdp_prog, ifindex_);
    if (!xdp_link) {
        return false;
    }
    links_.push_back(xdp_link);

    bpf_program* uprobe_prog = bpf_object__find_program_by_name(object_, "https_guard_ssl_write");
    if (!uprobe_prog) {
        return false;
    }

    bpf_link* uprobe_link = bpf_program__attach_uprobe(uprobe_prog, false, -1, openssl_lib_path_.c_str(), 0);
    if (!uprobe_link) {
        return false;
    }
    links_.push_back(uprobe_link);
    return true;
}

ring_buffer_sample_fn HttpGuardProgram::getRingBufferHandler() noexcept
{
    return &HttpGuardProgram::ringBufferCallback;
}

int HttpGuardProgram::ringBufferHandler(void* data, size_t size) noexcept
{
    if (size < sizeof(hg_event)) {
        return 0;
    }

    const auto* evt = static_cast<const hg_event*>(data);
    std::string severity;
    std::string message_id;
    std::string message;

    if (evt->event_type == HG_EVENT_TLS_VERSION_VIOLATION) {
        severity = "Critical";
        message_id = "OemSecurityEvent.1.0.0.HttpsTlsVersionViolation";
        message = "Security violation: Process '" + std::string(evt->process) + "' (PID " +
                  std::to_string(evt->pid) + ") attempted an HTTPS connection using an insecure TLS version (" +
                  TlsVersion(evt->tls_version).toString() + "). Packet was blocked.";
    } else if (evt->event_type == HG_EVENT_HTTP_ANOMALY_DETECTED ||
               evt->event_type == HG_EVENT_HTTP_PAYLOAD_OBSERVED) {
        std::string matched_rule;
        const bool suspicious = detector_.isSuspicious(evt->payload_snippet, matched_rule) ||
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
                  std::to_string(evt->pid) + "), rule '" + matched_rule + "'. Connection should be terminated or quarantined.";
    } else {
        return 0;
    }

    action_loop_.post(*evt, message_id, message, severity);
    return 0;
}

int HttpGuardProgram::ringBufferCallback(void* ctx, void* data, size_t size) noexcept
{
    return static_cast<HttpGuardProgram*>(ctx)->ringBufferHandler(data, size);
}

}  // namespace https_guard
