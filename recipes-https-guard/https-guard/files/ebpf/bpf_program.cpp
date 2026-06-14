#include "bpf_program.hpp"

#include <utility>

namespace https_guard {

BpfProgram::BpfProgram(bpf_program* program) noexcept
    : program_(program)
{
}

BpfProgram::BpfProgram(BpfProgram&& other) noexcept
    : program_(other.program_)
    , link_(other.link_)
{
    other.program_ = nullptr;
    other.link_ = nullptr;
}

BpfProgram& BpfProgram::operator=(BpfProgram&& other) noexcept
{
    if (this != &other) {
        detach();

        program_ = other.program_;
        link_ = other.link_;

        other.program_ = nullptr;
        other.link_ = nullptr;
    }
    return *this;
}

BpfProgram::~BpfProgram()
{
    detach();
}

BpfObject::BpfObject(BpfObject&& other) noexcept
    : object_(other.object_)
{
    other.object_ = nullptr;
}

BpfObject& BpfObject::operator=(BpfObject&& other) noexcept
{
    if (this != &other) {
        close();
        object_ = other.object_;
        other.object_ = nullptr;
    }
    return *this;
}

bool BpfProgram::attachXdp(unsigned int ifindex)
{
    if (!program_ || link_) {
        return false;
    }
    link_ = bpf_program__attach_xdp(program_, ifindex);
    return link_ != nullptr;
}

bool BpfProgram::attachUprobe(bool retprobe, pid_t pid, const std::string& binary_path, unsigned long offset)
{
    if (!program_ || link_) {
        return false;
    }
    link_ = bpf_program__attach_uprobe(program_, retprobe, pid, binary_path.c_str(), offset);
    return link_ != nullptr;
}

void BpfProgram::detach()
{
    if (link_) {
        bpf_link__destroy(link_);
        link_ = nullptr;
    }
}

bool BpfProgram::isAttached() const noexcept
{
    return link_ != nullptr;
}

BpfObject::BpfObject(bpf_object* object) noexcept
    : object_(object)
{
}

BpfObject::~BpfObject()
{
    close();
}

std::optional<BpfObject> BpfObject::openFile(const std::string& path)
{
    auto* object = bpf_object__open_file(path.c_str(), nullptr);
    if (!object) {
        return std::nullopt;
    }
    return BpfObject(object);
}

bool BpfObject::load()
{
    return object_ && bpf_object__load(object_) == 0;
}

std::optional<BpfProgram> BpfObject::findProgramByName(const std::string& name) const
{
    if (!object_) {
        return std::nullopt;
    }
    auto* program = bpf_object__find_program_by_name(object_, name.c_str());
    if (!program) {
        return std::nullopt;
    }
    return BpfProgram(program);
}

bpf_map* BpfObject::findMapByName(const std::string& name) const
{
    if (!object_) {
        return nullptr;
    }
    return bpf_object__find_map_by_name(object_, name.c_str());
}

bpf_object* BpfObject::get() const noexcept
{
    return object_;
}

void BpfObject::close()
{
    if (object_) {
        bpf_object__close(object_);
        object_ = nullptr;
    }
}

}  // namespace https_guard
