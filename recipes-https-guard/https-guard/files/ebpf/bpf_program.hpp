#pragma once

#include <bpf/libbpf.h>
#include <optional>
#include <string>
#include <sys/types.h>

namespace https_guard {

class BpfProgram {
public:
    explicit BpfProgram(bpf_program* program) noexcept;
    BpfProgram(const BpfProgram&) = delete;
    BpfProgram& operator=(const BpfProgram&) = delete;
    BpfProgram(BpfProgram&& other) noexcept;
    BpfProgram& operator=(BpfProgram&& other) noexcept;
    ~BpfProgram();

    bool attachXdp(unsigned int ifindex);
    bool attachUprobe(bool retprobe, pid_t pid, const std::string& binary_path, unsigned long offset);
    void detach();
    bool isAttached() const noexcept;

private:
    bpf_program* program_;
    bpf_link* link_ = nullptr;
};

class BpfObject {
public:
    BpfObject(const BpfObject&) = delete;
    BpfObject& operator=(const BpfObject&) = delete;
    BpfObject(BpfObject&& other) noexcept;
    BpfObject& operator=(BpfObject&& other) noexcept;
    ~BpfObject();

    static std::optional<BpfObject> openFile(const std::string& path);
    bool load();
    std::optional<BpfProgram> findProgramByName(const std::string& name) const;
    bpf_map* findMapByName(const std::string& name) const;
    bpf_object* get() const noexcept;

private:
    explicit BpfObject(bpf_object* object) noexcept;
    void close();

    bpf_object* object_ = nullptr;
};

}  // namespace https_guard
