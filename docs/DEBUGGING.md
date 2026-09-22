# Debugging Hook Attach and BPF Load

This guide separates failures that often get reported as one vague "BPF attach failed" message. The target image intentionally does not ship `bpftool`; see [LIMITATIONS.md](../docs/LIMITATIONS.md). Use the no-tool path on the BMC and the `bpftool` path on a bridged/TAP host when available.

## Identify the failing stage

```text
open ELF/parse -> CO-RE/BTF relocation -> BPF_PROG_LOAD/verifier -> attach/link
       |                  |                         |                  |
     file/ELF          vmlinux BTF              kernel policy       hook/driver
```

First capture the daemon log without filtering away errno:

```sh
systemctl status https-guard-daemon --no-pager
journalctl -u https-guard-daemon -b --no-pager | grep -iE 'bpf|libbpf|xdp|uprobe|lsm|errno|attach|verif'
uname -a
```

A failed optional XDP or LSM hook should not be confused with total daemon failure. Confirm whether at least the uprobe attached.

## Without `bpftool`

### Kernel and BTF checks

```sh
uname -r
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|UPROBES|UPROBE_EVENTS|NET_XDP|BPF_LSM)='
test -r /sys/kernel/btf/vmlinux && echo 'vmlinux BTF: present' || echo 'vmlinux BTF: missing'
cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null
cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null
dmesg | tail -100
```

`/proc/config.gz` may be absent; use the deployed kernel configuration or `/boot/config-$(uname -r)` when available. A missing BTF file matters for CO-RE relocation, while a missing JIT can matter only after verification on architectures where the kernel requires JIT for the selected program.

### Interpret errno by stage

- `EPERM`: missing privilege, locked-down BPF policy, or an unprivileged-BPF restriction.
- `EINVAL`: invalid program attributes, unsupported attach arguments, malformed context access, or a mode/device mismatch.
- `E2BIG`: verifier or kernel limit reached, often instruction, map, or log-size related.
- `ENOTSUPP` or `EOPNOTSUPP`: the kernel or driver does not implement that program type or attach mode. ARM32 BPF-LSM trampoline support is the project example.
- `EBUSY`: another XDP program or incompatible link already owns the device.
- `ENOENT` or `ENODEV`: the device, tracepoint, symbol, or target process disappeared or is not present.

### Capture better verifier evidence

The daemon uses libbpf. Enable its print callback in a diagnostic build with `libbpf_set_print()` and request a sufficiently large verifier log buffer for `BPF_PROG_LOAD`. On a target without a diagnostic build, raise the kernel log level temporarily and capture `dmesg` immediately around daemon startup. Do not treat a generic libbpf summary as the verifier explanation.

Separate load from attach where possible: first load the object/program against the target kernel, then attach it to the specific hook or interface. For XDP, explicitly compare native and generic mode. A generic-mode success with native-mode failure points at the driver or netdev path, not at the program verifier.

### Inspecting live state without `bpftool`

The process owns its `bpf_link`, program, and map file descriptors. While the daemon is running:

```sh
pid=$(pidof https-guardd)
ls -l /proc/$pid/fd
for fd in /proc/$pid/fdinfo/*; do
    grep -H -E '^(pos|flags|mnt_id|ino|prog_id|map_id|link_id)' "$fd" 2>/dev/null
done
```

This is less complete than `bpftool prog show`, but it can prove that the daemon still owns descriptors and that a restart released them. The daemon’s own startup and counter logs are the authoritative project-level signal.

## With `bpftool`

Run this on a supported host or in a bridged/TAP environment, not by assuming it exists on the AST2600 image:

```sh
sudo bpftool feature probe kernel
sudo bpftool prog show
sudo bpftool link show
sudo bpftool map show
sudo bpftool net attach show
sudo bpftool btf list
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c >/tmp/vmlinux.h
```

For an XDP-specific check:

```sh
sudo bpftool net show
ip -details link show dev eth0
```

Use `bpftool prog dump xlated id ID` for verifier-accepted instructions and `bpftool prog dump jited id ID` only when the target architecture actually provides the relevant JIT support. A missing JIT can make the second command fail even though load and attach succeeded.

## Reproduce off-target carefully

Verifier-only failures can usually be reduced on an x86_64 host with the same object and BTF assumptions. JIT, XDP driver, BPF-LSM trampoline, and tracepoint availability must be reproduced with the target kernel, for example in QEMU. This project’s AST2600 ARM32 JIT and trampoline gaps are platform facts, not host-tool defects; see [XDP_INTERNALS.md](XDP_INTERNALS.md) and [PLATFORM_CHECKS.md](PLATFORM_CHECKS.md).
