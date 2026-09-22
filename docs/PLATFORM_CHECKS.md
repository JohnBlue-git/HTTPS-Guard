# Target Kernel Capability Checks

Kernel version is a useful first clue, not a capability contract. Check the actual kernel, configuration, BTF, hook inventory, and device driver on the target that will run HTTPS-Guard. For constraints that remain even when a capability is present, see [LIMITATIONS.md](LIMITATIONS.md).

## Comprehensive Hook Checks

A hook is usable only when all five layers pass. A failure at any layer is
enough to make the hook unavailable:

| Layer | Question | How to check |
|---|---|---|
| 1. Kernel version | When was this program or attach type introduced? | `uname -r`, then verify with `bpftool feature probe` |
| 2. Kernel configuration | Was the required `CONFIG_*` option enabled? | `/proc/config.gz`, `/boot/config-$(uname -r)`, or the build configuration |
| 3. CPU architecture | Does this architecture provide the required JIT or BPF trampoline? | `uname -m`, architecture config, and an actual attach test |
| 4. Runtime environment | Are tracefs, debugfs, bpffs, LSM, cgroups, and permissions ready? | Filesystem checks, sysctls, `/sys/kernel/security/lsm`, and capabilities |
| 5. Device or symbol | Does the requested symbol, tracepoint, or NIC driver exist? | Tracepoint files, `/proc/kallsyms`, `ethtool`, and a controlled attach |

The most important rule is: **successful load does not prove successful
attach**. Always test the real attach operation on the target kernel. A
program can pass verification and still fail because a tracepoint is absent,
an architecture lacks a trampoline, a driver rejects native XDP, or the
process lacks permission.

### Ask the kernel directly

When the tools are available, probe the kernel instead of relying on a version
number:

```sh
sudo bpftool feature probe kernel
sudo bpftool feature probe kernel | grep program_type
sudo bpftool feature probe dev eth0
sudo bpftrace --info
```

`bpftool feature probe` attempts to load minimal programs and reports program
types, map types, helpers, and detected configuration. It is more useful than
version matching, but it primarily proves **load** capability. It does not
prove that a particular hook can attach to a symbol, tracepoint, or device.
The target image does not ship `bpftool`; use a host-side tool or the daemon's
attach log as described in [DEBUGGING.md](DEBUGGING.md).

### Approximate kernel versions and dependencies

These versions are orientation points, not acceptance criteria. Confirm the
actual target with `bpftool feature probe` and an attach test.

| Hook or feature | Approximate minimum | Important dependencies | Additional constraint |
|---|---:|---|---|
| Socket filter | 3.19 | `CONFIG_BPF_SYSCALL` | Classic and eBPF modes differ in available helpers |
| kprobe/kretprobe | 4.1 | `CONFIG_KPROBES`, `CONFIG_KPROBE_EVENTS`, `CONFIG_BPF_EVENTS` | Blacklisted or inlined functions cannot be probed |
| TC `cls_bpf` | 4.1; direct-action around 4.4 | `CONFIG_NET_CLS_BPF`, `CONFIG_NET_ACT_BPF`, `CONFIG_NET_SCH_INGRESS` | Requires `tc` and a suitable qdisc |
| uprobe/uretprobe | 4.x; perf uprobe support around 4.17 | `CONFIG_UPROBES`, `CONFIG_UPROBE_EVENTS` | The target binary must expose a resolvable symbol |
| Tracepoint | 4.7 | `CONFIG_BPF_EVENTS`, `CONFIG_FTRACE` | Syscall tracepoints also need `CONFIG_FTRACE_SYSCALLS` |
| XDP | 4.8; generic mode around 4.12 | `CONFIG_NET_XDP` | Native mode is a NIC-driver capability; AF_XDP additionally needs `CONFIG_XDP_SOCKETS` |
| perf event | 4.9 | `CONFIG_PERF_EVENTS` | The event must exist and be accessible |
| cgroup skb/socket | 4.10 | `CONFIG_CGROUP_BPF` | cgroup v2 is usually the easier deployment model |
| sockops | 4.13 | `CONFIG_CGROUP_BPF` | Attaches to a cgroup |
| raw tracepoint | 4.17 | Tracepoint infrastructure | The named raw tracepoint must exist |
| BTF/CO-RE | 5.2 | `CONFIG_DEBUG_INFO_BTF` | Required by many CO-RE, fentry, and LSM workflows |
| fentry/fexit | 5.5 | BTF and BPF trampoline | Trampoline support is architecture-specific |
| BPF LSM | 5.7 | `CONFIG_BPF_LSM`, `CONFIG_SECURITY` | Boot-time LSM order must include `bpf`; also needs a trampoline |
| Ring buffer and `CAP_BPF` | 5.8 | Kernel support and permission policy | Not a hook, but it affects the daemon ABI and privileges |

### Filesystem and sysctl quick reference

| Path or command | What it tells you |
|---|---|
| `/proc/config.gz` or `/boot/config-$(uname -r)` | Kernel build options; `/proc/config.gz` needs `CONFIG_IKCONFIG_PROC` |
| `/sys/kernel/btf/vmlinux` | Kernel BTF is present; CO-RE may be possible |
| `/sys/kernel/security/lsm` | Active LSM list; BPF LSM requires `bpf` to be present |
| `/sys/kernel/tracing/` or `/sys/kernel/debug/tracing/` | tracefs/debugfs entry point for tracepoints, kprobes, and uprobes |
| `available_events` | Tracepoints exported by this kernel |
| `events/<subsystem>/<event>/format` | Fields and types for one tracepoint |
| `available_filter_functions` | Functions exposed to ftrace-based attachment |
| `/proc/kallsyms` | Whether a kprobe target symbol exists |
| `kprobes/blacklist` | Functions that cannot accept a kprobe |
| `/sys/bus/event_source/devices/{kprobe,uprobe}/type` | Perf PMU support for kprobe/uprobe attachment |
| `/sys/fs/bpf/` | bpffs mount used for pinned maps, programs, and links |
| `/proc/sys/net/core/bpf_jit_enable` | JIT state; `0` means interpreter-only execution |
| `/proc/sys/kernel/unprivileged_bpf_disabled` | Restriction on unprivileged BPF use |
| `stat -fc %T /sys/fs/cgroup` | `cgroup2fs` indicates cgroup v2 |

Embedded images may not mount tracefs, debugfs, or bpffs automatically. Mount
them only when permitted by the target's policy:

```sh
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
```

### Enumerate tracepoints

Use at least one filesystem view and one tool view when diagnosing a missing
tracepoint:

```sh
tracing=/sys/kernel/tracing
test -r "$tracing/available_events" || tracing=/sys/kernel/debug/tracing

cat "$tracing/available_events"
awk -F: '{print $1}' "$tracing/available_events" | sort | uniq -c | sort -rn
grep -E '^(xdp|net|tcp|sock|syscalls):' "$tracing/available_events"
find "$tracing/events" -maxdepth 3 -type f -name format -print 2>/dev/null
```

When installed:

```sh
sudo bpftrace -l 'tracepoint:*'
sudo bpftrace -l 'tracepoint:syscalls:*'
sudo bpftrace -l 'tracepoint:tcp:*'
sudo perf list tracepoint
sudo bpftrace -lv 'tracepoint:syscalls:sys_enter_openat'
cat "$tracing/events/syscalls/sys_enter_openat/format"
```

Common subsystems include `syscalls`, `sched`, `net`, `skb`, `sock`, `tcp`,
`xdp`, `block`, `irq`, `kmem`, and `trace`. HTTPS-related candidates include
`sock:inet_sock_set_state`, `tcp:tcp_probe`, and
`syscalls:sys_enter_connect`, but availability varies by kernel configuration
and version. A program should check the event at startup and fall back to a
kprobe or another supported source when appropriate.

### Architecture and driver effects

```sh
uname -m
lscpu 2>/dev/null
zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(HAVE_EBPF_JIT|BPF_JIT)='
ethtool -i eth0
sudo bpftool net list
```

As with `bpftool`, don't assume `ethtool` is on the BMC image either — this
project's target ships only BusyBox `ip` and declares no runtime dependency
on `ethtool` (see [XDP_INTERNALS.md](XDP_INTERNALS.md#checking-a-driver-for-ndo_bpf)
for the same caveat and a host-side alternative).

JIT support and BPF trampoline support are separate capabilities. A missing
JIT normally means interpreter execution and a performance cost; it does not
by itself imply that every BPF program cannot load. fentry/fexit, BPF LSM, and
struct-ops require a trampoline implemented for the target architecture.

| Hook family | BPF trampoline required | ARM32 AST2600 expectation |
|---|---|---|
| kprobe/kretprobe | No | Generally available |
| tracepoint/raw tracepoint | No | Generally available |
| uprobe/uretprobe | No | Generally available |
| XDP, TC, cgroup, sockops, socket filter | No | Available subject to kernel/driver configuration |
| fentry/fexit | Yes | Not available without architecture support |
| BPF LSM | Yes | Not attachable on this project's ARM32 target |

XDP mode is a driver question as well as a kernel question:

```text
xdpdrv      native driver mode; requires driver ndo_bpf support
xdpgeneric  generic SKB mode; compatibility fallback, higher cost
xdpoffload  hardware execution; requires NIC firmware and driver support
```

Use `ethtool -i` to identify the driver and the actual daemon attach log to
record which mode succeeded. See [XDP_INTERNALS.md](XDP_INTERNALS.md) for the
packet paths and `ndo_bpf` details.

### Validate the real attach

Use a disposable test program and a maintenance window. These commands can
change tracing or network state; do not run the XDP or TC commands on a
production interface without a rollback plan.

```sh
sudo bpftrace -e 'kprobe:tcp_v4_connect { exit(); }'
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { exit(); }'
sudo bpftrace -e 'uprobe:/usr/lib/libssl.so.3:SSL_write { exit(); }'
sudo bpftrace -e 'fentry:tcp_v4_connect { exit(); }'  # trampoline check
sudo bpftrace -e 'lsm:file_open { exit(); }'           # BPF-LSM check
```

For XDP and TC, use a known-good test object and explicitly test the modes:

```sh
sudo ip link set dev eth0 xdpdrv obj prog.o sec xdp      # native
sudo ip link set dev eth0 xdpgeneric obj prog.o sec xdp  # generic fallback
sudo ip link set dev eth0 xdp off                        # rollback
sudo tc qdisc add dev eth0 clsact                       # infrastructure check
sudo tc qdisc del dev eth0 clsact                       # rollback
```

If `bpftrace` is unavailable, use the daemon's real attach path, a small
libbpf test program, or `libbpf_probe_bpf_prog_type()` for the load-only part.
For HTTPS-Guard, distinguish uprobe success, XDP native success, XDP generic
success, and BPF-LSM failure in the startup log rather than reducing them to a
single "BPF supported" result.

### Reusable capability snapshot

Save a snapshot with the kernel build identifier when bringing up a new board:

```sh
#!/bin/sh
echo "== kernel/arch =="; uname -r; uname -m
echo "== BTF =="; test -r /sys/kernel/btf/vmlinux && echo present || echo missing
echo "== active LSM =="; cat /sys/kernel/security/lsm 2>/dev/null || true
echo "== JIT =="; cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || true
echo "== tracefs =="; ls /sys/kernel/tracing/available_events 2>/dev/null || true
echo "== cgroup =="; stat -fc %T /sys/fs/cgroup
echo "== config =="
zcat /proc/config.gz 2>/dev/null | grep -E \
	'CONFIG_(BPF_SYSCALL|BPF_JIT|BPF_EVENTS|KPROBES|UPROBES|DEBUG_INFO_BTF|BPF_LSM|NET_CLS_BPF|NET_SCH_INGRESS|CGROUP_BPF|FTRACE_SYSCALLS)=' || true
echo "== program types =="
bpftool feature probe kernel 2>/dev/null | grep program_type || true
```

Record the kernel release, BTF availability, active LSMs, JIT state,
program types, required tracepoints, and XDP result for each interface. This
turns a future attach failure into a comparison with a known capability set
instead of a guess based on a version string.
