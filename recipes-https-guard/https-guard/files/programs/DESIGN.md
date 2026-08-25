# `programs/` — attaching BPF, and handing bytes over

This layer does two things and deliberately nothing else: it gets BPF programs
loaded and attached, and it hands each raw record to the detection pipeline. It
does not parse events, decide whether one is a violation, or dispatch a
countermeasure.

Per-detection rationale — what each rule looks for, how it is fed, and what it
cannot see — lives in [`detections/<family>/DESIGN.md`](../detections/), one
document per detection. This document is about the machinery underneath them.

## Two classes, and which way the inheritance runs

```
BpfProgram                     HttpGuardProgram
├── attach(obj, links)         ├── owns THE bpf_object
├── eventSource()              ├── owns THE ring buffer
└── ringBufferHandler()        ├── owns the poll loop
    └── submit(data, size,     └── holds vector<unique_ptr<BpfProgram>>
                detections_)
        ▲                              │
        │                              │
   SslUprobeProgram                    │ attaches each hook into its object,
   XdpTlsProgram          ◄────────────┘ then dispatches records back to them
   LsmCertGuardProgram
```

**A hook IS a `BpfProgram`; the orchestrator HAS several.** It used to be the
other way round — `HttpGuardProgram` inherited `BpfProgram` — which meant the
orchestrator inherited a BPF object lifecycle it was only half using, and
supplied the ring-buffer callback for records produced by *hooks*, the one thing
it is not.

### `BpfProgram` — three methods, one already implemented

`attach()` and `eventSource()` are pure virtual. `ringBufferHandler()` is not:
every hook overrides it, and the override is one line.

```cpp
void XdpTlsProgram::ringBufferHandler(const void* data, std::size_t size) noexcept
{
    DetectLoop::getInstance().submit(data, size, detections_);
}
```

That line is the whole of a hook's involvement in classification: it says *which
detections its records can feed*, in priority order, and returns. It must return
promptly — a slow callback lets the ring buffer fill, and a full ring buffer
**drops events**, which is a missed detection rather than merely added latency.

The base implementation submits an **empty** list, which `DetectLoop` counts and
reports. So a hook that forgets to declare its detections is loud rather than
silently discarding its own events.

A hook owns its detections as members, because `submit()` returns immediately
and the record is inspected later — the pointers must outlive the async hop.
They are `const` and stateless, because the connection-rate sweep can run them
concurrently with a record.

### `HttpGuardProgram` — one object, one ring buffer, one blocklist map

All three are singular **on purpose**, and it is the kind of invariant that
breaks silently if ignored: `BlocklistAddAction` writes the blocklist map that
the XDP program reads, so giving each hook its own `bpf_object` would give each
its own map. Enforcement would stop working while every log line still said it
was active.

```
loadFilter()
  ├── openObject()          bpf_object__open_file()
  ├── bpf_object__load()
  ├── attachHooks()         each hook->attach(object_, links_)
  │     └── requires at least ONE to succeed; which hooks are required vs.
  │         auxiliary is each hook's own diagnostic to log
  ├── Blocklist::adopt()    hand the map to the actions layer
  └── registerEventHandler() ring_buffer__new(events_fd, &ringBufferCallback, this)
```

**Where the libbpf trampoline lives, and why not on `BpfProgram`.**
`ring_buffer__new()` takes one callback and one context for the whole buffer,
and there is one shared buffer — so a per-hook static could never be the thing
libbpf calls. `HttpGuardProgram::ringBufferCallback()` reads the event source at
offset 0 of the record, finds the owning hook, and calls *that hook's*
`ringBufferHandler()`. An unowned source is reported, rate-limited
1-then-every-1000, because a mislabelled producer would otherwise flood the
journal at line rate.

The summary line is deliberately hook-agnostic:

```
https_guard: enforcement active via 2 of 3 hook(s)
```

The orchestrator has no hook names to report, only the `BpfProgram` base. Each
hook logs its own specific outcome.

## Per-hook attach specifics

### `ssl_uprobe` — uprobes on `libssl.so`

`bpf_program__attach_uprobe_opts(prog, -1, lib_path, 0, &opts)` — **`pid = -1`
means every process on the system**, not just bmcweb. That is deliberate: a
compromised BMC service exfiltrating over TLS, or a tool other than bmcweb
probing something over HTTPS, shows up here exactly as a legitimate client does.
It is also this hook's biggest gap — see
[`detections/payload_anomaly/DESIGN.md`](../detections/payload_anomaly/DESIGN.md)
on why `comm` is a hint and not an identity.

Three BPF programs attach, not two, because `SSL_read` needs a paired
entry+return probe:

| Program | Section | Shape |
|---|---|---|
| `https_guard_ssl_write` | `uprobe/ssl_write` | entry only |
| `https_guard_ssl_read_entry` | `uprobe/ssl_read` | entry, stashes args |
| `https_guard_ssl_read_exit` | `uprobe/ssl_read` | `retprobe=true`, reads + submits |

The reason is in
[`detections/payload_anomaly/DESIGN.md`](../detections/payload_anomaly/DESIGN.md):
`SSL_read`'s buffer is an *output* parameter, uninitialised at entry.

**Attach criticality:** `SSL_write` is this hook's required signal. Either half
of the `SSL_read` pair failing is logged but non-fatal, since `SSL_write` alone
still works. The daemon refuses to start only if *zero* hooks attach.

### `xdp_tls` — XDP on the NIC RX path

Attaches with `bpf_program__attach_xdp()`, which returns a real `bpf_link*`, so
**the kernel owns the attachment's lifetime**: when the link fd closes the
program is detached, including on a crash or `SIGKILL` where no destructor would
run.

That matters because the legacy `bpf_xdp_attach()` path does the opposite — the
attachment belongs to the *netdev* and outlives the process. The daemon used to
attach that way and never detach, so every restart hit "XDP program already
attached" and silently ran uprobe-only until reboot, while still reporting
itself healthy. The legacy path is kept as a fallback for kernels without link
support, and only there does the destructor detach explicitly.

**Stale attachments are identified before removal.** `clearStaleAttachment()`
queries the interface, resolves the attached program and compares its name:
`https_guard_xdp` means a leaked instance of *us*, so detach and continue;
anything else is logged and left alone. Clearing whatever happens to be on the
interface would trade our own outage for another tool's.

**Native attach is tried first, then generic/SKB mode, then the hook is skipped
without error.** The mode is a flag on `bpf_xdp_attach()`, and the difference is
*where in the receive path the program runs*:

| Mode | Flag | Runs | Cost | Needs |
|---|---|---|---|---|
| **Native** | `XDP_FLAGS_DRV_MODE` | inside the driver's Rx path, on the raw DMA buffer, **before** the kernel builds an `sk_buff` | lowest — an `XDP_DROP` costs almost nothing | driver XDP support (the AST2600's `ftgmac100` has it) |
| **Generic / SKB** | `XDP_FLAGS_SKB_MODE` | in the stack, **after** the `sk_buff` is already allocated | higher — the per-packet allocation has already happened | nothing — works on any driver, `veth`, or virtio-net (QEMU's TAP path) |
| **Offloaded** | `XDP_FLAGS_HW_MODE` | on a SmartNIC's own processor | none on the host CPU | a SmartNIC — no BMC NIC has one, so it is never attempted |

Native gives the enforcement its point: dropping a blocklisted source before an
`sk_buff` exists is what makes XDP cheaper than any userspace filter. Generic is
a correctness fallback, not a performance one — it keeps the hook working on
virtual NICs during development, at a cost that does not matter there. Passing
no mode bit already defaults to native, but the code names `XDP_FLAGS_DRV_MODE`
explicitly and does the DRV→SKB downgrade itself, so the startup log says which
mode actually took. See also the platform-adaptive section of the top-level
[`DESIGN.md`](../../../../DESIGN.md). XDP requires a real netdev, which SLIRP-mode
QEMU and some NICs do not offer, so this hook is auxiliary specifically so its
absence never stops the daemon.

### `lsm_cert_guard` — BPF-LSM on `file_open`

Expected to **fail** on this project's ARM32 target:

```
libbpf: prog 'https_guard_cert_open': failed to attach: -ENOTSUPP
https_guard: failed to attach LSM cert-access-guard (non-fatal): Unknown error 524
```

`BPF_PROG_TYPE_LSM` attach requires the BPF trampoline mechanism, and
`arch/arm/net/` has never implemented `arch_prepare_bpf_trampoline()`. Not
fixable at the BPF-program level. `2 of 3` is therefore the expected healthy
state here. Full reasoning, and the two approaches tried before settling on a
userspace identity check, in
[`detections/cert_access/DESIGN.md`](../detections/cert_access/DESIGN.md).

## The BPF object is one translation unit

`core/ebpf/https_guard.bpf.c` is the only file clang compiles for the BPF
target. It declares the shared ring buffer map and `#include`s each hook's
`<hook>.bpf.h`, so the result is a single object with one ring buffer, one
blocklist map, one per-source counter map and one load/verify pass, regardless
of how many hook headers get added.

Adding a hook means one `#include` there, one class here, one line in
`main.cpp`, and its sources in `CMakeLists.txt` and the recipe's `SRC_URI`.

## The raw event ABI

Each hook's `ebpf/<hook>_event.h` defines the bytes it puts on the ring buffer.
Both the BPF program and the C++ side compile the same header, so there is no
marshalling step — and nothing to catch a mismatch, which is why the layout is
nested rather than flat. Full detail, including the two `static_assert`ed
invariants, is in the top-level [`DESIGN.md`](../../../../DESIGN.md) under "The raw
event ABI".
