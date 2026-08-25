# programs/ — Detect layer

`DESIGN.md` in this directory covers `BpfProgram`, `HttpGuardProgram`, the
one-object invariant and each hook's attach specifics. The per-hook `DESIGN.md`
files are gone: detection rationale moved to `../detections/<family>/DESIGN.md`,
where a reader asking "how does X detection work" actually looks.

Attaches BPF hooks and hands their raw ring-buffer records to the detection
pipeline. That is *all* this directory does: it does not parse events, decide
whether one is a violation, or dispatch a countermeasure. Parsing moved to
`../detections/<family>/` because turning bytes into an event is part of deciding
what the event means — which leaves a hook down to the two things only it can
do, attach and hand over bytes.

## Layout

- **`core/`** — the parts that aren't specific to any one hook. Splits `ebpf/` + `src/` exactly like a hook directory, so the same rule reads everywhere: the path tells you what a file *is*.
  - `ebpf/https_guard.bpf.c` — the *only* file clang actually compiles for the BPF target. Declares the shared ring buffer map, then `#include`s each hook's `<hook>.bpf.h` (reaching up two levels: `../../<hook>/ebpf/<hook>.bpf.h`). One BPF object, one ring buffer, regardless of hook count.
  - `src/BpfProgram.{hpp,cpp}` — **the base class every hook inherits.** `attach()`, `eventSource()`, and a virtual `ringBufferHandler()`. Every hook overrides that last one, because it is where the hook declares **which detections its records can feed**:

    ```cpp
    void ringBufferHandler(const void* data, std::size_t size) noexcept override
    {
        DetectLoop::getInstance().submit(data, size, detections_);
    }
    ```

    The base implementation submits an empty list, which `DetectLoop` counts and reports — so a hook that forgets to declare its detections is loud rather than silently discarding its own events.
  - `src/HttpGuardProgram.{hpp,cpp}` — owns the BPF object, the ring buffer and the poll loop, and manages the hooks. It does **not** inherit `BpfProgram`: a hook *is* one, this class *has* several.
  - `main.cpp` — the composition root, deliberately at the *top* of `core/` rather than in `src/`: it belongs to neither half. The one file that knows every concrete hook and every source handler.

**One object, one ring buffer, one blocklist map.** All three are singular on
purpose. `BlocklistAddAction` writes the map the XDP program reads, so splitting
the object per hook would give each its own map and enforcement would stop
working while still looking healthy. Hooks attach *into* an object
`HttpGuardProgram` opens and loads.

**Where the libbpf ring-buffer trampoline lives, and why not on `BpfProgram`.**
`ring_buffer__new()` takes one callback and one context for the whole buffer,
and there is one shared buffer — so a per-hook static could never be the thing
libbpf calls. `HttpGuardProgram::ringBufferCallback()` reads the event source at
offset 0, finds the owning hook, and calls *that hook's* `ringBufferHandler()`.

**A hook owns its detections as members**, so the pointers it submits stay valid
for as long as `DetectLoop` might inspect the record — `submit()` returns
immediately and the record is processed later. They are `const` and stateless
because the sweep thread can run them concurrently with a record.

**List order is priority order**, and it is a real decision made here rather
than in `detections/`. A ClientHello can satisfy several detections at once and
only the first verdict is emitted, so `xdp_tls` puts the two enforcing rules
before the two alert-only ones — a legacy-TLS ClientHello that also offers RC4
is reported as the TLS violation, which enforces. The loop logs which index
claimed each record, so the ordering is observable at runtime.

### Per-hook layout

Every hook directory splits two ways, so what a file *is* is visible from its path:

- **`ebpf/`** — the `SEC(...)` program body and the raw event struct it submits. C, compiled by clang for the BPF target.
- **`src/`** — the `BpfProgram` subclass and any helper only this hook needs. No event types and no parsing: both live in `../detections/`.

**The raw event struct is nested, not flat.** Every `<hook>_event.h` starts with
`struct hg_event_hdr` (the shared envelope: `event_source`, `timestamp_ns`,
`pid`/`tgid`, `comm`) and then adds one sub-struct per group of fields only that
hook can observe. Two rules follow, pinned by `static_assert` in each hook's
`.cpp` rather than left to care: **`hdr` must be first**, and **`event_source`
must be first inside `hdr`**, because dispatch reads a `uint32` at offset 0
before it knows the record's type.

These headers are the BPF↔userspace **wire format**, not code — plain C, no
libbpf, compiled by both sides. That is why `detections/` includes them: parsing
them lives with the rules.

**Neither rules nor event types are here.** Both live in `../detections/`,
which keeps `programs/` the only tree that depends on libbpf — so a
classification rule cannot accidentally acquire a kernel dependency from code
sitting beside it. An earlier layout put hook-specific rules in a per-hook
`detector/` directory, which sounded tidier but wasn't: deciding where a rule
went required reasoning about whether some *future* hook might produce the same
fields, and it left `ssl_uprobe/` with no `detector/` at all because both of its
rules are shared with XDP.

- **`ssl_uprobe/`** — PRIMARY hook. Uprobes on OpenSSL's `SSL_write()` *and* `SSL_read()` in `libssl.so`, which fire for *every* process that calls either, not just bmcweb. Captures the negotiated TLS version and a plaintext snippet tagged with a `direction` (write is entry-only; read needs a paired entry+return uprobe). Uprobe context has no socket access, so `src/proc_peer_resolver.hpp` resolves the calling PID to a TCP socket via `/proc/<pid>/net/tcp` — that is this hook's `IPeerResolver`, used nowhere else. Submits, in order: TLS version, payload anomaly, traffic-observed. Process identity is `comm`, which is spoofable; `lsm_cert_guard/` exists for the stronger question. Attach mechanics in `DESIGN.md` here; detection rationale in `../detections/{tls_version,payload_anomaly}/DESIGN.md`.
- **`xdp_tls/`** — AUXILIARY hook. XDP on the NIC RX path, inspecting the TLS ClientHello and plaintext-HTTP-on-443 at the wire, before any TCP/TLS handshake completes. The only hook whose synchronous enforcement (`XDP_DROP` for a blocklisted source or a downgraded ClientHello) is reachable in practice, and the only place `blocklist_check()` (shared with `../../actions/blocklist/`) runs. `ebpf/parse_client_hello.h` extracts `legacy_version`, the offered cipher-suite list and the SNI host_name — kept deliberately dependency-free so the *same* code the kernel runs is unit-tested host-side (`../../tests/test_client_hello_parsing.cpp`); don't "simplify" its byte-at-a-time reads, which exist to satisfy the verifier. Feeds the most detections — `../detections/{tls_version,payload_anomaly,cipher_suite,sni}/` plus the three counter families. Cipher-suite and SNI are alert-only on purpose: the XDP blocklist drops a source across *all* ports, so enforcing on one odd handshake could lock an administrator out of SSH. Attach mechanics — BPF-link ownership and the native→generic→skip fallback — in `DESIGN.md` here.
- **`lsm_cert_guard/`** — AUXILIARY hook, BPF-LSM on the `file_open` security hook filtered to the HTTPS certificate/key path. Its whole reason to exist is a *stronger* identity check than `ssl_uprobe`'s spoofable `comm` — but that check (the accessing process's real executable) resolves only in userspace on this platform, inside `../detections/cert_access/`. Its `attach()` is expected to fail non-fatally on ARM32/AST2600: `bpf_program__attach_lsm()` returns `-ENOTSUPP` because this platform has no BPF trampoline at all, which `BPF_PROG_TYPE_LSM` attach fundamentally requires. Not fixable at the BPF-program level — the full story, including the two in-kernel approaches tried first, is in `../detections/cert_access/DESIGN.md`.
- **`utils/bounded_string.hpp`** — the one thing multiple hooks need identically: turning a fixed-size `char[]` from a raw BPF struct into a `std::string`, without assuming it's null-terminated.

## Adding a new hook

1. New subdirectory here, named after the hook.
2. `<hook>/ebpf/<hook>.bpf.h` with the `SEC(...)` program body (see `ssl_uprobe/ebpf/ssl_uprobe.bpf.h` for the shape), plus `<hook>/ebpf/<hook>_event.h` defining its raw event struct — `#include "hg_event_source.h"`, lead with `struct hg_event_hdr hdr;`, and put the hook's own fields in named sub-structs rather than flat.
3. `#include "../../<hook>/ebpf/<hook>.bpf.h"` from `core/ebpf/https_guard.bpf.c`.
4. A C++ class deriving from `BpfProgram`, in `<hook>/src/`, implementing `attach()` and `eventSource()`, holding its detections as members and overriding `ringBufferHandler()` to submit them. Put an always-matching `TrafficObservedDetection` last.
5. Register it in `main.cpp`'s `buildHookModules()`.
6. Add its sources to `CMakeLists.txt`'s `programs_lib` (and its include dirs), and its files to the `.bb` recipe's `SRC_URI`.
7. Any new detection is a directory under `../detections/<family>/` holding its event struct, its rule, its `IDetection` implementation and its `DESIGN.md` — then one entry in this hook's list. Nothing about it goes in this directory, and `main.cpp` does not change.

All tracked work is closed; `.scratch/extend-detection-coverage/PRIORITY.md` is the ledger.
