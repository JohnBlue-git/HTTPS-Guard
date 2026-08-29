# programs/ — Detect layer

Attaches BPF hooks, parses their raw ring-buffer events into the common `hg_event` representation. Nothing in this directory decides whether an event is a violation (that's `../detections/`) or dispatches a countermeasure (`../actions/`) — purely observe-and-parse, mirroring how the BPF side itself is purely observational.

## Layout

- **`core/`** — the parts that aren't specific to any one hook:
  - `BpfProgram.{hpp,cpp}` — generic BPF lifecycle wrapper (open/load/attach/poll). Knows nothing about uprobes, XDP, SSL, or hooks — could be lifted into an unrelated future BPF tool unchanged. Compare against `HttpGuardProgram` below; they look similar but sit at different abstraction layers and change for different reasons (this one only if libbpf's API changes).
  - `HttpGuardProgram.{hpp,cpp}` — the sole `BpfProgram` subclass. Owns the hook list, attaches them, and forwards each raw ring-buffer record to `DetectLoop` — nothing more. **Adding a hook should never mean editing this file** — if you find yourself doing that, something about the new hook doesn't fit `IHookModule` and that's worth reconsidering first.

  The interface a hook implements (`IHookModule`), the shared event discriminator (`hg_event_source.h`) and the engine that consumes what hooks produce (`DetectLoop`) all live in `../detections/core/`, not here: they belong to the detection concern, and keeping them there is what stops the dependency graph forming a cycle. `IHookModule.hpp` deliberately forward-declares `bpf_object`/`bpf_link` rather than including libbpf, so the classification tree stays buildable without a kernel.
  - `https_guard.bpf.c` — the *only* file clang actually compiles for the BPF target. Declares the shared ring buffer map, then `#include`s each hook's `<hook>.bpf.h`. One BPF object, one ring buffer, regardless of hook count.
  - `main.cpp` — the composition root. The one place that knows about every concrete `IHookModule` and `IDetector`. Adding a hook or a detector means adding a line here, never touching `HttpGuardProgram`.
### Per-hook layout

Every hook directory splits two ways, so what a file *is* is visible from its path:

- **`ebpf/`** — the `SEC(...)` program body and the raw event struct it submits. C, compiled by clang for the BPF target.
- **`src/`** — the `IHookModule` implementation and any helper only this hook needs.

**Classification rules are not here.** Every `IDetector` lives in `../detections/`, regardless of how many hooks feed it. An earlier version of this layout put hook-specific rules in a per-hook `detector/` directory, which sounded tidier but wasn't: deciding where a rule went required reasoning about whether some *future* hook might produce the same fields, and it left `ssl_uprobe/` with no `detector/` at all because both of its rules are shared with XDP. Keeping all rules in one place removes the judgment call, and keeps `programs/` the only tree that depends on libbpf — so a classification rule cannot accidentally acquire a kernel dependency from the code sitting beside it.

- **`ssl_uprobe/`** — PRIMARY hook. See its own `CLAUDE.md` + `DESIGN.md`.
- **`xdp_tls/`** — AUXILIARY hook. See its own `CLAUDE.md` + `DESIGN.md`.
- **`lsm_cert_guard/`** — AUXILIARY hook, BPF-LSM certificate-access guard. See its own `CLAUDE.md` + `DESIGN.md` — in particular, its `attach()` is currently expected to fail non-fatally on ARM32/AST2600 targets (this platform's BPF JIT has no trampoline support at all, which BPF_PROG_TYPE_LSM attach fundamentally requires — not something fixable at the BPF-program level).
- **`utils/bounded_string.hpp`** — the one thing multiple hooks need identically: turning a fixed-size `char[]` from a raw BPF struct into a `std::string`, without assuming it's null-terminated.

## Adding a new hook

1. New subdirectory here, named after the hook.
2. `<hook>/ebpf/<hook>.bpf.h` with the `SEC(...)` program body (see `ssl_uprobe/ebpf/ssl_uprobe.bpf.h` for the shape), plus `<hook>/ebpf/<hook>_event.h` defining its raw event struct (`#include "hg_event_source.h"` for the shared discriminator).
3. `#include "../<hook>/ebpf/<hook>.bpf.h"` from `core/https_guard.bpf.c`.
4. A C++ class implementing `IHookModule`, in `<hook>/src/`.
5. Register it in `main.cpp`'s `buildHookModules()`.
6. Add its sources to `CMakeLists.txt`'s `programs_lib` (and its three include dirs), and its files to the `.bb` recipe's `SRC_URI`.
7. Any new classification rule goes in `../detections/<rule-family>/`, and is registered for this hook's `hg_event_source` in `main.cpp` — never inside this directory.

Remaining planned work (cipher-suite/SNI detection extending `xdp_tls`, connection-rate detection, Slowloris/renegotiation-storm detection) is tracked in `.scratch/` — see its tickets for specifics.
