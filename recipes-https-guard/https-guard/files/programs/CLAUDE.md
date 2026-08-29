# programs/ — Detect layer

Attaches BPF hooks, parses their raw ring-buffer events into the common `hg_event` representation. Nothing in this directory decides whether an event is a violation (that's `../detectors/`) or dispatches a countermeasure (`../actions/`) — purely observe-and-parse, mirroring how the BPF side itself is purely observational.

## Layout

- **`core/`** — the parts that aren't specific to any one hook:
  - `BpfProgram.{hpp,cpp}` — generic BPF lifecycle wrapper (open/load/attach/poll). Knows nothing about uprobes, XDP, SSL, or hooks — could be lifted into an unrelated future BPF tool unchanged. Compare against `HttpGuardProgram` below; they look similar but sit at different abstraction layers and change for different reasons (this one only if libbpf's API changes).
  - `IHookModule.hpp` — the interface every hook implements: `attach(bpf_object*, links&) -> bool`, `eventSource() -> hg_event_source`, `parseEvent(data, size) -> optional<hg_event>`.
  - `HttpGuardProgram.{hpp,cpp}` — the sole `BpfProgram` subclass; the orchestrator. Holds the hook-module list and the detector registry (both injected by `main.cpp`, never constructed here) and loops over them generically. **Adding a hook should never mean editing this file** — if you find yourself doing that, something about the new hook doesn't fit `IHookModule` and that's worth reconsidering first.
  - `hg_event_source.h` — the shared `enum hg_event_source` discriminator. Compiled by both the BPF side (`.bpf.c`/`.bpf.h`, as C) and the C++ side — keep it C-compatible, no `enum class`, no C++-only syntax.
  - `https_guard.bpf.c` — the *only* file clang actually compiles for the BPF target. Declares the shared ring buffer map, then `#include`s each hook's `<hook>.bpf.h`. One BPF object, one ring buffer, regardless of hook count.
  - `main.cpp` — the composition root. The one place that knows about every concrete `IHookModule` and `IDetector`. Adding a hook or a detector means adding a line here, never touching `HttpGuardProgram`.
- **`ssl_uprobe/`** — PRIMARY hook. See its own `CLAUDE.md` + `DESIGN.md`.
- **`xdp_tls/`** — AUXILIARY hook. See its own `CLAUDE.md` + `DESIGN.md`.
- **`lsm_cert_guard/`** — AUXILIARY hook, BPF-LSM certificate-access guard. See its own `CLAUDE.md` + `DESIGN.md` — in particular, its `attach()` is currently expected to fail non-fatally on ARM32/AST2600 targets (this platform's BPF JIT has no trampoline support at all, which BPF_PROG_TYPE_LSM attach fundamentally requires — not something fixable at the BPF-program level).
- **`utils/bounded_string.hpp`** — the one thing multiple hooks need identically: turning a fixed-size `char[]` from a raw BPF struct into a `std::string`, without assuming it's null-terminated.

## Adding a new hook

1. New subdirectory here, named after the hook.
2. A `<hook>.bpf.h` with the `SEC(...)` program body (see `ssl_uprobe/ssl_uprobe.bpf.h` for the shape), plus a `<hook>_event.h` defining its raw event struct (`#include "../core/hg_event_source.h"` for the shared discriminator).
3. `#include` the new `.bpf.h` from `core/https_guard.bpf.c`.
4. A C++ class implementing `IHookModule`, in its own `.hpp`/`.cpp`.
5. Register it in `main.cpp`'s `buildHookModules()`.
6. Add its sources to `CMakeLists.txt`'s `programs_lib`, and its files to the `.bb` recipe's `SRC_URI`.

Remaining planned work (cipher-suite/SNI detection extending `xdp_tls`, connection-rate detection, Slowloris/renegotiation-storm detection) is tracked in `.scratch/` — see its tickets for specifics.
