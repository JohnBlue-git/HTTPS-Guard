# 12 — Reorganize each hook into ebpf/detector/src, and rename detectors/ → detections/

**What to build:** Give every hook one directory containing everything that hook owns, split by kind:

```
programs/<hook>/ebpf/      the .bpf.h program + its raw <hook>_event.h
programs/<hook>/detector/  the detectors that only that hook's data feeds
programs/<hook>/src/       the IHookModule implementation + its helpers
```

and rename the top-level `detectors/` to `detections/`.

**Blocked by:** 11 — Move parse/classify/dispatch off the ring-buffer poll thread into a DetectLoop (11 changes who calls the detectors; doing the file moves first would mean rewriting the same include paths and CMake wiring twice)

**Status:** done

## What moves, and the one thing that can't

Hook-specific detectors move into their hook, which is the cohesive part of this change — each is useless without the hook that populates its fields:

| Detector | Only meaningful for | Destination |
|---|---|---|
| `CipherSuiteDetector` + `weak_cipher_suites.hpp` | ClientHello bytes — XDP only | `programs/xdp_tls/detector/` |
| `SniDetector` | ClientHello bytes — XDP only | `programs/xdp_tls/detector/` |
| `CertAccessDetector` | `cert_identity_mismatch` — LSM only | `programs/lsm_cert_guard/detector/` |

**`TlsVersionDetector` and `PayloadAnomalyDetector` cannot move into a hook.** Both are registered for `HG_SOURCE_UPROBE` *and* `HG_SOURCE_XDP` in `buildDetectorRegistry()`. Putting them under one hook's `detector/` would force the other hook to include across a sibling directory — coupling two hooks that are otherwise independent, and contradicting the rule that a hook directory is self-contained. They stay in the shared tree, alongside the core interfaces.

So `detections/` ends up holding:

```
detections/core/            IDetector.hpp, Verdict.hpp, hg_event.hpp
detections/tls_version/     TlsVersionDetector.hpp, tls_version.hpp   (shared: uprobe + XDP)
detections/payload_anomaly/ PayloadAnomalyDetector.hpp                (shared: uprobe + XDP)
```

## Dependency direction to preserve

Today `programs_lib` links `detections_lib` in one direction only, and `hg_event.hpp` deliberately lives in the classify tree rather than `programs/` **specifically to keep that acyclic** (recorded in the current `detectors/CLAUDE.md`). Moving detectors under `programs/` must not invert or cycle that: the hook-specific detectors still depend only on `detections/core`, never on their hook's `src/` or `ebpf/`. If a detector ever needs something from `src/`, that's the signal it's stopped being a pure classification rule.

The practical trap: once a detector sits inside a `programs/` subdirectory that also contains libbpf-dependent code, nothing structurally stops it acquiring a libbpf include. The current split makes that impossible by construction; after this change it's only a convention, so it needs stating.

- [x] Each hook directory has `ebpf/`, `detector/`, `src/`, with files placed per the table above, and no hook includes another hook's headers
- [x] `detectors/` is renamed `detections/` and holds only the core interfaces plus the two genuinely shared rules
- [x] Hook-specific detectors compile against `detections/core` only — verified by the fact that the unit tests still link them without pulling in libbpf, exactly as the current tests do
- [x] The unit-test target still builds and passes host-side with no kernel/BPF/root dependency, including the parser tests that rely on `parse_client_hello.h` and `parse_uprobe_event.hpp` staying dependency-free after the move
- [x] Every moved file's path is updated in the `.bb` recipe's `SRC_URI`, and the recipe builds under real `bitbake` — the cross-compile is the only thing that catches a stale `SRC_URI` entry or an output-path assumption
- [x] `CLAUDE.md` files are updated to describe the new layout, including where the shared detectors live and why they didn't move
- [x] Verified on QEMU that the daemon still attaches and detects after the reorganization — a pure file move can still break the BPF object's relative `#include`s in `core/https_guard.bpf.c`

## Comments

Landed in two parts. The `detections/` rename and the move of `DetectLoop`,
`IHookModule` and `hg_event_source.h` into `detections/core/` went with
ticket 11, because 11 was rewriting those call sites anyway and doing it
twice would have been wasted work. This ticket finished the per-hook split.

### Final layout

```
programs/<hook>/ebpf/      SEC(...) program body + raw event struct
programs/<hook>/src/       IHookModule implementation + its helpers
programs/<hook>/detector/  IDetector rules only this hook's data can feed

detections/core/           hg_event, Verdict, IDetector, IPeerResolver,
                           IHookModule, hg_event_source, DetectLoop
detections/tls_version/    shared: uprobe + XDP
detections/payload_anomaly/ shared: uprobe + XDP
```

`ssl_uprobe/` has **no `detector/` directory**, and that is the correct
outcome rather than an omission: both rules that read its events
(`TlsVersionDetector`, `PayloadAnomalyDetector`) are also registered for XDP.
Putting a shared rule inside one hook would force the other hook to include
across a sibling directory, coupling two hooks that are otherwise
independent — so the rule for placement is "a rule lives in a hook's
`detector/` only when no other hook could ever produce the fields it reads".
`CipherSuiteDetector`/`SniDetector` (ClientHello bytes) and
`CertAccessDetector` (`cert_identity_mismatch`) qualify; those two do not.

### On the dependency risk the ticket flagged

The concern was that once a detector sits in a directory beside
libbpf-dependent code, nothing structurally stops it acquiring a libbpf
include. That is now weaker than it was, but still checked by construction:
the unit-test target links the hook-specific detectors *without* libbpf and
still builds, so a stray include would break the tests rather than pass
silently. The `ebpf/`/`src/`/`detector/` split also makes the intended
boundary visible in the path, which it was not before.

### Verification

- 44/44 unit tests pass under ASan/UBSan, with the hook-specific detectors
  compiled from their new homes and still no libbpf dependency.
- Clean cross-compile from `cleansstate` — the only thing that catches a
  stale `SRC_URI` entry (19 paths moved) or a broken relative include in the
  BPF aggregator, which now reaches `../<hook>/ebpf/<hook>.bpf.h`. All four
  BPF programs still present in the object.
- QEMU: all hooks attach (`2 of 3`, LSM expected to fail on ARM32), the
  uprobe path still enforces (`destroyed TCP connection` on a live
  connection), the XDP path still parses ClientHellos, and the Redfish log
  shows all three verdict types — `HttpsPayloadAnomalyDetected`,
  `HttpsWeakCipherSuiteDetected`, `HttpsTrafficObserved`. A pure file move
  can only break paths, so behaviour being unchanged is the whole test.

## Revised after review — all detectors live in `detections/`

The per-hook `detector/` directories were removed shortly after landing, on
review feedback, and every classification rule moved (back) into
`detections/<rule-family>/`. Final layout:

```
programs/<hook>/ebpf/   SEC(...) program body + raw event struct
programs/<hook>/src/    IHookModule implementation + helpers

detections/core/            hg_event, Verdict, IDetector, IPeerResolver,
                            IHookModule, hg_event_source, DetectLoop
detections/tls_version/     shared: uprobe + XDP
detections/payload_anomaly/ shared: uprobe + XDP
detections/cipher_suite/    XDP in practice
detections/sni/             XDP in practice
detections/cert_access/     LSM in practice
```

**Why this is better than what this ticket originally specified.** The
placement rule I had written — "a rule lives with a hook only when no other
hook could ever produce the fields it reads" — requires reasoning about
*hypothetical future hooks* every time someone adds a detector. That is
exactly the kind of rule that decays: the first person who adds a rule that
looks single-hook but later isn't has to move files and rewire two
CMakeLists. It had already produced a visible oddity, with `ssl_uprobe/`
having no `detector/` directory at all because both of its rules are shared.

Uniform placement removes the judgment call entirely, restores the clean
mapping (`programs/` = how we observe, `detections/` = what counts as a
violation), and keeps `programs/` the only tree that depends on libbpf — so
the contamination risk this ticket flagged is structurally out of reach again
rather than merely watched by a test.

It also fits where ticket 15 is going: capability interfaces
(`ITlsTrafficInfo` and friends) will live in `detections/core/`, and having
every rule already beside them avoids a second round of moves.

Verified again after the change: 44/44 tests, clean cross-compile from
`cleansstate`, no stale `detector/` references anywhere in the tree.
