# Documentation restructure and refinement

Status: done — see Comments

## Problem Statement

HTTPS-Guard's documentation has fallen behind and outgrown its current shape
in three separate ways:

1. **Drift.** A large round of work (dual-stack peer attribution, the
   kernel-side session-binding mechanism, the periodic sweep safety net)
   landed across several files, and while the directly-touched docs were kept
   current, the rest of the `DESIGN.md`/`CLAUDE.md` set was not
   comprehensively re-audited against the code as it stands today.
2. **Missing material.** Nothing in the docs currently explains, at the level
   of detail an operator or a future maintainer needs: which Redfish event
   each detection produces and via which hook and action it gets there; the
   mechanics of XDP's three operating modes and why this project's target
   (SLIRP in test, `ftgmac100` on real AST2600 hardware) is stuck on the
   slowest one; how to debug a failed hook attach without `bpftool` (which is
   deliberately not shipped — see `LIMITATIONS.md`); or how to check, on an
   arbitrary target kernel, which BPF program types, hooks and tracepoints it
   actually supports.
3. **Wrong shape.** The three root-level narrative docs (`DESIGN.md`,
   `DESIGN.html`, `LIMITATIONS.md`) sit at the repo root, uneasily mixed in
   with `README.md`, `CLAUDE.md`, build files and source trees, rather than
   grouped as the "read these to understand the project" set they actually
   are.

Left alone, the docs keep drifting further from the code, an operator with a
failed hook attach and no `bpftool` has nowhere in-repo to turn, and the docs
directory keeps looking more like an afterthought than the "every unit
documents itself" discipline the rest of this codebase holds itself to.

## Solution

A docs-only effort (no source or build-logic changes) that:

- Moves the root-level narrative docs into a dedicated `docs/` folder,
  leaving `README.md` as the root's front door.
- Re-audits every `DESIGN.md`/`CLAUDE.md` in the tree against the
  current code.
- Adds the missing Detected → Hook → Action reference table to the root
  design doc (and a lighter, visual version to its HTML companion).
- Adds three new reference docs under `docs/`: XDP internals and network
  data flow, `bpftool`/no-`bpftool` debugging, and how to check a target
  kernel's actual BPF/tracepoint capabilities.
- Attaches a small ASCII diagram to every existing bullet in
  `LIMITATIONS.md`, so each limitation is visually as well as textually
  explained.

## User Stories

1. As a new contributor, I want the repo's narrative documentation grouped
   under one `docs/` folder, so I know at a glance which files are "read this
   to understand the project" versus source code, build files, or per-unit
   design notes that stay next to the code they describe.
2. As a returning contributor, I want `README.md` to stay at the repository
   root, so the standard "read the README first" convention still works
   without a redirect.
3. As a contributor reading a `<family>/DESIGN.md` or a `CLAUDE.md` that
   links to the root `DESIGN.md` or `LIMITATIONS.md`, I want that link to
   still resolve after the move, so I don't hit a 404 in my own repo.
4. As a maintainer, I want every `DESIGN.md` and `CLAUDE.md` in the tree
   re-checked against the current code (dual-stack `IpAddress`, the
   kernel-side session-binding mechanism, the periodic session-tuple sweep,
   the IPv4-only blocklist with IPv6 teardown-only enforcement), so none of
   them describes a mechanism that no longer matches what ships.
5. As an on-call operator, I want one table that says, for each thing
   HTTPS-Guard can detect, which Redfish event message it produces, which
   hook(s) feed it, and which action(s) it can trigger, so I can go from "I
   saw event X in the log" to "here's what could have caused it and what it
   did about it" without reading nine separate `DESIGN.md` files.
6. As a contributor comparing detections, I want a plain list of every event
   type, every hook, and every action HTTPS-Guard has, so I have a
   vocabulary/inventory to check new work against.
7. As a visitor skimming `DESIGN.html` rather than the full `DESIGN.md`, I
   want its existing pipeline and platform-enforcement sections updated to
   mention dual-stack/session-binding and to carry a compact version of the
   new detected/hook/action table, without `DESIGN.html` growing to cover
   everything the deep-reference `DESIGN.md` now covers.
8. As a developer trying to understand why this project can't get full XDP
   acceleration on its target, I want a document that walks through the
   traditional (no-XDP) packet path and each of the three XDP modes
   (offloaded, native, generic), in the same request-flow-diagram style
   already used elsewhere in this codebase, so I understand where in the
   stack each mode intercepts a packet and why that changes the cost.
9. As that same developer, I want `ndo_bpf` explained as a network-driver-level
   hook (not a syscall hook), so I understand why XDP's native mode is a
   driver capability question, not a kernel-version question.
10. As a developer working against this project's QEMU/SLIRP test
    environment, I want to know how to actually determine that SLIRP doesn't
    support XDP, rather than taking it on faith, so I can verify the same
    reasoning on a different test setup if the tooling ever changes.
11. As a developer targeting a new piece of hardware, I want to know how to
    check whether that hardware's NIC driver implements `ndo_bpf`, so I can
    tell in advance whether native XDP is even possible there.
12. As an operator with a hook that fails to attach and no `bpftool` on the
    image (a deliberate choice — see `LIMITATIONS.md`), I want a debugging
    guide that gets me from "it failed" to "here's why" using only what's
    already on the image or reachable from a host machine, so a missing
    optional tool doesn't turn into a dead end.
13. As that same operator, I want the debugging guide to also cover the
    normal case — common and advanced `bpftool` usage — for the situations
    where `bpftool` genuinely is available (a bridged/TAP x86_64 host, per
    `LIMITATIONS.md`'s existing guidance), so the guide is useful whether or
    not the tool is present.
14. As a developer bringing this project to a new kernel or board, I want a
    guide for checking, ahead of time, which BPF program types, hooks and
    tracepoints that specific kernel build actually supports, so I'm not
    discovering a missing capability by watching an attach fail.
15. As a reader of `LIMITATIONS.md`, I want each limitation illustrated with
    a small text diagram where one clarifies the point (matching the
    ASCII-diagram convention already used throughout `detections/*/DESIGN.md`),
    so a structural constraint (a missing kernel hook, a byte-order mismatch,
    a fixed window) is as easy to absorb visually as it is to read.
16. As a maintainer, I want every new or moved document to read like the
    rest of this codebase's documentation — plain prose, ASCII diagrams in
    the existing box-drawing style, no unexplained jargon, cross-references
    resolved as relative links — so nothing about this effort feels bolted
    on.
17. As a maintainer, I want the XDP internals, debugging, and
    platform-capability-checking material to live in their own dedicated
    documents under `docs/` rather than folded into `LIMITATIONS.md`
    wholesale, with `LIMITATIONS.md` keeping only a short pointer to each —
    the same "point, don't duplicate" convention `LIMITATIONS.md` already
    uses for material that lives in `README.md`.
18. As a maintainer, I want `TESTS.md` to stay at
    `recipes-https-guard/https-guard/files/tests/TESTS.md` rather than move
    into the new root-level `docs/` folder, because it documents that one
    tree's test setup specifically and this codebase's convention is that
    tree-local docs live beside the code they describe, not in a
    repo-wide docs folder.
19. As a security reviewer, I want none of this effort to change any
    `.cpp`/`.hpp`/`.bpf.c`/`.bpf.h` source file, any `CMakeLists.txt`, or the
    BitBake recipe, so a docs-only change carries docs-only risk.

## Implementation Decisions

- **New folder:** `docs/` at the repository root.
- **Moves:** `DESIGN.md`, `DESIGN.html`, and `LIMITATIONS.md` move from the
  repo root into `docs/`. `README.md` stays at the root. `TESTS.md` stays at
  `recipes-https-guard/https-guard/files/tests/TESTS.md` (tree-local, not
  moved — see user story 18). No other file moves.
- **Cross-reference sweep:** every live (non-`.scratch`) file that links to
  the moved docs gets its relative path updated: the root `README.md` and
  `CLAUDE.md`, `LIMITATIONS.md` itself, and each `programs/CLAUDE.md`,
  `detections/CLAUDE.md`, `actions/CLAUDE.md`, and per-family `DESIGN.md`
  that currently links to the root `DESIGN.md`/`LIMITATIONS.md`. Historical
  records under `.scratch/` are left untouched — they describe the repo
  state at the time they were written and are not live navigation.
- **No BitBake recipe changes.** Confirmed the `.bb` recipe carries no
  references to `DESIGN.md`/`DESIGN.html`/`LIMITATIONS.md`, so the recipe's
  `SRC_URI` is unaffected by this move (these are narrative docs, not
  packaged into the image).
- **Repo-wide accuracy pass:** every `DESIGN.md` and `CLAUDE.md` in the tree
  (root, `programs/`, each hook's `DESIGN.md`, `detections/`, each
  detection family's `DESIGN.md`, `actions/`, each action kind's
  `DESIGN.md`) is checked against the current code and brought current where
  it has drifted. This is a correctness pass, not a rewrite: prose that is
  still accurate is left alone (matching this project's existing "surgical
  changes" norm), and only genuinely stale claims are corrected.
- **New table in the root design doc:** a Detected → Hook → Action reference
  table, one row per detection, naming its Redfish message ID (the same IDs
  already used throughout `detections/*/DESIGN.md` and `README.md`'s
  "Exercising the Detections" section), the hook(s) that can feed it, and
  the action(s) it can trigger (log-only vs. actionable, per the existing
  `Verdict::actionable` distinction). Alongside it, plain inventory lists of
  every event type, every hook, and every action.
- **`DESIGN.html` scope:** light-touch only. Update its existing "Detect →
  Classify → Dispatch" and "Platform-Adaptive Enforcement" sections to
  mention dual-stack/session-binding, and add a compact, visually-styled
  version of the new table. Do not attempt to mirror the new deep-reference
  material (XDP internals, debugging, platform checks) into the HTML
  companion — it stays a curated overview, not a full mirror of `DESIGN.md`.
- **New doc — XDP internals and network data flow** (`docs/XDP_INTERNALS.md`):
  covers the traditional (non-XDP) packet path versus each of XDP's three
  modes (offloaded, native, generic) as request-flow diagrams in this
  codebase's existing box-drawing ASCII style; explains `ndo_bpf` as a
  network-driver-level hook distinct from a uprobe/kprobe/tracepoint syscall
  hook; and gives concrete, reproducible steps for determining (a) that this
  project's QEMU/SLIRP test networking doesn't support XDP and (b) whether an
  arbitrary NIC driver implements `ndo_bpf`. `LIMITATIONS.md` keeps only a
  short pointer to this document where it currently discusses XDP, rather
  than duplicating the content.
- **New doc — debugging without (and with) `bpftool`**
  (`docs/DEBUGGING.md`): covers common and advanced `bpftool` usage for the
  situations where it is available (the bridged/TAP x86_64 host path
  `LIMITATIONS.md` already documents), and, as the more novel material, a
  methodology for diagnosing a failed hook load/attach with no `bpftool` at
  all: separating open/parse, CO-RE/BTF relocation, `BPF_PROG_LOAD`, and
  attach into distinct failure stages; capturing the verifier log via
  `libbpf_set_print()` and a kernel log level; reading `errno` (`EPERM`,
  `EINVAL`, `E2BIG`, `ENOTSUPP`/`EOPNOTSUPP`, `EBUSY`, `ENOENT`/`ENODEV`) for
  what each direction implies; checking kernel support via `uname -r`,
  `/proc/config.gz`, `/sys/kernel/btf/vmlinux`,
  `/proc/sys/net/core/bpf_jit_enable`,
  `/proc/sys/kernel/unprivileged_bpf_disabled`, and `dmesg`; separating load
  from attach and forcing generic-mode XDP explicitly; inspecting live state
  through `/proc/<pid>/fd` and `/proc/<pid>/fdinfo/<fd>` as a substitute for
  `bpftool prog show`; and where to reproduce a failure off-target (an x86
  host for verifier-only rejections, QEMU running the real target kernel for
  anything JIT- or driver-specific) — including this project's own AST2600
  ARM32 JIT gap as the running example of a "looks like a verifier error but
  is actually a missing JIT capability" case. States plainly, citing
  `LIMITATIONS.md`'s existing reasoning, why `bpftool` is not shipped on the
  target image, rather than re-litigating that decision.
- **New doc — checking platform capabilities**
  (`docs/PLATFORM_CHECKS.md`): how to determine, on a given target kernel,
  which BPF program types are supported, which hooks (kprobe, uprobe, XDP,
  LSM, tracepoint) are available, and which tracepoints exist — via kernel
  version, `/sys/kernel/debug/tracing/available_events` (or equivalent),
  `/proc/config.gz`, `bpftool feature probe` where available, and the
  filesystem/command-line checks already established in the debugging doc
  above (reused, not duplicated).
- **`LIMITATIONS.md` diagrams:** every existing bullet gets a small ASCII
  diagram where one clarifies the point, in the same box-drawing style
  already used in `detections/*/DESIGN.md`'s handshake diagrams. Not every
  bullet needs one — a diagram is added only where it earns its space over
  prose alone (matching this project's own stated preference for minimal,
  purposeful additions).
- **Sequencing:** the `docs/` move lands first, as its own unit of work, so
  every other change here edits files in their final location rather than
  being rebased across a subsequent move.

## Testing Decisions

This is a documentation-only effort; there are no unit, integration, or
BPF-level tests to write or run. "Correctness" here means:

- **Every internal link resolves.** After the move, every relative link
  touched by the cross-reference sweep is checked by following it (or by an
  equivalent link-check pass) rather than assumed correct from the edit
  alone.
- **Every command mentioned in the new debugging and platform-checks docs is
  one that has actually been run against this project's real target
  environment (QEMU/AST2600) or genuinely is host-side-only by design** (the
  same distinction `LIMITATIONS.md` already draws for its existing
  `bpftool` guidance) — not transcribed from general BPF knowledge without
  verification against this project's own constraints.
- **Every new or updated claim about the code (the event/hook/action table,
  the repo-wide accuracy pass) is checked directly against the current
  source**, the same way this session verified the two stale ticket
  statuses against `DetectLoop.cpp`, `detections/DESIGN.md`, and
  `detectloop_harness.cpp` before marking them done, rather than trusted
  from an existing doc's prior wording.
- **The full build still succeeds after the move** — `HTTPS_GUARD_BUILD_BPF`
  and `HTTPS_GUARD_BUILD_TESTS` builds don't reference the moved paths in
  any generated artifact, but this should be confirmed rather than assumed,
  since the cross-reference sweep touches `CLAUDE.md` files that sit
  alongside `CMakeLists.txt` files in the same directories.

Prior art: this repository already treats documentation as something to get
right rather than something to skip testing — see `.scratch/detection-first-
architecture/issues/08-documentation-pass.md` and
`.scratch/extend-detection-coverage/issues/07-doc-rewrites.md` for the
existing convention of a dedicated documentation ticket with concrete
acceptance criteria, which this spec's ticket breakdown follows.

## Out of Scope

- Any change to `.cpp`/`.hpp`/`.bpf.c`/`.bpf.h` source, `CMakeLists.txt`, or
  the BitBake recipe (see user story 19).
- Moving or restructuring any tree-local `DESIGN.md`
  (`programs/*/DESIGN.md`, `detections/*/DESIGN.md`, `actions/*/DESIGN.md`)
  or `CLAUDE.md` — only their content is audited for accuracy in place;
  their locations don't change.
- Automating `DESIGN.html` generation from `DESIGN.md`. They remain two
  separately-maintained documents, as they are today; this spec only
  updates `DESIGN.html`'s content by hand to match the agreed light-touch
  scope.
- Publishing or migrating any of this to the project's GitHub remote as
  Issues — per `issue-tracker.md`, that migration is the user's own,
  deliberately manual step.
- Adding a link-checking tool or CI job. Link resolution is verified by hand
  as part of this effort, not automated.
- Any new hardware bring-up, kernel config change, or actually enabling
  native XDP anywhere. The XDP internals doc explains the existing
  constraint; it does not attempt to lift it.

## Further Notes

- This spec supersedes the "docs-restructuring effort tracked separately at
  `.scratch/docs-restructure/`" mentioned in
  `.scratch/dual-stack-peer-attribution/spec.md`'s Further Notes. That
  earlier promise was narrowly scoped to rewriting two specific
  `LIMITATIONS.md` entries about uprobe attribution — that rewrite already
  shipped as part of finishing dual-stack-peer-attribution ticket 04, ahead
  of this spec and independent of it. This spec's scope was set fresh, in
  conversation with the user, and is substantially broader than that
  original promise.
- The two Chinese-language reference write-ups and the English no-`bpftool`
  debugging write-up the user supplied during scoping are the primary
  source material for `docs/XDP_INTERNALS.md` and `docs/DEBUGGING.md`
  respectively — an implementing agent should treat them as authoritative
  starting content to translate/adapt into this codebase's documentation
  style (English prose, the existing box-drawing ASCII convention,
  cross-referenced to this project's own actual detections/hooks rather than
  generic examples), not as content to research independently from scratch.
- A prior code review of the dual-stack-peer-attribution work flagged that
  `LIMITATIONS.md`'s IPv6-attribution bullet doesn't caveat that the
  binding's genuine (non-mapped) IPv6 code path is reviewed-but-not-live-
  verified, unlike a neighboring bullet that does disclose its own
  unverified assumption. The repo-wide accuracy pass (ticket 2) is the
  natural place to fix this specific inconsistency alongside the broader
  audit.

## Comments

Shipped as commit f18812d (`docs: restructure and audit HTTPS-Guard
references`): `docs/` created; `DESIGN.md`, `DESIGN.html` and
`LIMITATIONS.md` moved into it; `README.md` stayed at the root; `TESTS.md`
stayed at `recipes-https-guard/https-guard/files/tests/TESTS.md`; every
per-family `DESIGN.md` was renamed to a family-specific filename
(`TLS_VERSION.md`, `BLOCKLIST.md`, etc.); the Detected → Hook → Action table
landed in `docs/DESIGN.md`'s "Detection Reference" section; `DESIGN.html`
got the light-touch update; `docs/XDP_INTERNALS.md`, `docs/DEBUGGING.md` and
`docs/PLATFORM_CHECKS.md` were added; `LIMITATIONS.md` picked up diagrams.

A later review (this session) re-verified the cross-reference sweep and the
repo-wide accuracy pass against the current source, since both are exactly
the kind of claim this spec's own Testing Decisions ask not to trust from a
prior doc's wording:

- **Every relative link in every tracked Markdown file resolves** — checked
  programmatically, not by re-reading the edits. No broken links found.
- **The repo-wide accuracy pass had gaps, now closed.** Several places still
  described pre-dual-stack/pre-session-binding code: `docs/DESIGN.md`'s
  Event Processing Pipeline and ActionLoop diagrams named a function that no
  longer exists (`classifyAndDispatch`, actually `dispatchVerdict()` called
  from `DetectLoop::process()`), showed the old `if remote_ip_v4 != 0:` gate
  instead of the current family-aware `IpAddress` one, and both that file and
  `docs/DETECTIONS.md` still narrated the sweep timer calling a `sweepRates()`
  that was renamed to `sweepAll()` when `SessionTupleSweeper` was added
  alongside `ConnRateSweeper`. `docs/LIMITATIONS.md` was still missing the
  IPv6-live-verification caveat this spec's own Further Notes flagged as
  outstanding. Several `CLAUDE.md`/`*.md` files elsewhere in the tree also
  still referenced the pre-dual-stack `remote_ip_v4`/`local_ip_v4` fields
  (`EventMeta` now carries `remote_ip`/`local_ip` as `IpAddress`), one
  (`actions/CLAUDE.md`) pointed at the wrong shared doc (`PROGRAM.md` instead
  of `ACTIONS.md` for `ActionLoop`), and two source comments
  (`detections/CMakeLists.txt`, `tests/CMakeLists.txt`) still named the
  deleted `hg_event`/`IDetector` types instead of their `EventMeta`/
  `IDetection` replacements. All of the above were corrected as part of this
  review, not left for a future pass.
- **Not independently re-verified this session:** that
  `HTTPS_GUARD_BUILD_BPF`/`HTTPS_GUARD_BUILD_TESTS` still build clean after
  the move (no BitBake/cross-compile environment available to this review;
  the original commit's own testing claims this was checked at the time) and
  that every command in the new `DEBUGGING.md`/`PLATFORM_CHECKS.md` docs is
  one that was actually run against the real target rather than transcribed
  from general knowledge — that would require re-running them against
  hardware/QEMU, which this pass did not do.
