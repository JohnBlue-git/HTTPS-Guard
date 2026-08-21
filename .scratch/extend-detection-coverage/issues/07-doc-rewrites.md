# 07 — Documentation rewrite for the extended detection coverage

**What to build:** Once the five detection-capability tickets have landed, bring every doc back in line with what actually exists — the same kind of pass done for the `programs`/`detectors`/`actions` split, now covering the new hook(s) and detectors this spec added.

**Blocked by:** 02 — SSL_read mirror; 03 — BPF-LSM certificate-access guard; 04 — Cipher-suite and SNI detection; 05 — Connection-rate detection; 06 — Slowloris and renegotiation-storm detection

**Status:** done

- [x] `DESIGN.md` describes every hook and detector that now exists, not just `ssl_uprobe`/`xdp_tls` and the two original detectors
- [x] `programs/lsm_cert_guard/DESIGN.md` and `CLAUDE.md` exist, written to the same depth and shape as `programs/ssl_uprobe/DESIGN.md` (why detect this, how it works with diagrams, what's hooked, known limitations)
- [x] `programs/xdp_tls/DESIGN.md` is updated to cover cipher-suite/SNI parsing and connection-rate tracking, since both extend that hook rather than introducing a new one
- [x] Whatever new detector directories exist under `detectors/` (cert-access, cipher-suite, SNI, connection-rate, Slowloris, renegotiation-storm, or however the implementers of tickets 03-06 actually structured them) each get the same "why/how/limitations" treatment `detectors/CLAUDE.md` already gives the first two
- [x] `DESIGN.html` is regenerated to match — it currently predates even the `programs`/`detectors`/`actions` split, not just this spec's additions
- [x] `README.md`'s component-roles table and architecture diagram reflect the final hook/detector list
- [x] The stateful-detector architecture decision from ticket 06 is documented somewhere durable (`detectors/CLAUDE.md` or a dedicated note), not left implicit in that ticket's own comments
- [x] A pass confirms no doc still describes the system as having only two hooks or two detectors

## Comments

Documentation-only change; no source file touched, 59/59 tests still pass.

### What was actually stale

More than the ticket anticipated, because two of the criteria had partly been
met in passing by earlier tickets while others had rotted further:

- `detections/CLAUDE.md` had accumulated real damage from scripted edits: an
  orphaned paragraph spliced *inside* the `core/` bullet list, a **duplicated
  `cert_access/` entry** with two different descriptions, a reference to
  `hg_event.tls_violation_hint` (a field that moved behind
  `ITlsTrafficInfo::tlsViolationHint()` in ticket 15), and "covers both
  existing detectors" when there are eight. Rewritten rather than patched.
- `DESIGN.md` still showed classification happening inline in the
  ring-buffer callback, listed two detectors, and described `parseEvent()`
  returning `optional<hg_event>`.
- `programs/xdp_tls/DESIGN.md` claimed **"No rate-based detection"** — a
  section describing as future work something that hook now implements.
- `DESIGN.html` predated the `programs`/`detections` split entirely: it named
  `pattern_detector`, `https_guard_program.cpp`, and a `https_guard/` +
  `ebpf/` layout that no longer exists.
- `programs/ssl_uprobe/DESIGN.md` described the LSM guard as "planned" inside
  an ASCII diagram.

### Verification, rather than assertion

Rather than eyeball it, the final pass checks the docs against the tree:
every hook directory that exists is named in all four top-level docs, every
`*Detector` that exists is named in `DESIGN.md` and `README.md`, and every
`detections/<rule>/` directory has an entry in `detections/CLAUDE.md`. A grep
for the specific stale phrasings (`two hooks`, `two detectors`,
`pattern_detector`, `planned BPF-LSM`, `https_guard_program`) returns nothing.

`DESIGN.html` names message IDs rather than C++ class names, which is
deliberate for a reader-facing document, so it is exempt from the
class-name check.

### The stateful-detector decision now has a durable home

Ticket 06 resolved it in its own comments; it now lives in
`detections/CLAUDE.md` under "Stateful rules without stateful detectors",
with the diagram of where state actually lives and the two consequences that
follow (rates reset with the window, levels do not; all three per-source
rules share one event source and rely on each synthesised event carrying only
its own capability).

### One recommendation not acted on

`DESIGN.html` is hand-maintained with no generator, and it has now fallen
behind twice — it missed the `programs`/`detections` split entirely and then
this spec's five new rules. It has been brought current, but a hand-written
HTML mirror of `DESIGN.md` is a standing drift trap. Worth deciding whether
to keep it as a curated overview or retire it in favour of the markdown;
that is a call for the maintainer rather than something to do unilaterally to
a 40KB document somebody wrote deliberately.
