# 08 — Documentation pass for the detection-first layout

**What to build:** Bring every remaining document in line with the architecture
after 01–07.

**Blocked by:** 01, 02, 03, 04, 05, 06, 07

**Status:** done

## Known to be wrong once the above land

- `programs/CLAUDE.md` — describes `core/` as owning the BPF lifecycle, and the per-hook `src/` as holding event types.
- `detections/CLAUDE.md` — the capability-interface section, the registry section, the `tlsViolationHint()` section and the `hg_event` bullet all describe mechanisms that will no longer exist.
- `DESIGN.md` — the `IHookModule`/`IDetector` sections, the pipeline diagram, the source tree.
- `DESIGN.html` — §3's event table, §4's entire class-relationship section including the SVG, the capability matrix and the ownership table.
- `README.md` — the architecture diagram lists detectors under a `DetectLoop worker` box.
- Root `CLAUDE.md` — names `IHookModule`/`IDetector` as "the two seams meant to grow".

- [x] Each of the above is corrected, not patched around
- [x] `DESIGN.html`'s class diagram redrawn — it is hand-maintained with no generator and has fallen behind twice before, so verify box text fits and tags balance rather than eyeballing
- [x] A grep for the removed names (`hg_event`, `IHookModule`, `ITlsTrafficInfo`, `DetectorRegistry`, `dynamic_cast`) returns nothing outside `.scratch/`
- [x] Every path named in `DESIGN.md`'s source tree exists
- [x] `LIMITATIONS.md` still accurate — several entries name types that move

## Comments

Everything the ticket listed was wrong, and all of it is corrected rather than
patched around.

- **`detections/CLAUDE.md`** — rewritten. Most of it described mechanisms that no longer exist: the capability interfaces, the detector registry, `tlsViolationHint()` as a virtual method, `hg_event` as a base class.
- **`programs/CLAUDE.md`** — `core/` now described as owning the object rather than being a `BpfProgram`; the per-hook `src/` no longer claims to hold event types or parsing; the "adding a hook" checklist rewritten.
- **`DESIGN.md`** — the `IHookModule`/`IDetector` sections replaced with `BpfProgram`, concepts, composed event types and handler dispatch; the pipeline diagram redrawn; the source tree regenerated from the filesystem again.
- **`DESIGN.html` § 4** — the whole class-relationship section rewritten, SVG included. The old "three interfaces" framing was simply false once rules stopped being polymorphic. The capability matrix became a *concepts satisfied* matrix, and the prose now tells the three-stage story honestly: one god-object, then a base plus six capability interfaces, then composition plus concepts.
- **`README.md`** — architecture diagram and the component-roles table.
- **Root `CLAUDE.md`** — the "two seams" bullet rewritten, plus a new one stating there is no RTTI on the classification path.
- **Per-hook `CLAUDE.md` × 3** — each claimed its hook "implements `IHookModule`" and, for two of them, that parsing lived in `src/`.

### Verified rather than asserted

- A grep for every removed name (`hg_event`, `IHookModule`, `IDetector`, all six `I*Info`, `DetectorRegistry`, `parse_uprobe_event`, `*_hg_event`, `cert_identity_mismatch`) returns nothing outside `.scratch/`, where the historical ticket records correctly still use them.
- Every path named in `DESIGN.md`'s source tree exists — checked with a brace-expanding validator, after the first attempt produced false positives from a naive expander and the wrong working directory.
- `DESIGN.html` tags balance; all SVG text fits its box (estimated widths against the geometry, since a hand-written 240KB SVG cannot be eyeballed).
- 58 doctest cases + 12 static_asserts pass; clean cross-compile from `cleansstate`.

No source changed in this pass — documentation and `SRC_URI` only.
