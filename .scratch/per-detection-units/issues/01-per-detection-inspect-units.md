# 01 — Each detection parses and evaluates itself; hooks declare their list

**What to build:** Replace the per-source handler with a list of **per-detection
units**. Each hook overrides `ringBufferHandler()` and submits its own list:

```cpp
void ringBufferHandler(const void* data, std::size_t size) noexcept override
{
    DetectLoop::getInstance().submit(data, size, detections_);
}
```

`submit()` takes the list, `DetectLoop::process()` loops it, and each unit fills
in what to parse and what to evaluate — all defined under `detections/`.

`detections/sources/` goes away: every event struct and every parse
implementation moves into the `detections/<family>/` directory that owns it.

**Blocked by:** None — the previous spec's 8 tickets are all closed

**Status:** done

## Why this is better than the per-source handler it replaces

The handler introduced by the last spec centralised one source's whole chain,
which meant a detection was still split across two places: its rule in
`detections/<family>/`, its parsing and its event struct in
`detections/sources/`. Adding a detection meant editing a source handler.

After this, a detection directory holds **everything about that detection** —
the event struct, the parse, the rule, and its `DESIGN.md` — and a hook names
the detections it can feed. That is the arrangement the tree has been moving
towards for three specs.

## The interface

One non-template interface so a list is homogeneous, implemented by classes that
*are* templated on the raw struct where a detection serves more than one hook:

```cpp
class IDetection {
public:
    virtual std::optional<Verdict> inspect(const void* data, std::size_t size,
                                           EventMeta& meta) const = 0;
};
```

`nullopt` means "not mine, doesn't parse, or no violation". `meta` is filled by
the parse so `DetectLoop` can dispatch without knowing the event type.

## Four things to get right

**Rule order becomes the hook's list order.** That is the one real cost: "which
rule wins" is a classification decision, and it now lives in `programs/`. It is
accepted deliberately — each list is 2–4 entries, explicit and readable at the
point where the hook says what it can observe — but it must be *stated*, not
left for someone to discover.

**First match must still win.** One record currently produces exactly one
Redfish event. If every unit in the list dispatched, an XDP ClientHello would
produce up to four. Loop, stop at the first verdict.

**The traffic-observed fallback becomes the last element**, not a special case
in `DetectLoop`. It always matches, so first-match-wins handles it with no
branch — and `DetectLoop` needs no knowledge of it at all.

**The pointers must outlive the async hop.** `submit()` returns immediately and
the record is processed later, so the list cannot be a dangling view of a
temporary. The hook owns its units as members; `DetectLoop` copies the pointer
list into the queued record.

## The concepts almost certainly become redundant — check, then act

`event_traits.hpp` exists because two rules served two different event types, so
they needed something other than a concrete type to bind to. Once each detection
has its **own** event struct, every rule has exactly one input type, and an
ordinary parameter type gives the same compile-time guarantee a concept was
giving.

Verify that before deleting anything: if no rule takes more than one struct, the
concepts are ceremony and should go, and the 12 `static_assert`s they support
become assertions about distinct named types, which the compiler already
enforces. If some rule *does* still take two, keep the concept for that one.

## Parsing the same record more than once

Each unit parses what it needs, so an XDP ClientHello is parsed by up to four
units — where the source handler parsed once and fed four rules. That is a real
cost: mostly a couple of extra `std::string` constructions per event.

Judge it against what the pipeline already does per event (ring-buffer copy,
Asio post, JSON serialisation, a file write) rather than in isolation, and put
the shared envelope parse (`hg_event_hdr` → `EventMeta`) in one place so at
least that is not duplicated per unit.

- [x] `submit(data, size, detections)` exists and `DetectLoop::process()` loops the list
- [x] Each hook overrides `ringBufferHandler()` and names its own detections
- [x] `detections/sources/` is gone; every event struct and parse lives in its family's directory
- [x] Every detection directory holds its event struct, its parse, its rule and its `DESIGN.md`
- [x] First match wins — one record still produces exactly one Redfish event
- [x] The traffic-observed fallback is the last list element, not a branch in `DetectLoop`
- [x] The submitted pointer list cannot dangle across the async hop, and a test covers a record processed after `submit()` returned
- [x] The concepts question is settled either way, with the reasoning written down
- [x] The shared `hg_event_hdr` → `EventMeta` parse exists in exactly one place
- [x] `parse` stays linkable without the actions, so the tests still exercise the real parser
- [x] `detections/` still has no libbpf
- [x] 58+ host tests pass; clean cross-compile from `cleansstate`
- [x] QEMU: the five-ClientHello baseline is unchanged — 2 weak-cipher, 2 SNI-anomaly, 2 payload-anomaly — and a live connection is still torn down

## Comments

Done as specified. A hook now declares its detections and submits them with
every record; `DetectLoop::process()` walks the list and the first verdict wins.

### The concepts question, settled

They went. Checked first, as the ticket asked: after each detection got its own
event struct, **no rule takes more than one type** — so an ordinary parameter
type gives exactly the guarantee the concept was giving, and `event_traits.hpp`
was ceremony. The 12 `static_assert`s went with it; "this rule cannot read that
event" is now a type mismatch the compiler reports at the call site.

Concepts *do* survive, in `core/detection_traits.hpp`, doing genuinely different
work: describing what a **raw record** carries (`HasConnectionTuple`,
`HasViolationHint`, `HasClientHello`). That is what lets
`TlsVersionDetection<RawT>` serve both the uprobe and XDP layouts from one
definition instead of two, and lets `CipherSuiteDetection` state in a `requires`
clause that only a ClientHello-parsing hook can feed it — so naming it in the
wrong hook's list does not compile.

### The cost, stated

**Rule priority now lives in `programs/`.** Which detection wins is a
classification decision, and it is expressed as list order in the hook. Accepted
because each list is 2–5 entries readable exactly where the hook says what it
can observe, and because it decides something real: `xdp_tls` puts its two
enforcing detections ahead of its two alert-only ones, so a legacy-TLS
ClientHello that also offers RC4 is reported as the TLS violation. A new test
pins that ordering rather than leaving it to comments.

**A record is parsed more than once** — up to four times for an XDP ClientHello,
where the per-source handler parsed once and fed four rules. The shared envelope
parse is in one place (`event_meta_from.hpp`) so at least that is not repeated,
and each detection parses only its own fields. Against a ring-buffer copy, an
Asio post, JSON serialisation and a file write per event, it does not register.

### Observability changed, and it needed replacing

The per-source handlers each logged a detail line
(`xdp event received: ... cipher_suites=3/3, sni='...'`), and after this change
no single class sees a whole record, so those had nowhere to live. Rather than
lose the trace, `DetectLoop` now logs one line per record from the shared
envelope, naming **which index in the list claimed it**:

```
event source=2 pid=0 (swapper/0) claimed by detection 2 of 5: ...HttpsWeakCipherSuiteDetected
event source=2 pid=0 (swapper/0) claimed by detection 3 of 5: ...HttpsSniAnomalyDetected
event source=2 pid=0 (swapper/0) claimed by detection 4 of 5: ...HttpsTrafficObserved
```

That is strictly better for the thing it now needs to show: list order is a real
decision, and it is visible at runtime instead of only in source. Source-specific
detail (suite names, hostnames) still reaches the journal through verdict
messages.

### One field lost a consumer, deliberately

`is_inbound` — the `SSL_read` vs `SSL_write` distinction from an earlier ticket —
no longer exists in any event struct, because no rule reads it. The `direction`
field is still in the raw record, so a future detection that cares can parse it;
carrying it in an event struct nothing looks at would be exactly the speculative
field this decomposition exists to avoid.

### Verification

- 57 doctest cases, including a new one that pins list-order priority by running
  two detections against one synthetic raw record.
- Harness 10/10 under ASan/UBSan, including a new check that a record submitted
  with a **deliberately temporary** view is still inspected — the dangling case
  the ticket called out.
- `detections/` still compiles standalone with no libbpf.
- Clean cross-compile from `cleansstate`. Two failures on the way, both only the
  cross-compile catches: `detect_runner` still calling the old two-argument
  `submit()`, and `resolveRealExePath` needing `inline` once it moved into a
  header.
- QEMU: `2 of 3 hooks`; `detect_runner` demonstrates each loop property in order
  (early submit counted, double configure refused, **empty list reported**,
  all-declining list reported as unclaimed, matching list dispatched); a live
  connection still torn down; and the baseline unchanged — 2 weak-cipher, 2
  SNI-anomaly, 2 payload-anomaly, 2 traffic-observed.

### A wording bug detect_runner exposed

The shutdown summary said "dropped earlier due to a full queue" for every drop,
which stopped being true once a drop could also mean an oversized record or an
empty detection list. Corrected — the runner made it visible by producing
exactly that case.
