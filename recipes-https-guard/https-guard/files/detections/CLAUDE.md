# detections/ — Classify layer, and the pipeline engine

Two things live here: every classification rule, and the loop that drives the
whole detect → classify → dispatch pipeline.

A **detector** answers exactly one question — "does this already-parsed event
match my rule?" — and does nothing else: no I/O, no BPF or socket access, no
enforcement, and no knowledge of which hook produced the event. Parsing is
`../programs/`; carrying out a response is `../actions/`.

Every rule lives here, one subdirectory per rule family, **including rules
only one hook can currently feed**. Placement deliberately does not depend on
which hook supplies the data: an earlier layout put single-hook rules inside
their hook, which meant reasoning about hypothetical future hooks every time
a rule was added. Keeping them together also keeps this tree free of libbpf,
so a rule cannot acquire a kernel dependency by sitting next to kernel code.

## Layout

### `core/` — shared vocabulary and the engine

- `IDetector.hpp` — `virtual std::optional<Verdict> evaluate(const hg_event&) const = 0`. Takes the event by `const&` and never mutates it; a detector's entire output is the `Verdict` it returns, or `nullopt`.
- `hg_event.hpp` — what *every* event has: timestamp, pid/tgid, process, and the connection named by role (`local_*` / `remote_*`, never `src`/`dst` — see the header for the bug that naming caused). No classification fields; those live only in `Verdict`. No hook-specific fields either; those live behind capabilities below.
- `Verdict.hpp` — `{severity, message_id, message, actionable}`. What a detector decided, never what was observed.
- `ITlsTrafficInfo.hpp`, `IClientHelloInfo.hpp`, `ICertAccessInfo.hpp`, `IConnectionRateInfo.hpp`, `ISlowlorisInfo.hpp`, `IRenegotiationInfo.hpp` — **capability interfaces**. A detector depends on the capability it needs; the concrete per-hook event types (in `../programs/<hook>/src/`, plus the synthesised ones beside their rules here) implement whichever they can supply. Nothing here names a concrete event type, so adding a hook or a field cannot touch this directory.
- `IPeerResolver.hpp` — lets a hook resolve the connection tuple *on demand*. Exists because that resolution is the most expensive thing in the pipeline for uprobe events and almost nothing needs it.
- `IHookModule.hpp` — the interface every hook implements. Lives here, not in `programs/`, so `DetectLoop` can call hooks without the dependency graph forming a cycle. Forward-declares `bpf_object`/`bpf_link` rather than including libbpf, deliberately.
- `hg_event_source.h` — the shared discriminator, compiled by both the BPF side (as C) and C++. Keep it C-compatible.
- `DetectLoop.{hpp,cpp}` — the worker thread that owns parse → classify → dispatch. See below.

### Rules

| Directory | Rule | Fed by | Actionable? |
|---|---|---|---|
| `tls_version/` | TLS below 1.2 (+ the `TlsVersion` name helper it alone uses) | uprobe **and** XDP | yes |
| `payload_anomaly/` | SQLi / path-traversal / attack-signature substrings, case-insensitive | uprobe **and** XDP | yes |
| `cipher_suite/` | weak offered suites — NULL, EXPORT, RC4, 3DES, anonymous KEX (+ the suite table) | XDP | **no** — alert only |
| `sni/` | malformed SNI always; hostname mismatch only when `HTTPS_GUARD_EXPECTED_SNI` is set | XDP | **no** — alert only |
| `cert_access/` | an unrecognised process opened the HTTPS key | LSM | **no** |
| `conn_rate/` | connection attempts per source per window (+ `ConnRateSweeper`) | synthesised | yes |
| `slowloris/` | connections held open per source | synthesised | yes |
| `renegotiation/` | TLS handshake records per source per window | synthesised | yes |

## Why some rules enforce and others only alert

This is the distinction to understand before adding a rule, because getting
it wrong has already caused an outage during testing.

The blocklist applies to a source address on **every port**, not just 443. So
an actionable verdict against a false positive removes all access to the BMC
for the blocklist TTL.

- `cipher_suite` and `sni` fire on a handshake bmcweb refuses anyway. The offer itself does no damage, so alerting is proportionate. Making them actionable locked an operator out of SSH during testing — that incident is why they are alert-only.
- `conn_rate`, `slowloris` and `renegotiation` describe *ongoing harm*: slots being occupied, or asymmetric load being generated. An alert that does not stop it is close to useless, so these enforce — which makes their thresholds safety-critical rather than tuning details, and is why all three are configurable with measured defaults.
- `cert_access` is not actionable because there is no connection to act on, and any in-kernel enforcement already happened (or didn't) before the detector ran.

## Stateful rules without stateful detectors

Three rules need to remember things across events — rates, counts, standing
levels — and **no detector holds any state**. That is deliberate, and it is
the answer to a design question that came up explicitly when the Slowloris
and renegotiation rules were added: should `IDetector` grow a stateful
variant, or should a stateful sibling interface exist alongside it?

Neither. The purity above is what makes every rule testable with a
hand-built event and safe to call from anywhere, and weakening it for three
rules would weaken it for all eight. Instead:

```
BPF map (per-source counters)  ->  ConnRateSweeper  ->  synthesised event  ->  pure detector
      state lives here            aggregates on a timer      carries the aggregate
```

`ConnRateDetector`, `SlowlorisDetector` and `RenegotiationDetector` each read
a single number off the event they are handed. The counting lives in an
`LRU_HASH` keyed on source address (LRU because a plain hash keyed on source
*is* a DoS vector once a spoofed-source flood fills it), and
`conn_rate/ConnRateSweeper` reads it on a timer and manufactures one event
per rule per offending source.

Two consequences worth knowing:

- **Rates reset with the window; levels do not.** Slowloris tracks
  connections *held open*, so its counter must survive the window roll — an
  attacker who opens connections and then goes quiet would otherwise look
  idle. It is floored at zero, because closes can legitimately outnumber
  observed SYNs.
- **All three share one `hg_event_source`.** First-match-wins in the registry
  is safe because each synthesised event carries only its own capability, so
  the other two detectors decline. A test pins that they do not poach each
  other's events.

## DetectLoop, and why classification is not inline

`DetectLoop` runs parse → classify → dispatch off the poll thread, on a
Boost.Asio `io_context` — the same scaffolding `ActionLoop` uses. The
ring-buffer callback in `../programs/core/HttpGuardProgram.cpp` only copies
the raw record and posts it.

That matters for detection coverage, not just latency: a callback that runs
long lets the ring buffer fill, and a full ring buffer **drops events** — a
missed detection nothing reports. The boundary is drawn at the *raw record*
rather than after parsing, because measured, `evaluate()` is the cheapest
thing in the path while parsing walks `/proc` per event.

Three things about its shape are deliberate, and each is there because the
obvious version was wrong:

- **`post()`, not `co_spawn()`.** `ActionLoop` spawns coroutines because
  `IAction`'s entry point is one. Nothing on the classify path awaits
  anything, so a coroutine frame per event would buy nothing.
- **Admission is bounded explicitly.** `post()` is an unbounded queue, and
  on a ~1GB BMC an OOM is a far worse outcome than a dropped event — the
  daemon dying takes *all* detection with it. So depth is capped by an
  in-flight counter, and the policy is drop-the-newest-and-count, which
  leaves a coherent prefix of history rather than a hole in the middle.
- **Two threads, and the sweep timer is off the record strand.** Records go
  through a strand, so they stay serialized and in arrival order. The sweep
  does not, because a single-threaded loop starves it by FIFO fairness
  alone: an expiring timer queues *behind* every record already posted.
  Measured with a deliberate backlog, one thread produced **zero** sweeps in
  nine seconds; two produced one every two seconds as intended. That is the
  same failure ticket 05 shipped once, in a subtler form.

The safety of running the sweep concurrently with a record rests on
classification having no shared mutable state — which is exactly the
statelessness described above. A detector that quietly grew a member would
be a **data race** here, not merely a style breach.

The loop also carries a per-item `try/catch`, mirroring `ActionLoop`: a throw
costs that one event, not the daemon. Everything below it allocates, and the
handlers are `noexcept`, so without that boundary a `bad_alloc` would be
`std::terminate`.

## The registry

`DetectLoop::DetectorRegistry` (aliased as `HttpGuardProgram::DetectorRegistry`,
built in `programs/core/main.cpp`) maps each `hg_event_source` to an *ordered*
list of detectors — first match wins. No match falls back to an inline
"OK, traffic observed" verdict, which is not itself a detector because there
is nothing to detect in that case.

## Why `tlsViolationHint()` exists

`ITlsTrafficInfo::tlsViolationHint()` is the one capability method that exists
purely to prevent a specific bug. `xdp_tls`'s BPF side computes a line-rate
`is_violation` from the wire, and that is a *stronger* signal than
`TlsVersionDetector` can derive from a version number alone: a
genuinely-parsed `legacy_version` of `0x0000` is a real violation on the wire,
whereas `tlsVersion() == 0` from the uprobe only means "never observed".
`UprobeEvent` therefore returns a hard `false`, and `XdpEvent` returns the
BPF-computed flag.

Collapsing those two zeros shipped as a real bug once, caught by review
rather than by the implementer. If you write a rule spanning hooks with
different BPF-side classification power, check whether you need the same
treatment before assuming one number means the same thing everywhere.

## Testing

`../tests/test_detectors.cpp` covers all eight rules: a clearly-violating
input, a clearly-clean input, and each rule's real boundaries — the exact TLS
threshold, the `tlsViolationHint()` override, case-insensitivity, empty
input, `N` triggers while `N-1` does not for each counting rule, and
zero-threshold-means-disabled (the most consequential boundary in the
counting rules, since treating 0 as a threshold everything exceeds would
blocklist every source that ever connects).

There are also tests for the capability boundary itself — that an event
lacking a capability is declined rather than misread — and for the fact that
the three per-source rules do not poach each other's events.

This is the one seam in the project explicitly designed to be testable
without a kernel, root or QEMU. A new rule should get the same treatment
before it is considered done.
