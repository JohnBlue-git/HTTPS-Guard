# 15 — Stop `hg_event` being a god object every hook has to widen

**What to build:** Let each hook own the data only it produces, so adding a hook stops meaning "edit a struct that every hook and every detector sees". `hg_event` keeps only what is genuinely universal; everything hook-specific lives with that hook.

**Blocked by:** 11 — DetectLoop (it changes what gets queued and who calls `parseEvent`, so doing this first means rewriting the same call sites twice)

**Relationship to 12:** 12 is done and settled the layout this slots into. Its original pairing rationale — that hook-specific event detail and hook-specific detectors should sit together — no longer applies, because 12 ultimately put *every* detector in `detections/` rather than inside hooks. That turns out to help here rather than hurt: detectors never need to see a concrete per-hook event type at all, only the capability interfaces, so the concrete types can live in `programs/<hook>/src/` with nothing in `detections/` depending on them.

**Status:** done

## The problem

`hg_event` currently carries **25 data members**, and roughly ten are meaningless for any given event. It has grown since this ticket was filed — ticket 11 added `peer_resolver` — which is the pattern worth stopping: every hook or feature that lands widens a type in the classification layer that every other hook depends on.

| Group | Fields | Meaningful for |
|---|---|---|
| universal | `timestamp_ns`, `event_type`, `pid`, `tgid`, `process`, `source_ip`, `local_ip_v4`, `remote_ip_v4`, `local_port`, `remote_port`, `peer_resolver` (+ its two memo members) | everything |
| TLS traffic | `tls_version`, `tls_record_type`, `tls_violation_hint`, `payload_snippet` | `ssl_uprobe` + `xdp_tls` |
| direction | `is_inbound` | `ssl_uprobe` only |
| ClientHello | `cipher_suites`, `cipher_suites_offered`, `sni_present`, `sni_malformed`, `sni_hostname` | `xdp_tls` only |
| certificate access | `cert_identity_mismatch`, `cert_shadow_mode`, `cgroup_id`, `real_exe_path` | `lsm_cert_guard` only |

So an LSM certificate-access event carries a cipher-suite list and a TLS version; a uprobe event carries `sni_malformed`. Beyond being untrue, it means every new hook widens a header in the *classification* layer that every other hook depends on — the opposite of the property `IHookModule` exists to provide.

## The constraint that rules out the obvious design

"One event type per hook" does not work on its own. `TlsVersionDetector` and `PayloadAnomalyDetector` are each registered for **both** `HG_SOURCE_UPROBE` and `HG_SOURCE_XDP`. Given per-hook types with nothing in common, those two detectors would have no type to bind to, and duplicating them per hook is exactly the duplication the shared classification layer exists to prevent.

`tls_violation_hint` is a concrete example of why they must stay shared: it exists *because* XDP can compute a violation on the wire that the uprobe cannot, and one detector has to reason about both cases.

## Shape that satisfies both

Small **capability interfaces** in the classification core, implemented by whichever hook can actually provide them. A detector depends on the capability it needs, not on a hook:

```
detections/core/
  hg_event.hpp          universal members only; knows nothing about any hook
  ITlsTrafficInfo.hpp   tlsVersion(), tlsViolationHint(), payloadSnippet()
  IClientHelloInfo.hpp  cipherSuites(), sniHostname(), sniMalformed(), ...
  ICertAccessInfo.hpp   realExePath(), cgroupId(), identityMismatch(), ...

detections/tls_version/     depends on ITlsTrafficInfo only
detections/payload_anomaly/ depends on ITlsTrafficInfo only
detections/cipher_suite/    depends on IClientHelloInfo only
detections/sni/             depends on IClientHelloInfo only
detections/cert_access/     depends on ICertAccessInfo only

programs/ssl_uprobe/src/     event type implements ITlsTrafficInfo
programs/xdp_tls/src/        event type implements ITlsTrafficInfo + IClientHelloInfo
programs/lsm_cert_guard/src/ event type implements ICertAccessInfo
```

Note what this buys given 12's final layout: `detections/` depends only on
its own interfaces, and `programs/` depends on `detections/`. The concrete
per-hook event types are private to their hook — nothing in the
classification tree ever names them, so adding a hook or a field cannot
touch `detections/` at all.

`IDetector::evaluate(const hg_event&)` stays exactly as it is, so `HttpGuardProgram` keeps dispatching generically and adding a hook still requires no change to it. A detector obtains its capability from the event and returns `nullopt` if the event does not provide it — which registration already guarantees it will, so the check is defensive rather than load-bearing.

Adding a hook then touches: its own directory, one line in `main.cpp`, and nothing else. Adding a *field* touches only that hook's directory.

## Trade-offs to weigh, not assume

- **Polymorphism forces a lifetime decision.** `IHookModule::parseEvent` currently returns `std::optional<hg_event>` by value. Capability interfaces need references or pointers, so this likely becomes `std::unique_ptr<hg_event>`. That is a contained change (three hooks plus the orchestrator) but it is a real API change, and it interacts with ticket 11's queue — which is another reason 11 goes first.
- **`std::variant` looks simpler and isn't.** A variant of per-hook detail structs keeps value semantics, but `hg_event.hpp` would then have to include every hook's header to name the alternatives — reintroducing the exact coupling this ticket removes.
- **Cost of the capability lookup.** A `dynamic_cast` per detector per event is cheap relative to the `/proc` work ticket 11 is removing, but it should be measured rather than assumed, and it is worth checking it does not undo 11's gains.
- **Don't over-split.** Three capabilities covering the current five detectors is the right granularity; one interface per field would be worse than the god object.

- [x] `hg_event` contains only fields that are meaningful for every event source, and its header depends on no hook
- [x] Each hook owns the definition of the data only it produces, in its own directory
- [x] `TlsVersionDetector` and `PayloadAnomalyDetector` still serve both uprobe and XDP events without duplication
- [x] `IDetector`'s signature is unchanged and `HttpGuardProgram` still needs no knowledge of any concrete hook or event type
- [x] Adding a hypothetical new hook is demonstrated to touch only its own directory plus one line in `main.cpp` — state this concretely in the ticket comments, since it is the whole point
- [x] Detectors fail safe if handed an event lacking their capability, rather than relying solely on registration being correct
- [x] The existing tests still exercise the real parsers host-side with no libbpf dependency; the capability split must not force test doubles where real code was being tested
- [x] Verified on QEMU that all five detectors still fire on the same inputs they fire on today — this is a pure refactor, so any behavioural change is a regression

## Comments

`hg_event` went from **25 data members to 12**, all genuinely universal
(when, which process, which connection, plus the lazy peer resolver). It now
names no hook and no capability, so adding either cannot touch it.

Three capability interfaces in `detections/core/`:

| Interface | Supplies | Implemented by |
|---|---|---|
| `ITlsTrafficInfo` | `tlsVersion()`, `tlsViolationHint()`, `payloadSnippet()` | `UprobeEvent`, `XdpEvent` |
| `IClientHelloInfo` | cipher suites, SNI | `XdpEvent` |
| `ICertAccessInfo` | real exe path, cgroup, identity/shadow flags | `CertAccessEvent` |

Concrete event types live in `programs/<hook>/src/`, and nothing in
`detections/` names them — detectors recover their capability with
`dynamic_cast` and return `nullopt` when the event can't supply it.

`ITlsTrafficInfo` is what made capabilities necessary rather than one event
type per hook: `TlsVersionDetector` and `PayloadAnomalyDetector` are
registered for both uprobe and XDP, so they need a type to bind to that
isn't a hook. `tlsViolationHint()` is the sharp edge of that — it returns a
hard `false` on `UprobeEvent` (whose BPF side makes no determination, so
`tls_version == 0` really means "not observed") and the BPF-computed flag on
`XdpEvent` (where a parsed `0x0000` is a genuine violation). Conflating
those two zeros was a real bug once; now the difference is expressed in the
type rather than in a shared field plus a comment.

### Two things this forced, both improvements

- **`hg_event` is non-copyable.** Copying one as an `hg_event` would slice
  off the hook's half, so the copy constructor is deleted and `parseEvent()`
  returns `std::unique_ptr<hg_event>`. The compiler now rejects the mistake
  rather than silently producing an event with its capabilities missing.
- **`RedfishEventMessage` stopped storing an event by value.** It held a
  whole `hg_event` copy but only ever read `timestamp_ns` and `pid`; it now
  keeps those two scalars. That was required by the slicing rule and also
  removes a 25-member copy per event.

### Verification

47/47 unit tests under ASan/UBSan, including three new ones asserting the
boundary itself: a `CertAccessEvent` is declined by both TLS rules while
still matching `CertAccessDetector`; a `UprobeEvent` is declined by both
ClientHello rules; an `XdpEvent` supplying both capabilities matches both
families. Clean cross-compile first try.

On QEMU, verified live through the new interfaces:

| Verdict | Path exercised |
|---|---|
| `HttpsPayloadAnomalyDetected` (x2) | uprobe → `ITlsTrafficInfo`, and enforcement still tore the connection down |
| `HttpsWeakCipherSuiteDetected` | XDP → `IClientHelloInfo` |
| `HttpsSniAnomalyDetected` | XDP → `IClientHelloInfo` |
| `HttpsTrafficObserved` | OK fallback |

**Two detectors were not exercised live**, and neither gap is new:
`TlsVersionDetector` needs a client that actually negotiates < TLS 1.2, and
`CertAccessDetector` needs the LSM hook, which cannot attach on ARM32 at all
(ticket 03). Both are covered by unit tests, including the
`tlsViolationHint()` asymmetry above, but "covered by unit tests" is a weaker
claim than the live confirmations and worth reading as such.
