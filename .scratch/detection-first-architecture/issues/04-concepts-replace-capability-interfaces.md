# 04 — Rules bind to concepts, not capability interfaces

**What to build:** Fold the six `I*Info` capability interfaces into the event
structs as plain members, and let the rules that span hooks bind through a
C++20 concept instead of a virtual interface.

**Blocked by:** 03 — the structs have to exist first

**Status:** done

## Why concepts specifically

The capability interfaces exist for exactly one reason: `TlsVersionDetector` and
`PayloadAnomalyDetector` are each registered for **both** the uprobe and XDP
sources, so they need something to bind to that isn't one hook's type. A
concept solves that without RTTI, and turns "this event cannot supply what the
rule reads" from a runtime `dynamic_cast` returning null into a compile error.

## The trap to preserve

`ITlsTrafficInfo::tlsViolationHint()` is not a convenience. A genuinely parsed
wire `legacy_version` of `0x0000` **is** a violation, while `tls_version == 0`
from a uprobe only means "never observed". Collapsing those two zeros shipped
as a real bug, caught in review rather than by the implementer. Whatever the
concept looks like, both event types must still be able to answer that question
differently, and the reason must stay written down next to it.

- [x] The six `I*Info` headers are gone, their fields living on the event structs
- [x] `TlsVersionDetector` and `PayloadAnomalyDetector` still serve both uprobe and XDP, through one definition rather than two
- [x] A rule instantiated with an event lacking a field it reads fails to **compile**, and a test documents that (e.g. a `static_assert` that the concept is not satisfied)
- [x] The `tlsViolationHint()` distinction survives, with its rationale
- [x] No `dynamic_cast` remains in `detections/`
- [x] 60/60 host tests pass, plus the new compile-time checks

## Comments

The six `I*Info` headers are gone; their fields live on the event structs and
the rules bind to C++20 concepts in `detections/core/event_traits.hpp`.

The payoff is exactly what the ticket asked for, and it showed up immediately:
converting the tests, **four test cases stopped compiling**. Those were the ones
asserting that a rule *declines* an event lacking the capability it reads. They
are now `static_assert`s — 12 of them — because the assertion is that the code
would not build, and only the compiler can state that. A mismatch can no longer
reach a running daemon at all, and "declined" no longer looks identical in the
log to "evaluated and found clean".

`tlsViolationHint()` survives as the `violation_hint` field, with its reasoning
moved next to the concept that requires it: a genuinely-parsed wire
`legacy_version` of 0x0000 **is** a violation, while `tls_version == 0` from a
uprobe only means "never observed". `UprobeEvent` hard-codes `false`; `XdpEvent`
carries the BPF-computed flag.

Every rule's emitted message text was checked literal-by-literal against the
previous revision and is byte-identical, including the em dash in the
weak-cipher message. The only string that changed was a doc comment.
