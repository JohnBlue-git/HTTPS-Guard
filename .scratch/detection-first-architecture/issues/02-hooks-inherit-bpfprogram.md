# 02 — Hooks inherit BpfProgram; HttpGuardProgram composes them

**What to build:** Each hook (`SslUprobeProgram`, `XdpTlsProgram`,
`LsmCertGuardProgram`) becomes a `BpfProgram`. `HttpGuardProgram` stops
inheriting it and instead owns and manages the hook objects. The ring-buffer
callback gets a default body in `BpfProgram` that does nothing but
`DetectLoop::getInstance().submit(data, size)` — overridable, but not expected
to be overridden.

**Blocked by:** 01 — the default handler needs the singleton to submit to

**Status:** done

## Why the current shape reads strangely

`HttpGuardProgram final : public BpfProgram` means the orchestrator inherits a
BPF object lifecycle, and supplies `attachProgram()` and
`getRingBufferHandler()` as overrides — so the callback for records produced by
*hooks* lives on the class that is not a hook. Now that the handler body is one
line, the indirection buys nothing.

## The constraint that must not be broken

`BpfProgram` currently owns both a `bpf_object` and a `ring_buffer`. Three hooks
each inheriting that unchanged gives three objects, three ring buffers, and
three **separate blocklist maps** — and `BlocklistAddAction` writes the map the
XDP program reads, so enforcement would silently stop working. There is one
object, one ring buffer and one blocklist map on purpose.

So the split is: `BpfProgram` keeps *being a hook* (attach my programs into an
already-loaded object; here is my ring-buffer handler), and `HttpGuardProgram`
keeps *owning the object* (open, load, one ring buffer, the poll loop) and hands
the object to each hook to attach into.

- [x] `HttpGuardProgram` does not inherit `BpfProgram`; it holds them
- [x] All three hooks inherit `BpfProgram`
- [x] `BpfProgram::ringBufferHandler()` has a default body that only submits, and is virtual so a hook *can* override it
- [x] Still exactly one `bpf_object`, one ring buffer and one blocklist map — verified by the blocklist actually dropping traffic on QEMU after the change, not by reading the code
- [x] `IHookModule`'s role is reconsidered rather than left half-overlapping `BpfProgram`: if a hook is now a `BpfProgram`, having it also implement a separate hook interface needs a reason, and if there isn't one, one of them goes
- [x] Hook attach failure is still non-fatal per hook, and the `N of M hook(s)` count still reflects reality (LSM still expected to fail on ARM32)
- [x] Clean cross-compile; QEMU shows all three hooks attempted, uprobe enforcement working, and XDP detection working

## Comments

The inheritance now runs the right way: a hook **is** a `BpfProgram`;
`HttpGuardProgram` **has** several. `BpfProgram` keeps `attach()`,
`eventSource()`, `parseEvent()` and a virtual `ringBufferHandler()` whose entire
default body is `DetectLoop::getInstance().submit(data, size)`.
`HttpGuardProgram` took over the object lifecycle it used to inherit — open,
load, the single ring buffer, the poll loop, link teardown.

### `IHookModule` is gone

The ticket asked for a reason to keep it, and there wasn't one: with
`BpfProgram` carrying `attach`/`eventSource`/`parseEvent`, the two interfaces
were the same interface. Its only remaining job was letting `DetectLoop` call
hooks without naming a libbpf type — and that is now solved better, by
`DetectLoop::ParseFn`: the composition root hands parsing over as a plain
callable, so the classification tree never names a hook type at all and stays
buildable, and unit-testable, without a kernel.

That also dissolved the ownership tangle ticket 01 left behind, where the
singleton held the hook vector purely so it could parse. `HttpGuardProgram`
owns the hooks now, as it should.

### Where the libbpf trampoline ended up, and why not on BpfProgram

`ring_buffer__new()` takes **one** callback and **one** context for the whole
buffer, and there is one shared buffer — so a per-hook static could never be
the thing libbpf calls. The trampoline therefore lives with the buffer's owner:
`HttpGuardProgram::ringBufferCallback()` reads the event source at offset 0,
finds the owning hook, and calls *that hook's* `ringBufferHandler()`. The
override point the ticket asked for is real; only the libbpf-shaped half of it
could not be per-hook. Said so in both headers rather than leaving it to be
rediscovered.

An unowned event source is now reported on the poll thread, rate-limited
1-then-every-1000, because a mislabelled producer would otherwise flood the
journal at line rate — which is its own denial of service.

### The constraint, verified rather than reasoned about

One object, one ring buffer, one blocklist map. The proof that it survived is
not that the code reads correctly: a crafted legacy-TLS ClientHello sent from
the host produced

```
xdp event received: tls_version=769, is_violation=1
BlocklistAddAction: blocklisted 10.0.2.2 for 300s
BlockTcpAction: destroyed TCP connection 10.0.2.15:443 -> 10.0.2.2:34988
```

and **SSH from that host died immediately**, recovering after 292s of the 300s
TTL. SSH dying is the interesting part: it means a userspace map write reached
the XDP program's own `blocklist_check()`, which is only possible if both still
share one map. Three objects would have looked identical in the log and dropped
nothing.

### Verification

- Harness 9/9 under ASan/UBSan, now driving the real `ParseFn` seam rather than
  a test-only interface.
- Clean cross-compile from `cleansstate`. One failure on the way, worth noting
  because only the cross-compile catches it: `main.cpp` referenced
  `HttpGuardProgram::DetectorRegistry`, an alias that went away with the old
  header.
- QEMU: `2 of 3 hook(s)`, uprobe enforcement tears down a live connection, and
  the five-ClientHello baseline is unchanged — 2 weak-cipher, 2 SNI-anomaly,
  2 payload-anomaly, traffic observed.
