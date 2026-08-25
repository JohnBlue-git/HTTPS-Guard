#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

#include "Verdict.hpp"
#include "event_meta.hpp"

namespace https_guard {

/**
 * One detection: what to parse out of a raw record, and what to conclude.
 *
 * A hook names the detections it can feed and submits that list with every
 * record (see `BpfProgram::ringBufferHandler`). `DetectLoop` loops the list and
 * stops at the first verdict.
 *
 * WHY PARSE AND EVALUATE TOGETHER
 * ------------------------------
 * Because they are the same decision. What a detection needs out of a record is
 * determined entirely by what its rule reads, so splitting them put half of a
 * detection in one directory and half in another — and adding a detection meant
 * editing a shared per-source handler. Now a detection directory holds all of
 * it: the event struct, the parse, the rule, and the `DESIGN.md`.
 *
 * ONE NON-TEMPLATE INTERFACE, TEMPLATED IMPLEMENTATIONS
 * ---------------------------------------------------
 * The list has to be homogeneous, so this interface is not templated. The
 * implementations are, where a detection serves more than one hook: e.g.
 * `TlsVersionDetection<struct uprobe_event>` and
 * `TlsVersionDetection<struct xdp_event>` share one rule and one event struct,
 * differing only in the raw layout they read.
 *
 * WHY inspect() IS NOT A COROUTINE
 * -------------------------------
 * A reasonable thing to reach for, given `IAction::execute_async()` next door
 * returns an `awaitable<void>` and a verdict's actions are run as an awaited
 * group. It is the wrong shape here, and the reason is specific rather than a
 * preference.
 *
 * A suspension point only pays when something else can make progress while you
 * wait on an *external party* -- a socket, a timer, a disk. Nothing on this path
 * waits. `inspect()` is a memcpy, a few string constructions and some integer
 * compares; the two syscalls in the neighbourhood (`readlink("/proc/<pid>/exe")`
 * in cert_access, and the `/proc/<pid>/net/tcp` parse behind peer resolution)
 * are CPU work in kernel context, with no device to wait for. An async read of a
 * procfs file completes immediately-ish, because the kernel generates the content
 * during the read.
 *
 * So making these awaitable would add a coroutine frame per detection per record
 * and buy no concurrency. And running a hook's list with `wait_for_all` would
 * additionally discard first-match-wins: all five detections would evaluate for
 * one ClientHello, and a winner would be picked *after* doing all the work
 * instead of before.
 *
 * WHEN THAT WOULD CHANGE
 * ---------------------
 * If a detection ever needs to consult something genuinely remote or slow -- an
 * IP-reputation lookup, a query to another daemon, a large file -- then this
 * signature should become `awaitable<std::optional<Verdict>>` and a hook's list
 * should be split: keep the cheap ordered short-circuit first, and only group
 * the genuinely-independent slow ones with `wait_for_all`. Paying a network
 * round-trip to discover a TLS 1.0 ClientHello would be a poor trade.
 *
 * See detections/DESIGN.md for the same argument with the numbers, and for the
 * optimisation that *is* available today, which is a different executor rather
 * than a coroutine.
 *
 * LIFETIME
 * --------
 * `submit()` returns immediately and the record is inspected later, on a
 * `DetectLoop` thread. Implementations must therefore be owned by something that
 * outlives the loop — in practice the hook holds them as members — and must be
 * stateless and safe to call concurrently, since the connection-rate sweep runs
 * alongside record processing.
 */
class IDetection {
public:
    virtual ~IDetection() = default;

    /**
     * What this detection is called, for diagnostics.
     *
     * Costs nothing per record: it is a string literal in rodata reached through
     * the vtable, not state carried in the queued record. It is read once per
     * record, on the line that reports which detection claimed it -- so
     * "claimed by cipher_suite" instead of "claimed by detection 2 of 5",
     * which said nothing without the hook's source open beside it.
     *
     * Deliberately NOT a lookup key. A hook's list is walked in order and the
     * first verdict wins, so the order *is* the priority; a name-keyed map has
     * no order, and would need a parallel order vector to recover what the
     * array already gives. Hashing a string per record to select among two to
     * five entries would also be slower than scanning them.
     */
    virtual std::string_view name() const noexcept = 0;

    /**
     * Parses what this detection needs and evaluates its rule.
     *
     * Returns `nullopt` for "this record is not mine", "it does not parse", and
     * "it parses but does not violate" alike — the caller does not distinguish,
     * it just tries the next detection in the list.
     *
     * Fills `meta` with the record's common envelope whenever the record is
     * long enough to have one, so the caller can dispatch, and so a later
     * always-matching entry in the list can report on traffic no rule flagged.
     */
    virtual std::optional<Verdict> inspect(const void* data,
                                           std::size_t size,
                                           EventMeta& meta) const = 0;
};

}  // namespace https_guard
