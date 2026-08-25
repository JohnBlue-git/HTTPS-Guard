#include <iostream>
#include <memory>
#include <utility>
#include <vector>

#include "dispatch.hpp"
#include "core/ActionLoop.hpp"
#include "log/LogAction.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"
#include "redfish_event_message.hpp"

namespace https_guard {

Verdict trafficObservedVerdict(const EventMeta& meta, const std::string& tls_desc)
{
    Verdict verdict;
    verdict.severity   = "OK";
    verdict.message_id = "OemSecurityEvent.1.0.HttpsTrafficObserved";
    verdict.message    = "HTTPS traffic observed from process '" + meta.process +
                         "' (PID " + std::to_string(meta.pid) +
                         "), TLS version: " + tls_desc;
    return verdict;
}

void dispatchVerdict(const EventMeta& meta,
                     const Verdict& verdict,
                     const DispatchContext& ctx)
{
    if (ctx.action_loop == nullptr) {
        std::cerr << "https_guard: BUG: dispatchVerdict with no ActionLoop\n";
        return;
    }

    /* Collect this verdict's whole response, then hand it over as one group.
     *
     * Note the asymmetry with the detection path directly above this call:
     * classification is synchronous and this is not. That is deliberate --
     * actions wait on external parties (an epoll-driven netlink round-trip, a
     * file write that can queue behind another writer) and detections do not.
     * See IDetection.hpp for why inspect() is not a coroutine, and
     * detections/DESIGN.md for what would have to be true to change that.
     *
     * These are independent I/O -- a netlink syscall, a BPF map update, a file
     * write -- so they overlap at their suspension points instead of running
     * strictly one after another, and ActionLoop gets a single completion point
     * for the verdict rather than three unrelated detached coroutines. That is
     * what lets it say "two of three countermeasures completed" instead of each
     * action reporting into the void; a silently failing countermeasure is this
     * project's most-repeated bug. */
    std::vector<std::unique_ptr<IAction>> response;
    response.reserve(3);

    if (verdict.actionable) {
        /* Only now is the connection tuple worth resolving -- this is the first
         * point that actually needs it, and most events never get here. For XDP
         * the addresses came from the packet and this is already satisfied.
         *
         * Then gate on whether an ADDRESS IS PRESENT, not on whether resolution
         * ran. Conflating those two silently disabled enforcement for every
         * event that already knows its own address: XDP reads it from the packet
         * headers and the rate sweeper sets it directly, so neither carries a
         * resolver, so ensurePeerResolved() returned false and the whole
         * actionable branch was skipped. It stayed hidden because the only
         * enforcement path exercised live was a uprobe payload anomaly, which
         * does have a resolver. */
        /* The most expensive step in the whole pipeline, and it runs right here
         * on a DetectLoop thread: a /proc/<pid>/fd scan plus a
         * /proc/<pid>/net/tcp parse, measured around 505 lines per event on a
         * busy host. It is already behind `actionable`, so the large majority of
         * events never pay it -- which is why it is a resolver on EventMeta
         * rather than something parsing fills in eagerly.
         *
         * Moving it to its own executor would free a classification thread, and
         * that is the real optimisation available on this path (see
         * detections/DESIGN.md -- it is a different executor, not a coroutine).
         * It is NOT obviously a win: it adds a hop before enforcement, and
         * SOCK_DESTROY needs the connection to still exist. The synchronous call
         * here maximises the chance the socket is still there to destroy. */
        meta.ensurePeerResolved();
        if (meta.remote_ip_v4 != 0) {
            /* Tearing down a connection only makes sense when we know which
             * connection. A rate violation is attributed to an address, not a
             * socket -- no local endpoint, no ports -- so asking netlink to
             * destroy a zero tuple produced a guaranteed -ENOENT and a
             * misleading "SOCK_DESTROY failed" line. The blocklist below is the
             * meaningful response for that case. */
            const bool have_full_tuple = meta.local_ip_v4 != 0 &&
                                          meta.local_port != 0 &&
                                          meta.remote_port != 0;
            if (have_full_tuple) {
                response.push_back(std::make_unique<BlockTcpAction>(
                    meta.local_ip_v4, meta.remote_ip_v4,
                    meta.local_port, meta.remote_port, verdict.message));
            }

            response.push_back(std::make_unique<BlocklistAddAction>(
                meta.remote_ip_v4,   /* block the peer, never our own address */
                ctx.blocklist_ttl, verdict.message));
        } else {
            std::cerr << "https_guard: PID " << meta.pid << " (" << meta.process
                      << ") — no connection could be attributed, declining to enforce\n";
        }
    }

    /* Always, regardless of severity. Last in the group so the enforcement
     * actions are launched first -- with wait_for_all the order does not change
     * the outcome, but it does mean the countermeasure is in flight before the
     * log write competes for the same thread. */
    RedfishEventMessage event_msg(meta, verdict.message_id, verdict.message, verdict.severity);
    response.push_back(std::make_unique<LogAction>(event_msg.format(), ctx.output_path));

    std::cerr << "https_guard: dispatching " << response.size()
              << " action(s) for severity=" << verdict.severity << "\n";
    ctx.action_loop->pushActions(std::move(response));
}

}  // namespace https_guard
