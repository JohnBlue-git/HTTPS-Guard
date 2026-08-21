/* Scheduling tests for the real detections/core/DetectLoop.cpp.
 *
 * Not part of the https_guard_tests binary, and not a reimplementation:
 * DetectLoop.cpp and ConnRateSweeper.cpp are compiled from real source, while
 * their collaborators (ActionLoop, the three actions, libbpf's two map calls)
 * are replaced at LINK time. See README.md in this directory for what each
 * check is for and how to build it.
 */
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>

#include "DetectLoop.hpp"
#include "log/LogAction.hpp"
#include "blocklist/BlocklistAction.hpp"
#include "tcp/BlockTcpAction.hpp"

using namespace https_guard;
using clk = std::chrono::steady_clock;

/* ---- link-time doubles for the collaborators ---------------------------- */

static std::atomic<int> g_pushed{0};

namespace https_guard {

ActionLoop::ActionLoop() noexcept : io_context_(), work_guard_(boost::asio::make_work_guard(io_context_)) {}
ActionLoop::~ActionLoop() noexcept {}
ActionLoop& ActionLoop::getInstance() noexcept { static ActionLoop i; return i; }
void ActionLoop::pushAction(std::unique_ptr<IAction>) noexcept { g_pushed.fetch_add(1); }

LogAction::LogAction(std::string, std::string) {}
boost::asio::awaitable<void> LogAction::execute_async() { co_return; }
BlocklistAddAction::BlocklistAddAction(std::uint32_t ip, std::chrono::seconds ttl, std::string r) noexcept
    : src_ip_v4_(ip), ttl_(ttl), reason_(std::move(r)) {}
boost::asio::awaitable<void> BlocklistAddAction::execute_async() { co_return; }
BlockTcpAction::BlockTcpAction(std::uint32_t a, std::uint32_t b, std::uint16_t c, std::uint16_t d, std::string r) noexcept
    : local_ip_v4_(a), remote_ip_v4_(b), local_port_(c), remote_port_(d), reason_(std::move(r)) {}
boost::asio::awaitable<void> BlockTcpAction::execute_async() { co_return; }

}  // namespace https_guard

/* ConnRateSweeper's only two libbpf calls. Recording the timestamp of each
 * sweep's first call is how sweep cadence is observed. */
static std::mutex              g_sweep_mu;
static std::vector<clk::time_point> g_sweeps;

extern "C" int bpf_map_get_next_key(int, const void* key, void*)
{
    if (key == nullptr) {   /* start of a sweep */
        const std::lock_guard<std::mutex> lk(g_sweep_mu);
        g_sweeps.push_back(clk::now());
    }
    return -1;              /* map empty */
}
extern "C" int bpf_map_lookup_elem(int, const void*, void*) { return -1; }

/* ---- test doubles for the pipeline's own seams -------------------------- */

static constexpr hg_event_source kTestSource = HG_SOURCE_UPROBE;

/* Records arrival order and can be made slow, to build a backlog. */
class SlowHook final : public IHookModule {
public:
    std::atomic<int>          parsed{0};
    std::atomic<int>          us_per_parse{0};
    std::mutex                mu;
    std::vector<std::uint32_t> order;

    bool attach(bpf_object*, std::vector<bpf_link*>&) noexcept override { return true; }
    hg_event_source eventSource() const noexcept override { return kTestSource; }

    std::unique_ptr<hg_event> parseEvent(const void* data, size_t size) const noexcept override
    {
        const auto us = us_per_parse.load();
        if (us > 0) std::this_thread::sleep_for(std::chrono::microseconds(us));

        std::uint32_t seq = 0;
        if (size >= 8) std::memcpy(&seq, static_cast<const unsigned char*>(data) + 4, 4);
        {
            auto* self = const_cast<SlowHook*>(this);
            const std::lock_guard<std::mutex> lk(self->mu);
            self->order.push_back(seq);
        }
        const_cast<SlowHook*>(this)->parsed.fetch_add(1);

        auto evt = std::make_unique<hg_event>();
        evt->pid = seq;
        return evt;
    }
};

/* Throws, to prove one bad event does not take the daemon down. */
class ThrowingDetector final : public IDetector {
public:
    std::optional<Verdict> evaluate(const hg_event&) const override
    { throw std::runtime_error("boom"); }
};

static void submitSeq(DetectLoop& loop, std::uint32_t seq)
{
    unsigned char buf[16] = {};
    const std::uint32_t src = static_cast<std::uint32_t>(kTestSource);
    std::memcpy(buf, &src, 4);
    std::memcpy(buf + 4, &seq, 4);
    loop.submit(buf, sizeof(buf));
}

static int failures = 0;
static void check(bool ok, const char* what)
{
    std::printf("%-58s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) ++failures;
}

int main()
{
    ActionLoop& al = ActionLoop::getInstance();

    /* ---- 1. bounded admission: drop-newest past the cap ---------------- */
    {
        std::vector<std::unique_ptr<IHookModule>> hooks;
        auto hook = std::make_unique<SlowHook>();
        SlowHook* raw = hook.get();
        hooks.push_back(std::move(hook));
        raw->us_per_parse.store(2000);          /* 2ms: makes a backlog easy */

        DetectLoop loop(al, hooks, {}, std::chrono::seconds(60), "/dev/null");

        const int n = 20000;
        for (int i = 0; i < n; ++i) submitSeq(loop, static_cast<std::uint32_t>(i));

        const auto dropped = loop.droppedCount();
        check(dropped > 0, "admission bounded: drops counted past the cap");
        check(dropped >= static_cast<std::uint64_t>(n) - 4096 - 64,
              "admission bounded: cap is ~kMaxQueueDepth, not unbounded");
        std::printf("      submitted=%d dropped=%llu accepted=%llu\n",
                    n, (unsigned long long)dropped,
                    (unsigned long long)(n - dropped));
        loop.stop();
    }

    /* ---- 2. FIFO order across records --------------------------------- */
    {
        std::vector<std::unique_ptr<IHookModule>> hooks;
        auto hook = std::make_unique<SlowHook>();
        SlowHook* raw = hook.get();
        hooks.push_back(std::move(hook));

        DetectLoop loop(al, hooks, {}, std::chrono::seconds(60), "/dev/null");
        for (std::uint32_t i = 0; i < 500; ++i) submitSeq(loop, i);
        for (int spin = 0; spin < 200 && raw->parsed.load() < 500; ++spin)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));

        bool ordered = raw->order.size() == 500;
        for (std::size_t i = 0; ordered && i < raw->order.size(); ++i)
            ordered = raw->order[i] == i;
        check(ordered, "records classified in arrival order (strand)");
        loop.stop();
    }

    /* ---- 3. the sweep is not starved by a record backlog --------------- */
    {
        std::vector<std::unique_ptr<IHookModule>> hooks;
        auto hook = std::make_unique<SlowHook>();
        SlowHook* raw = hook.get();
        hooks.push_back(std::move(hook));
        raw->us_per_parse.store(5000);          /* 5ms/event */

        DetectLoop loop(al, hooks, {}, std::chrono::seconds(60), "/dev/null");
        loop.enableRateSweeps(3 /* any fd >= 0 */,
                              ConnRateSweeper::Thresholds{100, 100, 100});

        /* 3000 x 5ms = ~15s of backlog, against a 2s sweep interval. */
        for (std::uint32_t i = 0; i < 3000; ++i) submitSeq(loop, i);

        const auto t0 = clk::now();
        std::this_thread::sleep_for(std::chrono::seconds(9));

        std::size_t sweeps = 0;
        clk::time_point last{};
        long worst_gap_ms = 0;
        {
            const std::lock_guard<std::mutex> lk(g_sweep_mu);
            sweeps = g_sweeps.size();
            auto prev = t0;
            for (auto& t : g_sweeps) {
                const auto gap = std::chrono::duration_cast<std::chrono::milliseconds>(t - prev).count();
                if (gap > worst_gap_ms) worst_gap_ms = gap;
                prev = t;
            }
            if (!g_sweeps.empty()) last = g_sweeps.back();
        }

        std::printf("      backlog still draining: parsed=%d of 3000\n", raw->parsed.load());
        std::printf("      sweeps in 9s=%zu  worst gap=%ldms (interval 2000ms)\n",
                    sweeps, worst_gap_ms);
        check(raw->parsed.load() < 3000, "the backlog really was still draining");
        check(sweeps >= 4, "sweep kept running while a backlog drained");
        check(worst_gap_ms < 4000, "sweep never delayed past ~2x its interval");
        (void)last;
        loop.stop();
    }

    /* ---- 4. a throwing detector costs one event, not the daemon -------- */
    {
        std::vector<std::unique_ptr<IHookModule>> hooks;
        auto hook = std::make_unique<SlowHook>();
        SlowHook* raw = hook.get();
        hooks.push_back(std::move(hook));

        DetectLoop::DetectorRegistry reg;
        reg[kTestSource].push_back(std::make_unique<ThrowingDetector>());

        DetectLoop loop(al, hooks, std::move(reg), std::chrono::seconds(60), "/dev/null");
        for (std::uint32_t i = 0; i < 20; ++i) submitSeq(loop, i);
        for (int spin = 0; spin < 200 && raw->parsed.load() < 20; ++spin)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        check(raw->parsed.load() == 20, "every event still processed despite throws");
        loop.stop();
    }

    /* ---- 5. oversized/undersized records, and stop() idempotence ------- */
    {
        std::vector<std::unique_ptr<IHookModule>> hooks;
        hooks.push_back(std::make_unique<SlowHook>());
        DetectLoop loop(al, hooks, {}, std::chrono::seconds(60), "/dev/null");

        const auto before = loop.droppedCount();
        std::vector<unsigned char> big(HG_MAX_RAW_EVENT_SIZE + 1, 0);
        loop.submit(big.data(), big.size());
        check(loop.droppedCount() == before + 1, "oversized record rejected and counted");

        loop.submit(nullptr, 8);
        loop.submit(big.data(), 0);
        check(loop.droppedCount() == before + 1, "null/empty submit is a no-op");

        loop.stop();
        loop.stop();
        loop.stop();
        check(true, "stop() is idempotent");
    }

    std::printf("\n%s (%d failure(s))\n", failures == 0 ? "ALL PASS" : "FAILURES", failures);
    return failures == 0 ? 0 : 1;
}
