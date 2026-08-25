/* detect_runner — a standalone runner for the detection pipeline.
 *
 * The counterpart to actions/core/main.cpp (action_runner): a small binary that
 * starts one layer on its own, so the loop can be exercised and observed without
 * a kernel, a BPF object, or root.
 *
 * What it proves, in order:
 *   1. getInstance() returns a loop with its threads already running.
 *   2. A record submitted before configure() is refused and *counted*, not
 *      silently dropped.
 *   3. A record submitted with an empty detection list is reported rather than
 *      discarded -- that is what a hook which forgot to declare its detections
 *      would do.
 *   4. A record with a detection that declines is reported as unclaimed, which
 *      is what a list missing its terminal TrafficObservedDetection looks like.
 *   5. A record with a matching detection is dispatched.
 *   6. stop() joins cleanly and reports what it lost.
 */
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <string_view>
#include <thread>

#include "DetectLoop.hpp"
#include "IDetection.hpp"
#include "core/ActionLoop.hpp"
#include "hg_event_source.h"

namespace {

/** Never claims a record. Stands in for a list with no terminal entry. */
class DecliningDetection final : public https_guard::IDetection {
public:
    std::string_view name() const noexcept override { return "declining"; }

    std::optional<https_guard::Verdict> inspect(const void*, std::size_t,
                                                https_guard::EventMeta&) const override
    {
        return std::nullopt;
    }
};

/** Always claims a record, the way TrafficObservedDetection does. */
class ClaimingDetection final : public https_guard::IDetection {
public:
    std::string_view name() const noexcept override { return "claiming"; }

    std::optional<https_guard::Verdict> inspect(const void*, std::size_t,
                                                https_guard::EventMeta& meta) const override
    {
        meta.process = "detect_runner";
        meta.pid     = 1;
        https_guard::Verdict v;
        v.severity   = "OK";
        v.message_id = "OemSecurityEvent.1.0.HttpsTrafficObserved";
        v.message    = "synthetic record from detect_runner";
        return v;
    }
};

}  // namespace

int main()
{
    using https_guard::ActionLoop;
    using https_guard::DetectLoop;
    using https_guard::IDetection;

    DetectLoop& loop = DetectLoop::getInstance();
    std::cout << "detect_runner: DetectLoop started, configured=" << std::boolalpha
              << loop.configured() << "\n";

    unsigned char rec[16] = {};
    const std::uint32_t src = static_cast<std::uint32_t>(HG_SOURCE_UPROBE);
    std::memcpy(rec, &src, sizeof(src));

    const DecliningDetection declining;
    const ClaimingDetection  claiming;
    const IDetection* one_declining[] = {&declining};
    const IDetection* one_claiming[]  = {&claiming};

    /* (2) before configure(): refused and counted. */
    loop.submit(rec, sizeof(rec), DetectLoop::DetectionList{one_claiming, 1});

    loop.configure(ActionLoop::getInstance(), std::chrono::seconds(300), "/dev/null");
    std::cout << "detect_runner: configured=" << loop.configured() << "\n";

    /* Configuring twice is a programming error; this should report and ignore. */
    loop.configure(ActionLoop::getInstance(), std::chrono::seconds(300), "/dev/null");

    /* (3) empty list. */
    loop.submit(rec, sizeof(rec), {});

    /* (4) a list whose entries all decline. */
    loop.submit(rec, sizeof(rec), DetectLoop::DetectionList{one_declining, 1});

    /* (5) a list that claims it. */
    loop.submit(rec, sizeof(rec), DetectLoop::DetectionList{one_claiming, 1});

    /* And a record too small to carry even a discriminator. */
    unsigned char runt[2] = {};
    loop.submit(runt, sizeof(runt), DetectLoop::DetectionList{one_claiming, 1});

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    loop.stop();
    std::cout << "detect_runner: done\n";
    return 0;
}
