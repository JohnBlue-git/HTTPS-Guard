
#include <iostream>
#include <utility>

#include "Blocklist.hpp"
#include "BlocklistAction.hpp"

namespace https_guard {

BlocklistAddAction::BlocklistAddAction(std::uint32_t src_ip_v4,
                                       std::chrono::seconds ttl,
                                       std::string reason) noexcept
    : src_ip_v4_(src_ip_v4)
    , ttl_(ttl)
    , reason_(std::move(reason))
{}

boost::asio::awaitable<void> BlocklistAddAction::execute_async()
{
    // Blocklist would call `bpf_map_update_elem()`
    // It is a fast syscall, ~1-5µs)
    // The simplest approach is the best
    Blocklist& bl = Blocklist::instance();
    const int rc = bl.add(src_ip_v4_, ttl_);
    if (rc != 0) {
        std::cerr << "BlocklistAddAction: add("
                  << Blocklist::formatIp(src_ip_v4_)
                  << ") failed: rc=" << rc
                  << " reason=" << reason_ << "\n";
        co_return;
    }
    std::cerr << "BlocklistAddAction: blocklisted "
              << Blocklist::formatIp(src_ip_v4_)
              << " for " << ttl_.count() << "s reason=" << reason_ << "\n";
    co_return;
}

}  // namespace https_guard
