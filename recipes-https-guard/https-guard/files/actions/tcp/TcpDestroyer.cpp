#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <utility>

#include <arpa/inet.h>
#include <cstddef>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "TcpDestroyer.hpp"

namespace https_guard {
namespace {

/* Minimal Netlink message for SOCK_DESTROY on a TCP 4-tuple, AF_INET or
 * AF_INET6 (sdiag_family, set by populateRequest() below, decides which). */
struct diag_nl_msg {
    struct nlmsghdr          nlh;
    struct inet_diag_req_v2  req;
};

/* Format a network-byte-order address (either family) for logging. */
std::string formatIp(bool is_ipv6, const std::array<std::uint8_t, 16>& addr) noexcept
{
    std::array<char, INET6_ADDRSTRLEN> buf{};
    const int family = is_ipv6 ? AF_INET6 : AF_INET;
    if (inet_ntop(family, addr.data(), buf.data(), buf.size()) == nullptr) {
        return std::string{is_ipv6 ? "::" : "0.0.0.0"};
    }
    return std::string{buf.data()};
}

/*
 * Prepare the SOCK_DESTROY Netlink message into the caller-provided
 * msghdr/iovec so that the calling coroutine can send it.
 */
void buildDestroyRequest(const struct diag_nl_msg& msg,
                         struct msghdr& nl_hdr,
                         struct iovec& iov,
                         struct sockaddr_nl& nl_addr) noexcept
{
    std::memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    std::memset(&iov, 0, sizeof(iov));
    iov.iov_base = const_cast<diag_nl_msg*>(&msg);
    iov.iov_len  = sizeof(msg);

    std::memset(&nl_hdr, 0, sizeof(nl_hdr));
    nl_hdr.msg_name    = &nl_addr;
    nl_hdr.msg_namelen = sizeof(nl_addr);
    nl_hdr.msg_iov     = &iov;
    nl_hdr.msg_iovlen  = 1;
}

}  // anonymous namespace

void TcpDestroyer::populateRequest(struct inet_diag_req_v2& req,
                                    bool is_ipv6,
                                    const std::array<std::uint8_t, 16>& local_addr,
                                    const std::array<std::uint8_t, 16>& remote_addr,
                                    std::uint16_t local_port,
                                    std::uint16_t remote_port) noexcept
{
    req.sdiag_family   = is_ipv6 ? AF_INET6 : AF_INET;
    req.sdiag_protocol = IPPROTO_TCP;
    req.idiag_states   = 0xFFF;  /* all TCP states */

    /* See the header and DESIGN.md: idiag_sport/idiag_dport are __be16,
     * ports arrive here in this project's host-byte-order convention, so
     * htons() applies at exactly this boundary. */
    req.id.idiag_sport = htons(local_port);
    req.id.idiag_dport = htons(remote_port);

    /* idiag_src/idiag_dst are __be32[4] -- 16 bytes either way. For AF_INET
     * the kernel reads only the first word; for AF_INET6 it reads all four
     * as one address. Copying all 16 bytes verbatim is correct for both,
     * since an IPv4 tuple already carries zero bytes past the first 4 (see
     * EventMeta::IpAddress::setV4()) -- there is no family-specific branch
     * needed here beyond sdiag_family itself. */
    static_assert(sizeof(req.id.idiag_src) == 16 && sizeof(req.id.idiag_dst) == 16,
                  "inet_diag_sockid's address fields changed shape");
    std::memcpy(req.id.idiag_src, local_addr.data(), sizeof(req.id.idiag_src));
    std::memcpy(req.id.idiag_dst, remote_addr.data(), sizeof(req.id.idiag_dst));

    /* idiag_cookie must be all-ones: "don't care / match any socket" --
     * a zero cookie would require an exact cookie match, which is almost
     * never what we want. */
    req.id.idiag_cookie[0] = ~0ULL;
    req.id.idiag_cookie[1] = ~0ULL;
}

TcpDestroyer::TcpDestroyer(bool is_ipv6,
                           std::array<std::uint8_t, 16> local_addr,
                           std::array<std::uint8_t, 16> remote_addr,
                           std::uint16_t local_port,
                           std::uint16_t remote_port,
                           std::string reason) noexcept
    : is_ipv6_(is_ipv6)
    , local_addr_(local_addr)
    , remote_addr_(remote_addr)
    , local_port_(local_port)
    , remote_port_(remote_port)
    , reason_(std::move(reason))
{
    /*
     * Open with SOCK_NONBLOCK so the fd can be used with
     * Boost.Asio's reactor (epoll) for true async I/O.
     */
    nl_fd_ = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    NETLINK_INET_DIAG);
    if (nl_fd_ < 0) {
        std::cerr << "BlockTcpAction: socket(NETLINK_INET_DIAG) failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
    }
}

TcpDestroyer::~TcpDestroyer() noexcept
{
    if (nl_fd_ >= 0) {
        close(nl_fd_);
    }
}

boost::asio::awaitable<bool> TcpDestroyer::async_execute() noexcept
{
    if (nl_fd_ < 0) {
        co_return false;
    }

    /* Build the SOCK_DESTROY request for the exact TCP 4-tuple. */
    struct diag_nl_msg msg{};
    msg.nlh.nlmsg_len   = sizeof(msg);
    msg.nlh.nlmsg_type  = SOCK_DESTROY;          /* <linux/inet_diag.h> */
    /* NLM_F_ACK matters here, and its absence hid a working enforcement path.
     *
     * With NLM_F_REQUEST alone, netlink replies only on *error* -- a
     * successful SOCK_DESTROY sends nothing back. While CONFIG_INET_DIAG was
     * missing from the kernel every request failed, so a reply always
     * arrived and the failure was always logged; once the kernel could
     * actually honour the request, success became completely silent and this
     * code sat waiting for a reply that was never coming.
     *
     * For a security daemon that is the wrong way round: a successful
     * teardown is precisely the event worth recording. Asking for an ack
     * makes the kernel answer either way, which also makes the
     * "destroyed TCP connection" branch below reachable at all. */
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq   = 1;

    /*
     * Byte order and orientation at this boundary -- the reason
     * SOCK_DESTROY never worked before, twice over (see DESIGN.md for the
     * full story: a byte-swapped port, then an inverted local/remote tuple,
     * both hidden behind a misleading -ENOENT that turned out to mean
     * "CONFIG_INET_DIAG is not built in", not "these arguments are wrong").
     *
     * populateRequest() carries this logic now, as a pure function that can
     * be (and is, in tests/actions/tcp_destroyer_test.cpp) checked directly
     * without a real socket -- exactly the coverage that would have caught
     * both bugs the first time.
     */
    populateRequest(msg.req, is_ipv6_, local_addr_, remote_addr_,
                     local_port_, remote_port_);

    /* ------------------------------------------------------------------
     * Truly async Netlink I/O via Boost.Asio's reactor.
     *
     * We wrap the non-blocking fd in a posix::stream_descriptor and
     * use async_wait() to be notified by epoll when the socket is
     * ready for writing / reading.  The actual sendmsg/recvmsg calls
     * are issued after readiness is confirmed, so they never block.
     * No thread, no polling loop, no busy-wait.
     * ------------------------------------------------------------------ */

    boost::asio::posix::stream_descriptor desc(
        co_await boost::asio::this_coro::executor);
    desc.assign(nl_fd_);

    /* ---- Send the destroy command ---- */
    struct iovec iov;
    struct msghdr nl_hdr;
    struct sockaddr_nl nl_addr;

    buildDestroyRequest(msg, nl_hdr, iov, nl_addr);

    co_await desc.async_wait(
        boost::asio::posix::stream_descriptor::wait_write,
        boost::asio::use_awaitable);

    const ssize_t sent = sendmsg(nl_fd_, &nl_hdr, 0);
    if (sent < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY sendmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        desc.release();
        co_return false;
    }

    /* ---- Read the kernel's reply ---- */
    std::uint8_t reply_buf[8192];

    struct iovec riov;
    std::memset(&riov, 0, sizeof(riov));
    riov.iov_base = reply_buf;
    riov.iov_len  = sizeof(reply_buf);

    struct sockaddr_nl reply_addr{};

    struct msghdr rcv_hdr;
    std::memset(&rcv_hdr, 0, sizeof(rcv_hdr));
    rcv_hdr.msg_name    = &reply_addr;
    rcv_hdr.msg_namelen = sizeof(reply_addr);
    rcv_hdr.msg_iov     = &riov;
    rcv_hdr.msg_iovlen  = 1;

    co_await desc.async_wait(
        boost::asio::posix::stream_descriptor::wait_read,
        boost::asio::use_awaitable);

    const ssize_t recvd = recvmsg(nl_fd_, &rcv_hdr, 0);
    if (recvd < 0) {
        std::cerr << "BlockTcpAction: SOCK_DESTROY recvmsg failed: "
                  << std::strerror(errno) << " (" << errno << ")\n";
        desc.release();
        co_return false;
    }

    /* Release ownership of the fd back to TcpDestroyer's destructor. */
    desc.release();

    /* Parse the Netlink response header. */
    if (recvd < static_cast<ssize_t>(sizeof(struct nlmsghdr))) {
        std::cerr << "BlockTcpAction: short Netlink reply ("
                  << recvd << " bytes)\n";
        co_return false;
    }

    const auto* nl_reply = reinterpret_cast<const struct nlmsghdr*>(reply_buf);

    if (nl_reply->nlmsg_type == NLMSG_ERROR) {
        /* NLMSG_ERROR carries an nlmsgerr struct; error == 0 means success. */
        const auto* err = static_cast<const struct nlmsgerr*>(NLMSG_DATA(nl_reply));
        const int nl_err = err->error;

        if (nl_err == 0) {
            std::cerr << "BlockTcpAction: destroyed TCP connection "
                      << formatIp(is_ipv6_, local_addr_) << ":" << local_port_
                      << " -> " << formatIp(is_ipv6_, remote_addr_) << ":" << remote_port_
                      << " reason=" << reason_ << "\n";
            co_return true;
        } else {
            std::cerr << "BlockTcpAction: SOCK_DESTROY failed for "
                      << formatIp(is_ipv6_, local_addr_) << ":" << local_port_
                      << " -> " << formatIp(is_ipv6_, remote_addr_) << ":" << remote_port_
                      << " reason=" << reason_
                      << " netlink_error=" << nl_err
                      << " (" << std::strerror(-nl_err) << ")\n";
            co_return false;
        }
    } else {
        std::cerr << "BlockTcpAction: unexpected Netlink reply type "
                  << nl_reply->nlmsg_type << '\n';
        co_return false;
    }
}

}  // namespace https_guard