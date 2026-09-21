#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <linux/inet_diag.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <cstring>

#include "TcpDestroyer.hpp"

using namespace https_guard;

namespace {

// 10.0.2.15 / 10.0.2.2 -- the same BMC/gateway pair README.md's own worked
// examples use, network byte order, zero-padded past the first 4 bytes
// exactly as EventMeta::IpAddress::setV4() leaves them.
constexpr std::array<std::uint8_t, 16> kLocalV4  = {10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
constexpr std::array<std::uint8_t, 16> kRemoteV4 = {10, 0, 2, 2,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// 2001:db8::1 / 2001:db8::2 -- RFC 3849 documentation range, so these can
// never collide with a real address.
constexpr std::array<std::uint8_t, 16> kLocalV6  = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
constexpr std::array<std::uint8_t, 16> kRemoteV6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

}  // namespace

TEST(TcpDestroyerRequestTest, Ipv4SelectsAfInetAndCopiesTheFirstFourBytes)
{
    struct inet_diag_req_v2 req{};
    TcpDestroyer::populateRequest(req, /*is_ipv6=*/false, kLocalV4, kRemoteV4, 443, 51000);

    EXPECT_EQ(req.sdiag_family, AF_INET);
    EXPECT_EQ(req.sdiag_protocol, IPPROTO_TCP);

    std::uint32_t src = 0, dst = 0;
    std::memcpy(&src, req.id.idiag_src, sizeof(src));
    std::memcpy(&dst, req.id.idiag_dst, sizeof(dst));
    std::uint32_t expected_src = 0, expected_dst = 0;
    std::memcpy(&expected_src, kLocalV4.data(), sizeof(expected_src));
    std::memcpy(&expected_dst, kRemoteV4.data(), sizeof(expected_dst));
    EXPECT_EQ(src, expected_src);
    EXPECT_EQ(dst, expected_dst);
}

TEST(TcpDestroyerRequestTest, LocalGoesToSrcAndRemoteGoesToDstNeverSwapped)
{
    // Pins the exact historical bug DESIGN.md records: under src/dst naming
    // the tuple was inverted for one hook, describing a socket that did not
    // exist. Two distinguishable addresses make a swap fail loudly rather
    // than by coincidence matching.
    struct inet_diag_req_v2 req{};
    TcpDestroyer::populateRequest(req, false, kLocalV4, kRemoteV4, 443, 51000);

    EXPECT_EQ(std::memcmp(req.id.idiag_src, kLocalV4.data(), 4), 0)
        << "idiag_src must be the LOCAL end, not the remote one";
    EXPECT_EQ(std::memcmp(req.id.idiag_dst, kRemoteV4.data(), 4), 0)
        << "idiag_dst must be the REMOTE end, not the local one";
}

TEST(TcpDestroyerRequestTest, PortsAreConvertedToNetworkByteOrder)
{
    // Pins the other historical bug DESIGN.md records: 443 (0x01BB) went
    // out unconverted and was read back as 47873 (0xBB01) -- an exact
    // byte swap. 47873 is an independent, known-good literal (computed by
    // hand from the DESIGN.md incident, not derived by calling htons() the
    // way the code under test does), so this disagrees with the code the
    // same way that incident would have.
    struct inet_diag_req_v2 req{};
    TcpDestroyer::populateRequest(req, false, kLocalV4, kRemoteV4, 443, 51000);

    EXPECT_EQ(ntohs(req.id.idiag_sport), 443);
    EXPECT_EQ(req.id.idiag_sport, 0xBB01);  // 443 byte-swapped, as network order
    EXPECT_EQ(ntohs(req.id.idiag_dport), 51000);
}

TEST(TcpDestroyerRequestTest, Ipv6SelectsAfInetSixAndCopiesAllSixteenBytes)
{
    struct inet_diag_req_v2 req{};
    TcpDestroyer::populateRequest(req, /*is_ipv6=*/true, kLocalV6, kRemoteV6, 443, 51000);

    EXPECT_EQ(req.sdiag_family, AF_INET6);
    EXPECT_EQ(std::memcmp(req.id.idiag_src, kLocalV6.data(), 16), 0);
    EXPECT_EQ(std::memcmp(req.id.idiag_dst, kRemoteV6.data(), 16), 0);
}

TEST(TcpDestroyerRequestTest, CookieIsAllOnesSoAnySocketMatches)
{
    // idiag_cookie is __u32[2] (a 64-bit cookie split across two 32-bit
    // words), not __u64[2] -- the initial version of this test compared
    // against ~0ULL and failed for exactly that reason, even though the
    // production assignment (~0ULL truncated into each __u32 word) was
    // already correct. 0xFFFFFFFFu is the right width for "all bits set
    // in this word".
    struct inet_diag_req_v2 req{};
    TcpDestroyer::populateRequest(req, false, kLocalV4, kRemoteV4, 443, 51000);

    EXPECT_EQ(req.id.idiag_cookie[0], 0xFFFFFFFFu);
    EXPECT_EQ(req.id.idiag_cookie[1], 0xFFFFFFFFu);
}
