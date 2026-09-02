#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <unistd.h>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace https_guard {

/* TCP states as they appear in /proc/net/tcp's `st` column (hex).  Only
 * ESTABLISHED is useful here: a LISTEN socket has no peer at all (its
 * rem_address is 00000000:0000), so it can never be the connection an
 * SSL_write/SSL_read belonged to. */
constexpr const char* kTcpStateEstablished = "01";

/**
 * One TCP socket as listed in /proc/<pid>/net/tcp.
 */
struct TcpSocketEntry {
    /* Named to match /proc/net/tcp's own columns: local_address (col 1)
     * and rem_address (col 2). No frame-of-reference ambiguity. */
    std::uint32_t local_ip_v4;   /* network byte order */
    std::uint32_t remote_ip_v4;  /* network byte order */
    std::uint16_t local_port;    /* host byte order */
    std::uint16_t remote_port;   /* host byte order */
    int           uid;
    int           tx_queue;
    int           rx_queue;
    int           sk;         /* kernel socket address (opaque) */
    std::uint64_t inode;      /* socket inode -- matches /proc/<pid>/fd entries */
};

/**
 * Outcome of trying to attribute an event to one specific connection.
 *
 * `resolved == false` is a first-class answer, not an error: for a server
 * with several concurrent connections there is genuinely no way to tell
 * from a uprobe event which socket a given SSL_write belonged to, and
 * guessing is actively harmful (the resulting address gets blocklisted
 * across every port).  Callers must not act on `entry` unless `resolved`.
 */
struct PeerResolution {
    bool             resolved = false;
    TcpSocketEntry   entry    = {};
    const char*      reason   = "not attempted";
};

/**
 * Utility to correlate a PID (from a BPF uprobe event) with the TCP
 * connection it is using, so enforcement actions can target a real
 * 4-tuple.
 *
 * IMPORTANT: /proc/<pid>/net/tcp is **network-namespace** scoped, not
 * process scoped -- it lists every TCP socket in the namespace that pid
 * belongs to, which on a BMC (single netns) is the whole system's table.
 * Identifying which of those the process actually owns requires matching
 * socket inodes against /proc/<pid>/fd entries.  Use resolveEstablishedPeer()
 * for that; getTcpSockets() alone deliberately does no such filtering and
 * its result must not be treated as belonging to the process.
 */
class ProcPeerResolver {
public:
    /**
     * Socket inodes actually owned by `pid`, read from /proc/<pid>/fd entries
     * (each socket fd is a symlink of the form "socket:[12345]").
     *
     * Returns an empty set on error, which resolveEstablishedPeer() treats
     * as "cannot attribute" rather than "no restrictions".
     */
    static std::unordered_set<std::uint64_t> getOwnedSocketInodes(pid_t pid) noexcept
    {
        std::unordered_set<std::uint64_t> inodes;
        const std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";

        DIR* dir = ::opendir(fd_dir.c_str());
        if (dir == nullptr)
        {
            return inodes;  // process gone, or no permission
        }

        while (const dirent* ent = ::readdir(dir)) {
            if (ent->d_name[0] == '.')
            {
                continue;
            }

            std::array<char, 64> link{};
            const std::string fd_path = fd_dir + "/" + ent->d_name;
            const ssize_t len = ::readlink(fd_path.c_str(), link.data(), link.size() - 1);
            if (len <= 0)
            {
                continue;  // fd closed under us; normal, just skip it
            }
            link[static_cast<std::size_t>(len)] = '\0';

            // Only socket fds matter: "socket:[12345]"
            static constexpr char kPrefix[] = "socket:[";
            constexpr std::size_t kPrefixLen = sizeof(kPrefix) - 1;
            if (std::strncmp(link.data(), kPrefix, kPrefixLen) != 0)
            {
                continue;
            }

            // strtoull rather than stoull: this is a noexcept path, and a
            // non-throwing parse is simpler than guarding every call.
            const std::uint64_t inode =
                std::strtoull(link.data() + kPrefixLen, nullptr, 10);
            if (inode != 0)
            {
                inodes.insert(inode);
            }
        }

        ::closedir(dir);
        return inodes;
    }

    /**
     * resolveEstablishedPeer() with a short-lived memo.
     *
     * Worth having because the underlying reads are both expensive and
     * highly repetitive: `/proc/<pid>/net/tcp` is **network-namespace**
     * scoped, so on a single-netns BMC every event re-parses byte-identical
     * content (505 lines on the dev host), and a single HTTPS request
     * produces several uprobe events for the same pid in quick succession.
     *
     * The TTL is deliberately very short. This data is used to target
     * enforcement, so acting on a stale tuple risks tearing down or
     * blocklisting the wrong connection -- the exact failure mode tickets 13
     * and 14 were about. A window measured in tens of milliseconds collapses
     * the burst without letting a connection meaningfully change identity.
     */
    static PeerResolution resolveEstablishedPeerCached(pid_t pid) noexcept
    {
        using clock = std::chrono::steady_clock;
        static constexpr auto kTtl = std::chrono::milliseconds(50);

        struct Entry { PeerResolution result; clock::time_point at; };
        static std::mutex mu;
        static std::unordered_map<pid_t, Entry> cache;

        const auto now = clock::now();
        {
            const std::lock_guard<std::mutex> lock(mu);
            const auto it = cache.find(pid);
            if (it != cache.end() && (now - it->second.at) < kTtl)
            {
                return it->second.result;
            }
        }

        PeerResolution fresh = resolveEstablishedPeer(pid);

        {
            const std::lock_guard<std::mutex> lock(mu);
            // Bound the map so a churn of short-lived pids can't grow it
            // without limit; entries are cheap to rebuild.
            if (cache.size() > 256)
            {
                cache.clear();
            }
            cache[pid] = Entry{fresh, now};
        }
        return fresh;
    }

    /**
     * Attributes an event to a single established connection owned by
     * `pid`, or explains why it could not.
     *
     * Deliberately fails closed when the answer is ambiguous -- see
     * PeerResolution.  A busy server will often land here, and declining
     * to enforce is the correct outcome: acting on the wrong connection
     * blocklists that address on every port.
     */
    static PeerResolution resolveEstablishedPeer(pid_t pid) noexcept
    {
        PeerResolution result;

        const auto owned = getOwnedSocketInodes(pid);
        if (owned.empty())
        {
            result.reason = "no socket fds owned by pid (process gone, or not permitted)";
            return result;
        }

        const auto all = getTcpSockets(pid);
        const TcpSocketEntry* match = nullptr;
        std::size_t match_count = 0;

        for (const auto& sock : all)
        {
            if (sock.inode == 0 || owned.count(sock.inode) == 0)
            {
                continue;  // belongs to some other process in this namespace
            }
            ++match_count;
            if (match == nullptr)
            {
                match = &sock;
            }
        }

        if (match_count == 0)
        {
            result.reason = "pid owns no established TCP connection";
            return result;
        }
        if (match_count > 1)
        {
            // Cannot tell which of them this SSL_write/SSL_read used; a
            // uprobe event carries no socket identity. Resolving this
            // properly needs the fd read out of the SSL object's BIO in
            // BPF -- see the ticket's "known ceiling" note.
            result.reason = "pid owns multiple established connections; cannot attribute event to one";
            return result;
        }

        result.resolved = true;
        result.entry    = *match;
        result.reason   = "unique established connection owned by pid";
        return result;
    }

    /**
     * Parse /proc/<pid>/net/tcp and return every ESTABLISHED TCPv4 socket
     * in that pid's **network namespace** -- NOT only the ones belonging
     * to that process.  On a single-netns system (the normal BMC case)
     * that is the whole machine's connection table.
     *
     * The previous version of this comment claimed these connections
     * belonged to the process; nothing here filtered by process, and the
     * mismatch is what let an unrelated socket reach enforcement.  Use
     * resolveEstablishedPeer() when ownership matters, which for anything
     * acting on the result it always does.
     *
     * LISTEN and other non-ESTABLISHED states are skipped: they have no
     * peer, so they can never be the connection an event belonged to.
     * (Measured on a dev host: 447 of 505 entries were LISTEN, which is
     * why the unfiltered version so often selected one.)
     *
     * Returns an empty vector on error (invalid PID, no such file,
     * permission denied, etc.).
     */
    static std::vector<TcpSocketEntry> getTcpSockets(pid_t pid) noexcept
    {
        std::vector<TcpSocketEntry> entries;
        std::string path = "/proc/" + std::to_string(pid) + "/net/tcp";
        std::ifstream f(path);

        if (!f.is_open())
        {
            return entries;
        }

        std::string line;
        // Skip header line: "  sl  local_address rem_address ..."
        std::getline(f, line);

        while (std::getline(f, line)) {
            // Format (from kernel doc):
            //   sl  local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt
            //      uid timeout inode ...
            //
            // Example:
            //   0: 0100007F:01BB 00000000:0000 0A 00000000:00000000 00:00000000
            //      00000000     0        0 30000 1 0000000000000000 100 0 0 10 0
            //
            // We parse columns 1 (local_address), 2 (rem_address), 4 (tx_queue:rx_queue),
            // 7 (uid), and 8 (inode/sk).
            //
            // Columns are whitespace-separated.  We use simple string splitting.

            std::istringstream ss(line);
            std::string col;
            std::vector<std::string> cols;

            while (ss >> col) {
                cols.push_back(col);
            }

            // col[9] is the socket inode, which resolveEstablishedPeer()
            // needs in order to match against /proc/<pid>/fd entries.
            if (cols.size() < 10)
            {
                continue;
            }

            // col[3] is the TCP state. Only ESTABLISHED sockets describe a
            // real peer; skipping the rest is what stops a LISTEN entry
            // (rem_address 00000000:0000) reaching enforcement.
            if (cols[3] != kTcpStateEstablished)
            {
                continue;
            }

            // Column 0: "sl:" with colon, e.g. "0:" — skip it
            // Column 1: local_address "AABBCCDD:PPPP"
            // Column 2: rem_address  "AABBCCDD:PPPP"
            // Column 3: socket state (st)
            // Column 4: tx_queue:rx_queue
            // Column 7: uid

            TcpSocketEntry entry = {};

            // Parse local address (hex bytes reversed in groups of 2)
            // Format: "0100007F:01BB" -> IP=127.0.0.1, Port=443
            parseProcNetEntry(cols[1], entry.local_ip_v4, entry.local_port);   /* local_address */
            parseProcNetEntry(cols[2], entry.remote_ip_v4, entry.remote_port); /* rem_address   */

            // Parse tx_queue:rx_queue
            parseQueue(cols[4], entry.tx_queue, entry.rx_queue);

            // Parse uid.  Guarded like every other numeric field here
            // (parseProcNetEntry/parseQueue below): this whole function is
            // noexcept, so an unparseable column escaping as an exception
            // would be std::terminate() -- killing the daemon over one odd
            // line of /proc, rather than skipping the field.
            if (cols.size() > 7)
            {
                try
                {
                    entry.uid = std::stoi(cols[7], nullptr, 10);
                }
                catch (...)
                {
                    entry.uid = 0;
                }
            }

            // Socket inode (col 9) -- the only field that ties this entry
            // to a specific process, via /proc/<pid>/fd entries. strtoull rather
            // than stoull: no-throw suits this noexcept path.
            entry.inode = std::strtoull(cols[9].c_str(), nullptr, 10);

            entries.push_back(entry);
        }

        return entries;
    }

    /**
     * Parse a /proc/net/tcp address field of the form "AABBCCDD:PPPP"
     * into an IPv4 address (network byte order) and port (host byte order).
     *
     * The hex IP bytes are reversed: "0100007F" -> 0x7F000001 -> 127.0.0.1
     * The port is "01BB" -> 443
     */
    static void parseProcNetEntry(const std::string& field,
                                   std::uint32_t& ip_v4,
                                   std::uint16_t& port) noexcept
    {
        auto colon_pos = field.find(':');
        if (colon_pos == std::string::npos)
        {
            ip_v4 = 0;
            port = 0;
            return;
        }

        std::string ip_hex = field.substr(0, colon_pos);
        std::string port_hex = field.substr(colon_pos + 1);

        // Parse IP. The value must come out in NETWORK byte order, i.e. the
        // in-memory bytes must be 7F 00 00 01 for 127.0.0.1, since that is
        // what inet_ntop/inet_ntoa and the netlink/BPF consumers expect.
        //
        // No byte swap is needed, and doing one is wrong. The kernel writes
        // this field with %08X applied to the __be32 address read as a
        // native integer, so parsing it straight back to a native integer
        // reproduces the original network-order byte layout on both
        // endiannesses:
        //
        //   LE: __be32 127.0.0.1 is bytes 7F 00 00 01 -> native read
        //       0x0100007F -> printed "0100007F" -> parsed 0x0100007F ->
        //       stored little-endian -> bytes 7F 00 00 01. Correct.
        //   BE: bytes 7F 00 00 01 -> native read 0x7F000001 -> printed
        //       "7F000001" -> parsed 0x7F000001 -> stored big-endian ->
        //       bytes 7F 00 00 01. Correct.
        //
        // The previous code swapped the bytes, which produced 1.0.0.127
        // from 127.0.0.1 -- verified against getsockname/getpeername, and
        // visible in this project's own logs as "blocklisted 1.0.0.127".
        // That meant BlocklistAddAction was blocking an entirely different
        // address than the one observed. It was previously mistaken for an
        // artifact of loopback testing; it was not.
        if (ip_hex.length() == 8)
        {
            try
            {
                ip_v4 = static_cast<std::uint32_t>(std::stoul(ip_hex, nullptr, 16));
            }
            catch (...)
            {
                ip_v4 = 0;
            }
        }

        // Parse port
        if (port_hex.length() <= 4)
        {
            try
            {
                port = static_cast<std::uint16_t>(
                    std::stoul(port_hex, nullptr, 16));
            }
            catch (...)
            {
                port = 0;
            }
        }
    }

    /**
     * Parse tx_queue:rx_queue format e.g. "00000000:00000000"
     */
    static void parseQueue(const std::string& field,
                            int& tx_queue, int& rx_queue) noexcept
    {
        auto colon_pos = field.find(':');
        if (colon_pos == std::string::npos)
        {
            return;
        }
        try
        {
            tx_queue = std::stoi(field.substr(0, colon_pos), nullptr, 16);
            rx_queue = std::stoi(field.substr(colon_pos + 1), nullptr, 16);
        }
        catch (...)
        {
            // ignore
        }
    }
};

}  // namespace https_guard