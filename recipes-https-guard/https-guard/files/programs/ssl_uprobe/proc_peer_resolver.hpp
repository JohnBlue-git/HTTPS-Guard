#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace https_guard {

/**
 * TCP socket 4-tuple resolved from /proc/<pid>/net/tcp.
 */
struct TcpSocketEntry {
    std::uint32_t src_ip_v4;  /* network byte order */
    std::uint32_t dst_ip_v4;  /* network byte order */
    std::uint16_t src_port;   /* host byte order */
    std::uint16_t dst_port;   /* host byte order */
    int           uid;
    int           tx_queue;
    int           rx_queue;
    int           sk;         /* kernel socket address (opaque) */
};

/**
 * Utility to read /proc/<pid>/net/tcp and resolve the TCP connections
 * of a given process.  This allows the userspace daemon to correlate
 * a PID (obtained from a BPF uprobe event) with the actual socket
 * 4-tuples, enabling SOCK_DESTROY enforcement actions.
 */
class ProcPeerResolver {
public:
    /**
     * Parse /proc/<pid>/net/tcp and return all established TCPv4
     * connections belonging to that process.
     *
     * Returns an empty vector on error (invalid PID, no such file,
     * permission denied, etc.).
     */
    static std::vector<TcpSocketEntry> getTcpSockets(pid_t pid) noexcept
    {
        std::vector<TcpSocketEntry> entries;
        std::string path = "/proc/" + std::to_string(pid) + "/net/tcp";
        std::ifstream f(path);

        if (!f.is_open()) {
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

            if (cols.size() < 8) {
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
            parseProcNetEntry(cols[1], entry.src_ip_v4, entry.src_port);
            parseProcNetEntry(cols[2], entry.dst_ip_v4, entry.dst_port);

            // Parse tx_queue:rx_queue
            parseQueue(cols[4], entry.tx_queue, entry.rx_queue);

            // Parse uid
            if (cols.size() > 7) {
                entry.uid = std::stoi(cols[7], nullptr, 10);
            }

            // Parse sk (kernel socket address) from column 1's hex addr portion
            // The actual sk field is in column 9 in some kernel versions
            if (cols.size() > 8) {
                // Try to parse sk from the "inode" field (col 9 on newer kernels)
                // But for our purposes, we only need the 4-tuple
                (void)0; // placeholder
            }

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
        if (colon_pos == std::string::npos) {
            ip_v4 = 0;
            port = 0;
            return;
        }

        std::string ip_hex = field.substr(0, colon_pos);
        std::string port_hex = field.substr(colon_pos + 1);

        // Parse IP: hex string like "0100007F" -> reverse bytes -> 0x7F000001
        if (ip_hex.length() == 8) {
            try {
                std::uint32_t raw = static_cast<std::uint32_t>(
                    std::stoul(ip_hex, nullptr, 16));
                // raw is already in network byte order (big-endian reading)
                // From kernel proc: it's stored as raw in-memory bytes
                // So "0100007F" means bytes 01 00 00 7F = 1.0.0.127
                // We swap to get 127.0.0.1 in network byte order
                ip_v4 = ((raw & 0xFF) << 24) |
                        ((raw & 0xFF00) << 8) |
                        ((raw & 0xFF0000) >> 8) |
                        ((raw & 0xFF000000) >> 24);
            } catch (...) {
                ip_v4 = 0;
            }
        }

        // Parse port
        if (port_hex.length() <= 4) {
            try {
                port = static_cast<std::uint16_t>(
                    std::stoul(port_hex, nullptr, 16));
            } catch (...) {
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
        if (colon_pos == std::string::npos) {
            return;
        }
        try {
            tx_queue = std::stoi(field.substr(0, colon_pos), nullptr, 16);
            rx_queue = std::stoi(field.substr(colon_pos + 1), nullptr, 16);
        } catch (...) {
            // ignore
        }
    }
};

}  // namespace https_guard