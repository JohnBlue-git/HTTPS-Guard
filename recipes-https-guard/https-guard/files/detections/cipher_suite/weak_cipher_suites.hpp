#pragma once

#include <cstdint>
#include <string_view>

namespace https_guard {

/**
 * Well-known cryptographically weak TLS cipher suites, by their on-the-wire
 * code point.
 *
 * **This is a curated list, not an exhaustive one.** The full IANA registry
 * has hundreds of entries and enumerating every weak one from memory would
 * risk both false positives (a wrong code point flagging a strong suite)
 * and false confidence. What's here are the categories that actually matter
 * for a BMC — NULL encryption, EXPORT-grade, RC4, single-DES, 3DES, and
 * anonymous key exchange — with the specific code points each category is
 * most commonly offered under. A client offering any of these is either
 * very old, misconfigured, or deliberately probing for a downgrade.
 *
 * Each entry carries its name so the Redfish message can say *which* suite
 * was objected to rather than just a hex value, and so the table stays
 * auditable — anyone extending it can check an entry against RFC 8422 /
 * RFC 5246 / the IANA TLS registry by name rather than reverse-engineering
 * the intent of a bare number.
 */
struct WeakCipherSuite {
    uint16_t         code;
    std::string_view name;
    std::string_view reason;
};

inline constexpr WeakCipherSuite kWeakCipherSuites[] = {
    // NULL encryption — authenticated but entirely unencrypted.
    {0x0001, "TLS_RSA_WITH_NULL_MD5",                 "no encryption"},
    {0x0002, "TLS_RSA_WITH_NULL_SHA",                 "no encryption"},
    {0x003B, "TLS_RSA_WITH_NULL_SHA256",              "no encryption"},

    // EXPORT-grade — deliberately weakened key sizes (40/56-bit).
    {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5",        "export-grade key size"},
    {0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",    "export-grade key size"},
    {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",     "export-grade key size"},
    {0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", "export-grade key size"},
    {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", "export-grade key size"},

    // RC4 — practically broken (RFC 7465 prohibits it outright).
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5",              "RC4 stream cipher"},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA",              "RC4 stream cipher"},
    {0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",      "RC4 stream cipher"},
    {0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA",        "RC4 stream cipher"},

    // Single DES — 56-bit effective key.
    {0x0009, "TLS_RSA_WITH_DES_CBC_SHA",              "56-bit DES"},

    // 3DES — 64-bit block size, vulnerable to Sweet32.
    {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",         "3DES / Sweet32"},
    {0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",     "3DES / Sweet32"},
    {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",     "3DES / Sweet32"},
    {0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "3DES / Sweet32"},
    {0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",   "3DES / Sweet32"},

    // Anonymous key exchange — no server authentication at all, so a MITM
    // is indistinguishable from the real server.
    {0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",    "anonymous key exchange"},
    {0x0018, "TLS_DH_anon_WITH_RC4_128_MD5",          "anonymous key exchange"},
    {0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",     "anonymous key exchange"},
    {0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA",        "anonymous key exchange"},
};

/** Returns the matching table entry, or nullptr if `code` isn't known-weak. */
inline const WeakCipherSuite* findWeakCipherSuite(uint16_t code)
{
    for (const auto& entry : kWeakCipherSuites) {
        if (entry.code == code) {
            return &entry;
        }
    }
    return nullptr;
}

}  // namespace https_guard
