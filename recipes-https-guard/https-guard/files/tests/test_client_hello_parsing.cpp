#include <doctest/doctest.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "parse_client_hello.h"

namespace {

// Builds a ClientHello *body* (starting at legacy_version, which is where
// parse_client_hello_detail() expects to be handed a pointer) from its
// variable-length parts. Deliberately assembles real wire bytes rather than
// mocking the parser's inputs — the whole point is exercising the byte-level
// walk the BPF program actually performs.
class ClientHelloBuilder {
public:
    ClientHelloBuilder& version(uint16_t v)
    {
        version_ = v;
        return *this;
    }

    ClientHelloBuilder& sessionId(size_t len)
    {
        session_id_len_ = len;
        return *this;
    }

    ClientHelloBuilder& cipherSuites(std::vector<uint16_t> suites)
    {
        cipher_suites_ = std::move(suites);
        return *this;
    }

    // Overrides the cipher_suites_length field without changing the actual
    // suite bytes, for testing malformed input.
    ClientHelloBuilder& forceCipherSuitesLen(uint16_t len)
    {
        forced_cs_len_ = len;
        return *this;
    }

    ClientHelloBuilder& compression(size_t len)
    {
        compression_len_ = len;
        return *this;
    }

    ClientHelloBuilder& sni(std::string host)
    {
        sni_ = std::move(host);
        has_sni_ = true;
        return *this;
    }

    // Emits an SNI extension whose declared name_length disagrees with the
    // bytes actually present, for testing malformed input.
    ClientHelloBuilder& sniWithBadNameLen(std::string host, uint16_t declared_len)
    {
        sni_ = std::move(host);
        has_sni_ = true;
        forced_name_len_ = declared_len;
        return *this;
    }

    ClientHelloBuilder& sniNameType(uint8_t type)
    {
        sni_name_type_ = type;
        return *this;
    }

    // A non-SNI extension emitted before the SNI one, to exercise skipping.
    ClientHelloBuilder& padExtension(uint16_t type, size_t len)
    {
        pad_extensions_.push_back({type, len});
        return *this;
    }

    ClientHelloBuilder& omitExtensions()
    {
        omit_extensions_ = true;
        return *this;
    }

    std::vector<unsigned char> build() const
    {
        std::vector<unsigned char> b;
        push16(b, version_);
        b.insert(b.end(), 32, 0xAB);  // random

        b.push_back(static_cast<unsigned char>(session_id_len_));
        b.insert(b.end(), session_id_len_, 0xCD);

        const uint16_t cs_len = forced_cs_len_
            ? *forced_cs_len_
            : static_cast<uint16_t>(cipher_suites_.size() * 2);
        push16(b, cs_len);
        for (const uint16_t suite : cipher_suites_) {
            push16(b, suite);
        }

        b.push_back(static_cast<unsigned char>(compression_len_));
        b.insert(b.end(), compression_len_, 0x00);

        if (omit_extensions_) {
            return b;
        }

        std::vector<unsigned char> exts;
        for (const auto& [type, len] : pad_extensions_) {
            push16(exts, type);
            push16(exts, static_cast<uint16_t>(len));
            exts.insert(exts.end(), len, 0xEE);
        }

        if (has_sni_) {
            const uint16_t name_len = forced_name_len_
                ? *forced_name_len_
                : static_cast<uint16_t>(sni_.size());
            std::vector<unsigned char> sni_body;
            push16(sni_body, static_cast<uint16_t>(name_len + 3));  // list length
            sni_body.push_back(sni_name_type_);
            push16(sni_body, name_len);
            sni_body.insert(sni_body.end(), sni_.begin(), sni_.end());

            push16(exts, 0x0000);  // server_name
            push16(exts, static_cast<uint16_t>(sni_body.size()));
            exts.insert(exts.end(), sni_body.begin(), sni_body.end());
        }

        push16(b, static_cast<uint16_t>(exts.size()));
        b.insert(b.end(), exts.begin(), exts.end());
        return b;
    }

private:
    static void push16(std::vector<unsigned char>& out, uint16_t v)
    {
        out.push_back(static_cast<unsigned char>(v >> 8));
        out.push_back(static_cast<unsigned char>(v & 0xFF));
    }

    uint16_t version_ = 0x0303;
    size_t   session_id_len_ = 0;
    std::vector<uint16_t> cipher_suites_{0x1301, 0x1302};
    std::optional<uint16_t> forced_cs_len_;
    size_t   compression_len_ = 1;
    bool     has_sni_ = false;
    std::string sni_;
    std::optional<uint16_t> forced_name_len_;
    uint8_t  sni_name_type_ = 0;
    std::vector<std::pair<uint16_t, size_t>> pad_extensions_;
    bool     omit_extensions_ = false;
};

// Runs the real parser over a built body, as the XDP program would.
xdp_event parse(const std::vector<unsigned char>& body)
{
    xdp_event evt{};
    std::memset(&evt, 0, sizeof(evt));
    parse_client_hello_detail(&evt, body.data(), body.data() + body.size());
    return evt;
}

std::vector<uint16_t> capturedSuites(const xdp_event& evt)
{
    return {evt.cipher_suites, evt.cipher_suites + evt.cipher_suite_count};
}

}  // namespace

TEST_CASE("ClientHello parse: extracts the offered cipher suite list")
{
    const auto evt = parse(ClientHelloBuilder()
                               .cipherSuites({0x1301, 0x1302, 0xC02F})
                               .build());

    CHECK(evt.cipher_suites_offered == 3);
    CHECK(evt.cipher_suite_count == 3);
    CHECK(capturedSuites(evt) == std::vector<uint16_t>{0x1301, 0x1302, 0xC02F});
    CHECK(evt.sni_malformed == 0);
}

TEST_CASE("ClientHello parse: a non-empty session_id shifts every later field correctly")
{
    // Session resumption is completely normal, and getting this skip wrong
    // would silently misread the cipher suites that follow it.
    const auto evt = parse(ClientHelloBuilder()
                               .sessionId(32)
                               .cipherSuites({0xC030})
                               .sni("bmc.example.com")
                               .build());

    CHECK(capturedSuites(evt) == std::vector<uint16_t>{0xC030});
    CHECK(evt.sni_present == 1);
    CHECK(std::string(evt.sni_hostname) == "bmc.example.com");
}

TEST_CASE("ClientHello parse: extracts SNI past unrelated extensions")
{
    const auto evt = parse(ClientHelloBuilder()
                               .padExtension(0x000B, 4)   // ec_point_formats
                               .padExtension(0x000A, 8)   // supported_groups
                               .sni("johnblue")
                               .build());

    CHECK(evt.sni_present == 1);
    CHECK(std::string(evt.sni_hostname) == "johnblue");
    CHECK(evt.sni_malformed == 0);
}

TEST_CASE("ClientHello parse: no SNI extension is not an anomaly")
{
    // The overwhelmingly common case for a BMC reached by IP address.
    const auto evt = parse(ClientHelloBuilder().build());

    CHECK(evt.sni_present == 0);
    CHECK(evt.sni_malformed == 0);
    CHECK(std::string(evt.sni_hostname).empty());
}

TEST_CASE("ClientHello parse: no extensions block at all is not an anomaly")
{
    const auto evt = parse(ClientHelloBuilder().omitExtensions().build());

    CHECK(evt.sni_present == 0);
    CHECK(evt.sni_malformed == 0);
    CHECK(evt.cipher_suite_count == 2);  // still got the suites before it
}

TEST_CASE("ClientHello parse: cipher suite capture truncates but reports the true count")
{
    // 40 offered > HG_MAX_CIPHER_SUITES (32) capacity: a detector must be
    // able to tell "I only saw part of the list" from "the list was short".
    std::vector<uint16_t> many;
    for (uint16_t i = 0; i < 40; i++) {
        many.push_back(static_cast<uint16_t>(0x1300 + i));
    }

    const auto evt = parse(ClientHelloBuilder().cipherSuites(many).build());

    CHECK(evt.cipher_suites_offered == 40);
    CHECK(evt.cipher_suite_count == HG_MAX_CIPHER_SUITES);
    CHECK(evt.cipher_suites[0] == 0x1300);
    CHECK(evt.cipher_suites[HG_MAX_CIPHER_SUITES - 1] == 0x131F);
}

TEST_CASE("ClientHello parse: an over-long SNI is flagged rather than silently truncated")
{
    const std::string long_host(HG_SNI_LEN + 20, 'a');
    const auto evt = parse(ClientHelloBuilder().sni(long_host).build());

    CHECK(evt.sni_malformed == 1);
    CHECK(std::strlen(evt.sni_hostname) == HG_SNI_LEN - 1);
}

TEST_CASE("ClientHello parse: odd cipher_suites_length is flagged malformed")
{
    // Suite IDs are 2 bytes, so an odd length can't be a real list.
    const auto evt = parse(ClientHelloBuilder()
                               .cipherSuites({0x1301})
                               .forceCipherSuitesLen(3)
                               .build());

    CHECK(evt.sni_malformed == 1);
}

TEST_CASE("ClientHello parse: zero cipher_suites_length is flagged malformed")
{
    const auto evt = parse(ClientHelloBuilder()
                               .cipherSuites({})
                               .forceCipherSuitesLen(0)
                               .build());

    CHECK(evt.sni_malformed == 1);
}

TEST_CASE("ClientHello parse: an unknown SNI name_type is flagged malformed")
{
    const auto evt = parse(ClientHelloBuilder()
                               .sni("bmc.example.com")
                               .sniNameType(0x07)  // only 0 (host_name) is defined
                               .build());

    CHECK(evt.sni_malformed == 1);
    CHECK(evt.sni_present == 0);
}

TEST_CASE("ClientHello parse: SNI list_len inconsistent with name_len is flagged")
{
    const auto evt = parse(ClientHelloBuilder()
                               .sniWithBadNameLen("bmc", 900)
                               .build());

    CHECK(evt.sni_malformed == 1);
}

TEST_CASE("ClientHello parse: a hostname cut off by the packet end is flagged, not reported as complete")
{
    // Regression guard for a real bypass: a packet ending mid-hostname used
    // to yield sni_present with a PREFIX and no malformed flag, so a crafted
    // "bmc.evil.com" truncated to "bmc" could satisfy an expected-hostname
    // check it has nothing to do with.
    auto body = ClientHelloBuilder().sni("bmc.evil.com").build();
    body.resize(body.size() - 9);  // lop off most of the hostname bytes

    const auto evt = parse(body);

    CHECK(evt.sni_malformed == 1);
    CHECK(std::string(evt.sni_hostname) != "bmc.evil.com");
}

TEST_CASE("ClientHello parse: truncated packet never reads past the end")
{
    // Every prefix of a valid ClientHello must parse without reading out of
    // bounds. Under ASan/UBSan this is the test that would actually catch a
    // missing bounds check; without them it at least pins down that no
    // prefix produces a bogus "successful" parse.
    const auto full = ClientHelloBuilder()
                          .sessionId(16)
                          .cipherSuites({0x1301, 0x1302, 0xC02F})
                          .padExtension(0x000A, 6)
                          .sni("bmc.example.com")
                          .build();

    for (size_t len = 0; len < full.size(); len++) {
        const std::vector<unsigned char> prefix(full.begin(), full.begin() + len);
        xdp_event evt{};
        std::memset(&evt, 0, sizeof(evt));
        parse_client_hello_detail(&evt, prefix.data(), prefix.data() + prefix.size());

        // A partially-captured hostname must always come with the malformed
        // flag set, so a detector can't compare a prefix as if it were the
        // whole name (see parse_client_hello.h — this is a bypass guard,
        // and this loop is what caught it missing).
        if (evt.sni_present && std::string(evt.sni_hostname) != "bmc.example.com") {
            CHECK(evt.sni_malformed == 1);
        }
        CHECK(evt.cipher_suite_count <= HG_MAX_CIPHER_SUITES);
        CHECK(std::strlen(evt.sni_hostname) < HG_SNI_LEN);
    }
}
