#pragma once

#include <cstddef>
#include <type_traits>

namespace https_guard {

/*
 * What a raw record happens to carry.
 *
 * Several detections apply to more than one hook, and the raw layouts differ in
 * what they can supply — an XDP record has a connection tuple and a line-rate
 * violation hint, a uprobe record has neither. These let one templated detection
 * read what is there without a specialisation per hook, and without a member
 * that is meaningless for half its instantiations.
 *
 * Duck-typed on purpose: the nested-struct ABI already gives every hook the same
 * *shape* where they overlap (`raw.tls.version`, `raw.hdr.pid`), so asking
 * whether a member exists is both sufficient and the only thing being asked.
 */

template <class RawT>
concept HasConnectionTuple = requires(const RawT& r) { r.conn; };

template <class RawT>
concept HasTlsFields = requires(const RawT& r) { r.tls.version; };

template <class RawT>
concept HasViolationHint = requires(const RawT& r) { r.tls.is_violation; };

template <class RawT>
concept HasPayloadSnippet = requires(const RawT& r) { r.tls.payload_snippet; };

template <class RawT>
concept HasClientHello = requires(const RawT& r) { r.client_hello; };

}  // namespace https_guard
