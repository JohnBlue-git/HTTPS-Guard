# 01 — Shared TCP/TLS handshake-flow diagram across network-facing detection docs

**What to build:** one canonical ASCII diagram of the TCP three-way handshake followed
by the TLS record sequence (SYN → SYN-ACK → ACK → ClientHello → ServerHello → ... →
Finished → application data), reproduced — with a per-detection "you are here" marker —
into the `DESIGN.md` of `tls_version`, `sni`, `cipher_suite`, `conn_rate`, `slowloris`,
`renegotiation`, and `payload_anomaly`. This follows the existing convention in this
tree (e.g. `sni`/`cipher_suite` already share diagram text verbatim) of repeating
shared diagram text per file for standalone readability, rather than centralizing it in
one place. `cert_access` (a file-open detection, unrelated to the wire handshake) and
`traffic_observed` (the always-matching terminal catch-all) are intentionally not
touched.

**Blocked by:** None — can start immediately, independent of `detectloop-async-fanout`.

**Status:** done

- [x] One shared ASCII diagram of the TCP handshake + TLS record sequence is authored, matching the ASCII-diagram style already used elsewhere in these files
- [x] The diagram is added to `detections/tls_version/DESIGN.md` with a marker showing where the XDP pre-handshake-completion check and the uprobe post-negotiation check each sit
- [x] The diagram is added to `detections/sni/DESIGN.md` with a marker at the ClientHello/SNI-extension point
- [x] The diagram is added to `detections/cipher_suite/DESIGN.md` with a marker at the ClientHello/cipher-suite-list point
- [x] The diagram is added to `detections/conn_rate/DESIGN.md` with a marker showing the counter is keyed to the TCP SYN, independent of TLS content
- [x] The diagram is added to `detections/slowloris/DESIGN.md` with a marker showing the standing-level counter spans the whole connection lifetime, not one handshake stage
- [x] The diagram is added to `detections/renegotiation/DESIGN.md` with a marker at the post-handshake handshake-record (renegotiation) point
- [x] The diagram is added to `detections/payload_anomaly/DESIGN.md` with a marker at the `SSL_write`/`SSL_read` library-call boundary, positioned relative to the same handshake sequence
- [x] `detections/cert_access/DESIGN.md` and `detections/traffic_observed/DESIGN.md` are left unmodified
- [x] Each addition sits alongside that file's existing "why/how to detect" content without rewriting the surrounding prose

## Comments

Status was stale — this had already shipped. `conn_rate`, `slowloris` and `renegotiation` don't have separate `DESIGN.md` files any more (a later refactor consolidated them into one `detections/rate_sweep/DESIGN.md`, predating this status check but postdating this ticket's text), and that file carries all three markers this ticket asked for. `tls_version`, `sni`, `cipher_suite` and `payload_anomaly` each carry their own marker as specified. `cert_access/DESIGN.md` and `traffic_observed/DESIGN.md` were confirmed to have no handshake-diagram content.
