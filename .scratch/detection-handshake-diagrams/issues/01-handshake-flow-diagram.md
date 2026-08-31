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

**Status:** ready-for-agent

- [ ] One shared ASCII diagram of the TCP handshake + TLS record sequence is authored, matching the ASCII-diagram style already used elsewhere in these files
- [ ] The diagram is added to `detections/tls_version/DESIGN.md` with a marker showing where the XDP pre-handshake-completion check and the uprobe post-negotiation check each sit
- [ ] The diagram is added to `detections/sni/DESIGN.md` with a marker at the ClientHello/SNI-extension point
- [ ] The diagram is added to `detections/cipher_suite/DESIGN.md` with a marker at the ClientHello/cipher-suite-list point
- [ ] The diagram is added to `detections/conn_rate/DESIGN.md` with a marker showing the counter is keyed to the TCP SYN, independent of TLS content
- [ ] The diagram is added to `detections/slowloris/DESIGN.md` with a marker showing the standing-level counter spans the whole connection lifetime, not one handshake stage
- [ ] The diagram is added to `detections/renegotiation/DESIGN.md` with a marker at the post-handshake handshake-record (renegotiation) point
- [ ] The diagram is added to `detections/payload_anomaly/DESIGN.md` with a marker at the `SSL_write`/`SSL_read` library-call boundary, positioned relative to the same handshake sequence
- [ ] `detections/cert_access/DESIGN.md` and `detections/traffic_observed/DESIGN.md` are left unmodified
- [ ] Each addition sits alongside that file's existing "why/how to detect" content without rewriting the surrounding prose
