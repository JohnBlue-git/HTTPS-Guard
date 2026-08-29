# ssl_uprobe/ — PRIMARY hook

Uprobes on OpenSSL's `SSL_write()` *and* `SSL_read()` in `libssl.so` — fire for *every* process on the system that calls either, not just bmcweb. Captures the negotiated TLS version and a snippet of the plaintext being sent (`SSL_write`) or received (`SSL_read`), tagged with a `direction`; resolves the calling PID to a TCP socket via `/proc/<pid>/net/tcp` since uprobe context has no direct socket access.

**Read `DESIGN.md` in this directory before touching this hook's logic** — it covers why these specific functions are hooked, why `SSL_read` needs a paired entry+return uprobe while `SSL_write` doesn't, the exact byte-level mechanics of reading `ssl->version`, the full detect→classify→enforce flow with diagrams, and the one known gap worth understanding before extending it further: process identity isn't verified (comm is spoofable) — see `programs/lsm_cert_guard/` for the stronger mechanism aimed at a related but distinct question.

`SslUprobeProgram.{hpp,cpp}` implements `IHookModule` (see `../CLAUDE.md`); `ssl_uprobe.bpf.h` / `ssl_uprobe_event.h` are the BPF-side programs (write: entry-only; read: entry+return pair) and their shared raw event struct; `parse_uprobe_event.hpp` is the libbpf-free field-mapping logic (unit-tested in `../../tests/test_uprobe_parsing.cpp`); `proc_peer_resolver.hpp` is the PID→socket lookup used only by this hook.
