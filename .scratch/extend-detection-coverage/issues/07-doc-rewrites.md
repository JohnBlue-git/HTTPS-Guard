# 07 — Documentation rewrite for the extended detection coverage

**What to build:** Once the five detection-capability tickets have landed, bring every doc back in line with what actually exists — the same kind of pass done for the `programs`/`detectors`/`actions` split, now covering the new hook(s) and detectors this spec added.

**Blocked by:** 02 — SSL_read mirror; 03 — BPF-LSM certificate-access guard; 04 — Cipher-suite and SNI detection; 05 — Connection-rate detection; 06 — Slowloris and renegotiation-storm detection

**Status:** ready-for-agent

- [ ] `DESIGN.md` describes every hook and detector that now exists, not just `ssl_uprobe`/`xdp_tls` and the two original detectors
- [ ] `programs/lsm_cert_guard/DESIGN.md` and `CLAUDE.md` exist, written to the same depth and shape as `programs/ssl_uprobe/DESIGN.md` (why detect this, how it works with diagrams, what's hooked, known limitations)
- [ ] `programs/xdp_tls/DESIGN.md` is updated to cover cipher-suite/SNI parsing and connection-rate tracking, since both extend that hook rather than introducing a new one
- [ ] Whatever new detector directories exist under `detectors/` (cert-access, cipher-suite, SNI, connection-rate, Slowloris, renegotiation-storm, or however the implementers of tickets 03-06 actually structured them) each get the same "why/how/limitations" treatment `detectors/CLAUDE.md` already gives the first two
- [ ] `DESIGN.html` is regenerated to match — it currently predates even the `programs`/`detectors`/`actions` split, not just this spec's additions
- [ ] `README.md`'s component-roles table and architecture diagram reflect the final hook/detector list
- [ ] The stateful-detector architecture decision from ticket 06 is documented somewhere durable (`detectors/CLAUDE.md` or a dedicated note), not left implicit in that ticket's own comments
- [ ] A pass confirms no doc still describes the system as having only two hooks or two detectors
