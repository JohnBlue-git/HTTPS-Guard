# 07 — Split programs/<hook>/DESIGN.md into detections/<family>/DESIGN.md

**What to build:** Rewrite the three per-hook design documents as per-detection
documents, so a reader asking "how does X detection work" does not need to know
which hook feeds it first.

**Blocked by:** 06 — the code should already be arranged the way the docs claim

**Status:** done

## Why this is a rewrite, not a move

The existing documents are organised around a mechanism and each covers several
detections; the new ones are organised around a detection and each may reference
several mechanisms. `programs/xdp_tls/DESIGN.md` alone covers ClientHello
parsing, cipher suites, SNI, the blocklist and the per-source counters — four
different detection families plus an enforcement path.

Some hook-specific material genuinely belongs to the hook and should stay:
the ARM32 trampoline gap, the native→generic→skip XDP attach fallback, the
`ssl_st.version` offset mechanics, why `SSL_read` needs a paired entry+return
uprobe. A short `programs/<hook>/DESIGN.md` covering *attachment* is the right
outcome, not deleting them outright.

- [x] One `DESIGN.md` per detection family, named for the detection
- [x] Attachment-specific material stays with its hook, and nothing is lost in the split — check the old documents for content with no new home before deleting anything
- [x] Every diagram still describes something that exists
- [x] Cross-links updated: root `CLAUDE.md`, `DESIGN.md`, `DESIGN.html`, `README.md`, and each `CLAUDE.md` that names a per-hook `DESIGN.md`
- [x] The verification status in `README.md` still maps to the right document

## Comments

Eight new `detections/<family>/DESIGN.md` — one per detection — and the three
hook documents trimmed to what they are actually about.

### What each family document covers

The same shape throughout, because a reader arriving at one of these has the
same questions: what it detects, which message ID it emits, whether it enforces,
why it matters on a BMC specifically, which sources feed it, the rule's exact
logic and thresholds, and its real limits. Each ends with a pointer to the
runnable trigger recipe in README rather than repeating it.

### What stayed with the hooks, and why that was the right split

The hook documents keep material that is genuinely about *attachment*, and it is
substantial: why `SSL_read` needs a paired entry+return uprobe while `SSL_write`
does not (its `buf` is an output parameter, uninitialised at entry); the
`ssl_st.version` offset mechanics and why CO-RE cannot resolve a userspace
struct; the native→generic→skip XDP fallback and the BPF-link ownership that
made the leak structurally impossible; the three attempts at an in-kernel
identity check and the ARM32 trampoline and kfunc gaps that defeated two of
them.

None of that belongs in a per-detection document, and deleting it to force the
split would have destroyed the most detailed material in the project. Each hook
document now opens with a pointer to the detections it feeds, and each keeps its
mechanism sections.

The one genuine overlap is `xdp_tls`'s per-source counters section. It describes
where the counters live and where they are incremented — hook mechanism — while
the three family documents describe what each rule does with them and how its
threshold was chosen. Cross-linked in both directions rather than trimmed,
because the two angles are both useful and neither is a copy of the other.

### Verification

Every relative link in all eleven documents resolves (checked
programmatically, not by eye), and the eight new files are in `SRC_URI` — 101
entries, all of which exist.
