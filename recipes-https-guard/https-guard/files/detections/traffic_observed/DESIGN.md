# Traffic observed

**Detects:** nothing. That is the point.
**Emits:** `OemSecurityEvent.1.0.HttpsTrafficObserved` (OK).
**Enforces:** no.

## Why a detection that always matches

Every hook's detection list ends with this one, and `DetectLoop` stops at the
first verdict — so it is what reports traffic that no rule flagged, without
`DetectLoop` needing a "nothing matched" branch, and without any *other* class
having to know both "run the rules" and "what if none fired".

That is the whole reason it exists as a list entry rather than as logic. The
alternative shapes were all worse:

- **A branch in `DetectLoop`** after the loop. But then the loop needs a TLS
  description to put in the message, which means knowing what the record was —
  exactly the knowledge the loop is built not to have.
- **A fallback inside each detection.** Then every detection has two jobs, and
  "no violation" and "definitely fine" stop being distinguishable.
- **Nothing at all.** Then clean traffic is invisible, and the only way to know
  what ordinary traffic looks like on a given BMC is to guess a threshold and
  watch for lockouts.

## What it reports

The process and PID from the shared envelope, plus the TLS version where the
source has one and `n/a` where it does not — a certificate file open has no TLS
version, and printing `0` would read like one.

Templated on the raw struct like any multi-hook detection, so `if constexpr` on
`HasTlsFields` decides which of those two it can say.

## Not a rule, and deliberately not in `detections/core/`

It has no `Detector` class and no event struct, because there is no question to
ask: there is nothing to detect in the absence of a detection. But it *is* an
`IDetection`, it appears in every hook's list, and it emits a documented message
ID — so it gets a detection's directory rather than sitting in `core/` as the
one concrete detection among the shared vocabulary.

## How to trigger it

Any clean HTTPS request. See
[README.md § Exercising the Detections](../../../../../README.md#exercising-the-detections).
