# `LogAction` — the Redfish event

**What it does:** writes one JSON event per verdict to
`HTTPS_GUARD_EVENT_FILE`, which the event bridge tails and forwards to D-Bus and
the Redfish log directory for bmcweb's EventService to dispatch.

**When it runs:** for *every* verdict, including `OK`. That is not noise — the
only other way to know what ordinary traffic looks like on a given BMC is to
guess a threshold and watch for lockouts.

## The MessageId shape is not cosmetic

```
OemSecurityEvent.1.0.HttpsTlsVersionViolation
└─ registry ──┘ └maj┘└min┘ └──── message key ────┘
```

Exactly **four** dot-separated fields. bmcweb's
`registries::getMessageComponents()` requires that shape to resolve a message's
severity and text, and it does **not** accept a three-part semver patch digit —
`1.0.0` here silently fails to resolve, and the event arrives with a generic
borrowed severity instead of its own.

The registry itself is compiled into bmcweb by
`recipes-bmcweb/bmcweb/files/0001-add-oem-security-event-message-registry.patch`,
mirrored for documentation at `/redfish/v1/Registries/OemSecurityEvent.1.0.0/`.
So a real Redfish push for these IDs carries the real severity, not a fallback.

## `Id` and `EventId` come from the event's own timestamp

```json
{"Id":"116354254534","Events":[{"EventId":"116354254534-460", ...}]}
```

Both derive from `EventMeta::timestamp_ns`, and that is worth knowing because it
was broken for a long time: no parser copied `timestamp_ns` out of the raw
record, so every event's `Id` was `0` and every `EventId` was `0-<pid>`. Every
emitted Redfish event shared one `Id`, which is the one thing an `Id` is for. The
BPF side had been capturing it correctly the whole time. A regression test pins
it now.

The synthesised rate/Slowloris/renegotiation events had the *same* symptom for a
different reason: they have no BPF header to copy from, so `ConnRateSweeper` has
to stamp `timestamp_ns` itself. It reads `CLOCK_MONOTONIC` — deliberately the
same clock domain as `bpf_ktime_get_ns()` on the ring-buffer path — so ids from
the two paths share one clock and sort against each other; wall-clock here would
order these events randomly among the parsed ones. One reading is taken per
sweep and shared by every event that sweep synthesises, which is accurate: they
were all observed by that one walk.

## `AsyncFileStreamManager` — why file writes need a coroutine-aware lock

Several actions can be in flight at once, and more than one may target the same
file. A plain `std::mutex` is the wrong tool inside a coroutine: holding it
across a suspension point blocks the `io_context` thread that would otherwise be
making progress on someone else's I/O.

`async_mutex.hpp` therefore keeps, per filename, a `locked` flag and a deque of
`any_completion_handler<void()>` waiters, plus a cache of open
`asio::posix::stream_descriptor`s. A second writer to the same file suspends and
is resumed when the first releases — the thread is never blocked, only the
coroutine is.

The stream cache also means the common case (many events, one log file) opens the
file once rather than per event.

## What it will not do

Decide anything. The severity, the message ID and the message text all arrive in
the `Verdict`; this action formats and writes. `RedfishEventMessage` keeps only
the two scalars it formats (`timestamp_ns`, `pid`) rather than a whole event, so
it is usable by every detection without knowing any of their types.
