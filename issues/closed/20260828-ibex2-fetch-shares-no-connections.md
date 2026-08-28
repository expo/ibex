# ibex2 `fetch` builds a new NSURLSession per request, so no connection is ever reused

**Status:** Closed
**Resolved:** 2026-08-28
**Impact:** 3
**Urgency:** 2
**Ease:** 4
**Confidence:** 5
**Severity:** P3
**Systems:** Runtime, Transport
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-28
**Related:** LLP 0057 §3, LLP 0059.000 §3.5

`ibex2_darwin_http_send` (`crates/ibex2/src/engine/darwin_http.mm`) constructs a
fresh `ephemeralSessionConfiguration` + `NSURLSession` for every request and
calls `finishTasksAndInvalidate` at the end. Ephemeral is deliberate and should
stay — a shared cookie jar would be ambient authority arriving through the back
door. Per-*request* is the accident.

The cost is a full TLS handshake on every call. Measured against
`https://example.com/` on 2026-08-28, release build:

| shape | 1st | 2nd | 3rd |
|---|---|---|---|
| new ephemeral session per request (today) | 144ms | 79ms | 76ms |
| one shared session, reused | 107ms | ~1ms | ~1ms |

So roughly 80ms of avoidable latency per request after the first, which a
chatty application pays on every call.

The fix keeps the isolation property: hold **one** ephemeral `NSURLSession` per
runtime (not per process, so two runtimes still share no cookie or connection
state) and reuse it. The `Ibex2NoRedirect` delegate is stateless and can be
shared with it.

**Done when:** a second `fetch` to an origin already contacted by the same
runtime completes without a new TLS handshake, and a test asserts two runtimes
do not share a session.

## Resolution (2026-08-28)

`DarwinTransport` now owns one `NSURLSession` for the life of the runtime.
`RuntimeState` already held exactly one transport per runtime, so this was the
lifetime the session wanted all along — no plumbing was needed to get it.

`ibex2_darwin_session_create` / `_destroy` bracket it; `ibex2_darwin_http_send`
takes the session rather than building one. Ephemeral is unchanged, so two
runtimes still share no cookie, cache, or connection state.

Measured, release build, five sequential requests to the same origin:

| | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| before | 144ms | 79ms | 76ms | ~80ms | ~80ms |
| after | 105ms | 30ms | 26ms | 29ms | 32ms |

**An earlier version of this ticket claimed ~1ms**, which was wrong and
flattering. Those numbers were `NSURLCache` answering from memory without any
connection at all — the session inherited an in-memory response cache along
with the cookie jar (see the follow-up below). With the cache disabled, the
honest win is a full TLS handshake avoided: ~80ms to ~30ms.

Two tests, in `crates/ibex2/src/transport/darwin.rs`:

- `each_transport_owns_its_own_session` — two transports get distinct sessions,
  which is the isolation half and needs no network.
- `a_second_request_to_one_origin_reuses_the_connection` — asserts
  `NSURLSessionTaskMetrics.reusedConnection` directly. It does **not** time
  anything: the first version required a repeat under 40ms and passed because
  the URL cache was answering it, then failed on a working pool whenever the
  network was slow (64ms observed). Latency cannot separate a pooled request
  from a fast handshake; the platform will simply say which happened.

Both were mutation-tested: restoring a session per request fails the reuse
test, and removing the cookie configuration fails the state test.

## Follow-up found during review (fixed here)

A shared session is what makes the platform's **in-memory cookie jar and URL
cache** live — with a session per request they were destroyed each time, so
this change created the exposure. `ephemeralSessionConfiguration` means "not on
disk", not "no state".

Cookies are ambient authority the grant check cannot see: `net.fetch` is
per-origin, cookies are RFC 6265 domain-scoped, so a module granted
`evil.example.com` could set a cookie for `example.com` that the platform then
attaches to another module's request to `app.example.com`. v1 has no
credentials mode (LLP 0059.000 §3.5), so the correct number of cookies is zero.
Ibex 1 already did this (`src/engine/native_fetch_macos.mm`); Ibex 2 did not.

Now set: `HTTPCookieAcceptPolicy = Never`, `HTTPCookieStorage = nil`,
`HTTPShouldSetCookies = NO`, `URLCache = nil`, and
`requestCachePolicy = ReloadIgnoringLocalCacheData`.
`the_session_keeps_no_cookies_and_no_cache` asserts it against the live session
configuration rather than trusting the comment — the previous comment claimed
"no cookie jar, no disk cache" while the session had both in memory.

LLP 0059.000 §3.5 now records the scoping decision (runtime, not process or
request) rather than leaving it implicit in the code.
