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
| after | 133ms | 3ms | 2ms | 4ms | 1ms |

Two tests, in `crates/ibex2/src/transport/darwin.rs`:

- `each_transport_owns_its_own_session` — two transports get distinct sessions,
  which is the isolation half and needs no network.
- `a_second_request_to_one_origin_reuses_the_connection` — a repeat request
  must land under 40ms, a threshold well below handshake cost and well above
  reuse cost. It skips rather than fails without a network, since there is
  nothing to say about reuse then.

The reuse test was mutation-tested: restoring a session per request fails it.

LLP 0059.000 §3.5 now records the scoping decision (runtime, not process or
request) rather than leaving it implicit in the code.
