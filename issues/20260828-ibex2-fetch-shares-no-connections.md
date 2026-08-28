# ibex2 `fetch` builds a new NSURLSession per request, so no connection is ever reused

**Status:** Open
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
