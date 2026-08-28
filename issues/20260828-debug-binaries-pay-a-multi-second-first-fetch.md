# A debug ibex2 binary pays 3-9s on its first fetch, and it is dyld, not us

**Status:** Open
**Impact:** 2
**Urgency:** 2
**Ease:** 3
**Confidence:** 5
**Severity:** P3
**Systems:** Build, Testing, Transport
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-28
**Related:** LLP 0063 (where startup time goes)

Recorded because it cost real time to chase and it looks exactly like a
runtime bug until you measure it.

The **first** `[NSURLSessionConfiguration ephemeralSessionConfiguration]` in a
debug `ibex2` test binary takes **2.9-5.8s**, and up to ~9s under load. Every
subsequent call in that process takes 0ms, and the requests themselves are
~80-110ms throughout.

It is not ours, and it is not the network:

- `curl https://example.com/` — 129ms.
- A standalone Objective-C control doing the identical calls — `config=5ms`.
- Moving the call to a spawned pthread — still 5ms.
- Running it **before** any Hermes runtime exists — still 3-7s, so the engine,
  the harden step, and the loader are all uninvolved.
- Same binary, three consecutive processes — 3.6s, 4.4s, 3.9s. Not a one-time
  Gatekeeper scan.
- **Release build of the same code — `config=2ms`.**

`DYLD_PRINT_LIBRARIES=1` shows the stall is dyld promoting the network stack's
delayed images (`NetworkExtension`, `CryptoKit`, `OctagonTrust`, `IO80211`,
`EAP8021X`, ...) to loaded. Both the control and our binary load the same 884
dylibs; the control does it in 5ms. The difference is the main executable dyld
must resolve them against: 34MB unstripped with a debug symbol table, versus
8.9MB in release.

Two consequences:

1. **No product bug.** Shipping builds are release builds and pay 2ms.
2. **Test budgets must clear the tax.** `tests/loader.rs` ran a live-network
   capability assertion under a 10s quiescence budget; the tax ate it and the
   test failed for a reason unrelated to what it asserts. Raised to 45s, which
   costs nothing when quiescence returns early.

The residual risk is that this masks a *real* regression in first-fetch latency,
since 3s and 9s look alike. Worth either stripping debug test binaries or
asserting first-fetch cost in a release-mode test.

**Done when:** first-fetch latency is asserted somewhere that a regression in it
would fail, rather than being absorbed by a budget sized for dyld.
