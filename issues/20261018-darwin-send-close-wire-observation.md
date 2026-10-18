# Darwin send/close test sometimes observes disconnect before the close frame

**Status:** Open
**Systems:** Transport, Tests
**Author:** Charlie Cheever / Codex
**Date:** 2026-10-18

During the additional standalone vendored-Ibex suite at Exact
`11598b648e4883522d9141647aee7cda0f6ced7c` (Ibex `bbf47f3`),
`concurrent_send_and_close_submit_to_the_platform_in_admission_order` passed
its native admission-order assertion and observed `/echo message 1 6`, then
received `/echo gone` instead of `/echo close 1000 `. The suite reported
310 passing tests, this failure, and an independent headless-keychain failure.

The command on the Mac Studio was:

```text
cargo test --manifest-path vendor/ibex/crates/ibex2/Cargo.toml --locked --offline --lib --tests --no-fail-fast
```

Focused execution of the same send/close test subsequently passed on both
the pre-refresh Exact baseline `a28fc4f18` and merged candidate `c7ccaf5d`.
This did not reproduce a refresh regression, and does not establish why the
full-suite run lost the final close-frame observation. The required Exact
checks passed on both refreshed revisions; the upstream Mac adoption suite
also passed. Preserve the original failure rather than counting the
additional full suite as green. Logs and baseline/candidate commands are in
local ship record `20261018-upstream-followup`.

Follow-up should distinguish NSURLSession close delivery from test peer or
suite scheduling behavior. Retain the admission-order witness. Do not weaken
the close-frame expectation without establishing which contract it tests
and reproducing the relevant boundary.
