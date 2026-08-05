# CapSec inherited-alias Hermes profile digest drift

**Status:** Resolved

The inherited-intrinsic alias account still pinned a profile-review digest from
before the reviewed 12-patch Hermes profile was composed. Live source
discovery therefore failed closed even though the primary evaluator review,
lockdown digest, target branches, and reachable evaluator family were already
current.

## Resolution

Reviewed the exact live profiles and patch 0012. The patch adds a private
WebGPU ArrayBuffer alias/detach interface and keyed backing-store mechanics; it
does not add an evaluator, alter evaluator reachability, or reopen lockdown.
The source inventory still proves exactly `eval`, `Function`,
`AsyncFunction`, and `GeneratorFunction` across the three reviewed target
profiles. Updated the independent inherited-alias profile pin to
`sha256-76318d287e6d33e65b0f84d18fb91eda561a0e9caf432d1fb74c744964090de1`.
That profile rotation composes with the unchanged source-family review as
source-review digest
`sha256-ba4087b5a24f8b7dcd8f4729b416acb3a67687552d37718c1638707e2df1c481`.
The focused inherited-alias account and all 114 surface-inventory tests pass.

The subsequent replay onto `origin/main` `e4e9bca9` intentionally changed the
Linux build-authority bytes again: the builder now publishes the matching
Hermes VM CLI beside `hermesc`, and the downloader requires their HBC versions
to agree before installation. This is a compiler/runtime compatibility proof,
not a new evaluator path. The exact Linux build-authority digest is now
`sha256-af521ddda077302b82de42a024eba5e708b9072462d2c4e53c742d8cc473ea92`,
the composed three-profile digest is
`sha256-84af49ed9d745b080078dead37e62a5dfd3be2747f567c61040fbe3b4cba6cf0`,
the composed inherited-alias source-review digest is
`sha256-f71b13a426100133131621663461e41e28159c119ef1bffd8ea53802003aae96`,
and the reviewed evaluator identity is
`hermes-evaluators.3e6954de6300cf7cbd32f27af9077c4a0a55dc951e106a44a991791846e9971f`.
