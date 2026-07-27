# CapSec inherited-alias Hermes profile digest drift

Status: Resolved

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
