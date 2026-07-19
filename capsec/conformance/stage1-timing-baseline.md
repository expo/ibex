# LLP 0032 Stage 1 timing baseline

This note records the evidence available before bounded command execution
lands. It is diagnostic planning input, not CapSec promotion evidence.

## Available baseline

GitHub Actions run `29686446506` executed commit `3cdb20b0` on 2026-07-19.
The macOS job spent about 21 minutes in setup and a cache-miss Hermes build,
then the monolithic CapSec step ran for about 142 minutes before failing; its
artifact upload completed in about three seconds. The Windows job spent about
28 minutes installing the reviewed Hermes artifact, then rejected the suite in
about three seconds, so that attempt supplies no representative Windows suite
duration.

The old runner retained no per-command duration field. These workflow-level
measurements therefore cannot justify learned deadlines or a sharding choice.
The initial ceilings in `suite-plan.json` are containment limits chosen so the
complete authored critical path plus setup and cleanup/upload reserves fits the
360-minute workflow boundary, including the largest single command-cleanup
grace period. They are not performance targets.

## Stage 2 decision

Stage 2 remains deferred. First collect successful Stage 1 outcome artifacts
from both current targets, including every command's monotonic `elapsedMs` and
classification. Revisit resumable phases only after the retained results show
which late commands dominate elapsed time and how often bounded retries would
avoid meaningful repeated work. Stage 3 sharding is not part of this rollout.
