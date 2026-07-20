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

A contemporaneous main-branch run, `29705554965` at commit `a083666e`, adds
failure-path context but not a complete-suite baseline. Its macOS cache-miss
setup and Hermes build took about 19 minutes before the suite stopped after
about 92 seconds on the already-stale runtime-environment inventory. Its
Windows setup and Hermes install took about 27 minutes before the old
synchronous runner stopped after about three seconds because it could not
resolve `bun` as a child executable. These are predecessor failures, not
Stage 1 command-duration measurements.

Stage 1 branch run `29706646383` at commit `52b2095b` produced and uploaded
the new outcome, live-status, outer-budget, and secured-log artifacts on both
targets. The macOS outcome retained four preflight attempts: registry drift
17.233 seconds, contract drift 6.786 seconds, generated-policy drift 20.309
seconds, and the existing failing all-generated drift 27.850 seconds. The
Windows Job Object gate passed its synthetic parent/grandchild timeout test;
the full runner then retained a four-millisecond failed launch which exposed
case-sensitive construction of a case-insensitive Windows `Path` environment
key. The loader-environment fix following that run preserves the runner's
existing key and rejects duplicate case variants. This remains failure-path
evidence, not a complete-suite timing sample.

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
