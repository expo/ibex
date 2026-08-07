# Apple complete native shard reconciliation

**Status:** Resolved

After the `process.cwd` install identity was reconciled, the complete physical
Apple public shards reached several older contradictions hidden by focused
catalog slices:

- retained POSIX scalar/vector reads were attributed to the wrong terminal;
- descriptor `readFileAsync` omitted its own worker terminal;
- the portable append-open write fixture used a positional offset whose
  behavior differs between Darwin and Linux;
- static linkage eagerly demanded a target for a call-time-deferred literal
  dynamic import;
- a CommonJS call-time provider discarded the successful synchronous-ESM
  admission result at the native binding boundary; and
- the closed native filesystem denial allowlist omitted the already-authored
  `__exactFsReadFileAsync` global.

## Resolution

Evidence validation now distinguishes source-selected POSIX retained-open and
worker terminals from Windows typed edges. The portable fixture uses the
current-position sentinel. Deferred sources do not enumerate dynamic targets
during static linkage, and provider-returned ESM bindings preserve the
synchronous-eligibility result that the Rust provider proved before
publication. Focused regressions cover every boundary.

The physical M4 verifier passed 281 primary and 313 secondary fixtures with
zero failures. Both artifacts bind catalog digest
`sha256-egBjY2PSRxWBdGqh8Cib0Zau9Miin4QnnjD4Mh_y6LQ` and engine digest
`sha256-afSytE7VsUfboE9brsH6q0m7LA-KNYrghjCVYL05-yQ`. Cross-shard validation
accepted all 594 executions and produced aggregate digest
`sha256-pjKQVJY9H5oqPUfAd-3At7dYhftHksIn1291nfpP3ms`.
