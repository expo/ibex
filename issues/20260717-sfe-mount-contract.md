# Compiled mount contract: /app, /work, unset cwd (LLP 0023 revision)

**Status:** In Progress
**Severity:** P2
**Systems:** Runtime, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §4, LLP 0023
**Depends-on:** llp0014-canonical-policy-v2

An explicit LLP 0023 revision in the same change (its rule for new
mounts), adding `LogicalRoot::App`/`Work` vocabulary: `/app` is a
module/diagnostic namespace only in v1 — **no filesystem-visible
embedded assets**; every fs operation against it fails with a distinct
stable error. `/work` mounts the launch directory only when the
embedded policy grants it (authenticated directory object); absent
`/work`, virtual cwd is **unset** — relative paths and `chdir` fail
with the policy's stable denial, `process.cwd()` returns the defined
sentinel. Project-rooted grants are a compile-time error; the
generator's compiled-target mode emits `/app`//`/work`/absolute
resources.

**Done when:** LLP 0023 revised; denial + relocation fixtures pass;
phase-3 evidence gathered on whether the unset-cwd sentinel breaks
real Node-compat libraries (registered open question).

## Progress — 2026-07-17

LLP 0023 now defines the `compiled-app-work-v1` profile: typed `app`/`work`
logical roots, metadata-only `/app`, optional authenticated `/work`, the exact
`ibex:cwd:unset` view, and stable `ERR_IBEX_COMPILED_APP_NOT_FILESYSTEM` /
`ERR_IBEX_COMPILED_CWD_UNSET` failures. The product-neutral CapSec resolver
implements lexical containment without consulting an OS cwd or build tree.
Strict Rust ingestion and JavaScript authoring require target/mount-profile
coherence and reject project/package/home/tmp-rooted compiled authorities.
Schema/digest artifacts were regenerated; focused Rust and JavaScript tests are
green, the complete CapSec semantics suite passes, and the signed phase-0 SFE
pack/sign/relocation smoke still boots under the stricter compiled-policy ingest.

Runtime `process.cwd`/`chdir`/filesystem adapter integration, authenticated
launch-directory binding, relocation fixtures, and Node-compat sentinel evidence
remain. The issue stays in progress; the implementation deliberately does not
choose decision-register item 1's implicit-vs-policy-authored default.
