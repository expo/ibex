# Embedded admission, pinned-fd self-file, disk-free arming

**Status:** Open
**Impact:** 5
**Urgency:** 5
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Embedded admission, pinned-fd self-file, disk-free arming” shows the issue reaches a security, correctness, release, or core product boundary; the defect is blocking or unsafe on a live path now, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
**Severity:** P2
**Systems:** Security, Module Loader, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §3/§4
**Depends-on:** sfe-embedded-module-graph, sfe-graph-snapshot-domain, sfe-root-ceiling-and-bootstrap, sfe-mount-contract

Boot acquires one pinned fd/handle proven to be the object backing the
mapped stub (the engine loader's dev/inode mapped-image identity check
is the model); footer parsing, hashing, and section admission read only
from it (pathname reopen of `current_exe` can race replacement and is
forbidden). Arming consumes embedded sections through a new embedded
protected-artifact identity — (mapped executable object, authenticated
byte range, section role, digest) — an LLP 0021/arming revision (today's
protected artifacts require host path + fs object identity). Disk-free
arming binds embedded graph, policy, compiled-in engine identity,
registry projection, mounts, and protected sections with fresh
run/channel nonces; carriers bind the stub contract's engine identity
via the versioned/tagged LLP 0027 engine-binding field (loaded-file vs
static-compatibility identities cannot be confused).

**Done when:** relocation test (incl. carrier bytes) + authority-denial
+ bootstrap/application split + wrong-engine/wrong-version fixtures all
pass on both v1 tuples with no filesystem or network reads at boot.

## Progress — 2026-07-17

Compiled boot no longer calls `current_exe` or reads through a reopened path.
The shared native helper returns one descriptor only after comparing its
device/inode to the mapped executable object (Linux: `/proc/self/exe` plus the
routine's `/proc/self/maps` mapping; macOS: dyld main header plus
`proc_pidinfo` vnode). Every image byte and the post-read size check use that
descriptor. A subprocess test pins the copied test image, replaces its
pathname with a different object, and still authenticates the original bytes;
the signed macOS relocation smoke is also green. Arming ABI v2 now accepts
strict embedded protected artifacts bound to mapped executable object, exact
range, role, and content digest. Host and embedded facts must fill protected
roles exactly once; embedded ranges cannot overlap, and several ranges sharing
one executable collapse to one filesystem write guard. Rust and JavaScript
validators plus mismatch fixtures are green. Release compiled-Host
construction, authority-denial/bootstrap split, and the two-target fixture
matrix remain.

## Progress — 2026-07-18 (release preflight boundary)

Release boot now authenticates and cross-binds provenance, policy, graph,
carriers, and the static engine compatibility identity before any application
evaluation. It cannot enter the diagnostic runtime after release provenance is
recognized. The remaining work is the embedded authority snapshot and compiled
Host construction, followed by authority-denial/bootstrap split fixtures on
both release tuples; those steps depend on the unresolved LLP 0029 author
decisions governing environment authority and the first target advertisement.

## Remaining (verified 2026-07-31)

- DONE: pinned-fd self-image acquisition with native identity proof and
  replacement/relocation subprocess test; embedded protected-artifact
  identity + LLP 0021 arming-ABI revision; stub-level wrong-engine/
  wrong-version refusals.
- Disk-free arming is NOT started: the stub validates the embedded
  policy but never arms (`install_host(Host::strict())`, no nonce, no
  authority snapshot); the release path fail-closes before evaluation.
- No authority-denial or bootstrap/application-split fixtures exist for
  the compiled path; no two-tuple fixture matrix; no CI job; no
  syscall-level proof of "no fs/network reads at boot" (plausible but
  untested; dev stub still rpath-links Hermes dynamically).
- Stale claim: the Progress text says remaining steps await the
  first-target-advertisement decision — register item 4 was re-resolved
  2026-07-29 (v1 ships fail-closed); only register item 2 (env
  allowlist) still blocks.

## LLP 0047 reconciliation — 2026-08-01

Milestone 2 splits the remaining work without splitting admission. Both boot
modes must use this ticket's existing self-file, envelope, graph, policy, and
carrier preflight. Ambient boot then constructs the enforcement-off compiled
Host and may ship without target evidence. Disk-free `ArmedSnapshot`
construction, authority denial, and bootstrap/application split remain the
CapSec-selected path; missing advertisement must refuse before entry and may
never retry ambient. Successful production CapSec admission is v1.1, while a
fixture-only advertised build is still required to prove milestone 2 dispatch.
