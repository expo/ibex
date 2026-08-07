# Runtime cache cannot be materialized in a filesystem sandbox

**Status:** Closed
**Severity:** P2
**Systems:** CLI, Cache, Security
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-08-04
**Resolved:** 2026-08-04
**Related:** LLP 0023 §1; `issues/closed/20260804-run-posture-v1-advertisement-refusal.md`

## Problem

`ibex run` and `ibex build` selected the platform user-cache directory with no
operator override. Managed filesystem sandboxes that allowed the project and a
private temporary directory but denied the home cache failed before execution
while materializing protected CapSec artifacts or the bundle cache.

This was independent of the intentional v1 target-advertisement refusal.

## Resolution

The root CLI now accepts `--runtime-cache-dir <absolute-path>`. Ibex captures
that trusted selection before execution, reuses it for the process lifetime,
canonicalizes it after creation, and authenticates it as disjoint from the
project/package backing roots under LLP 0023. Relative paths and later attempts
to change the selection fail closed. The cache remains runtime-private and is
not exposed as a JavaScript mount.

The README includes the sandbox invocation. The platform cache remains the
default when no override is supplied.

## Verification

- CLI surface/help contract test covers the new authored option.
- Runtime tests retain cache/project overlap refusal.
- A sandbox-style smoke uses a private absolute temporary cache and reaches
  the expected target-advertisement gate instead of failing cache creation.
