# Historical issues predate the cdcstack header format

**Status:** Open
**Systems:** Tooling, Process
**Severity:** P3
**Author:** Charlie Cheever
**Date:** 2026-08-27

`node scripts/issue.mjs check --fix` repaired what it could mechanically. 73 problems remain across the pre-cdcstack backlog — mostly missing **Author:**, **Systems:**, and **Resolution:** on issues closed before the format was adopted. `--fix` deliberately will not invent a resolution, and neither should anyone else. Burn these down by hand or grandfather them explicitly; do not let the check sit red.
