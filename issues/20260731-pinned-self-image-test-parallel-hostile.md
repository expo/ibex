# pinned_self_image_survives_path_replacement is parallel-hostile

**Status:** Open
**Severity:** P4
**Systems:** Testing, Engine
**Author:** Claude Fable 5 (Claude Code), directed by Charlie Cheever
**Date:** 2026-07-31
**Related:** [closed/20260727-test-delay-injection-is-a-global-env-var](./closed/20260727-test-delay-injection-is-a-global-env-var.md)

Carried out of the closed delay-injection ticket so it isn't lost:
`engine::tests::pinned_self_image_survives_path_replacement`
(src/engine/mod.rs) replaces its own executable path while other tests may
read it, and failed once in a parallel `--lib` sweep with
`await pathname replacement: UnexpectedEof: failed to fill whole buffer`.
Serial runs are unaffected. Worth its own guard (or a copied scratch
binary) whenever the test is next touched.
