# Capsec generator/model update before engine deletion

**Status:** Open
**Severity:** P2
**Systems:** Security, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4c
**Depends-on:** oxc-window-close

The inventory generator discovers transform engines via
`TransformEngine::Variant` token references and errors when none exist;
the authored coverage model names the `transpile_with_swc` routes.
Update discovery to the Oxc-only shape and the authored
route/classifier inventories BEFORE the enum deletion, then regenerate
the complete catalog (Rust, C++, JS/TS, registry, schema, docs — not
just `capsec_registry_generated.rs`).

**Done when:** `bun run check:capsec-registry` green on the regenerated
catalog; the ten `surface.loader.*.swc.*` IDs are gone from the
inventory (the auditable removal record).
