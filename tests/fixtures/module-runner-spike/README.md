# LLP 0026 bounded producer spike

This directory is fixture-only adoption evidence. The producer is compiled
only with Cargo's `module-runner-spike` feature; it does not select a runtime
evaluator, publish artifacts to a cache, or create an interim path-based module
identity.

Regenerate the 12 canonical artifacts:

```sh
cargo run --features module-runner-spike --example module_runner_spike -- \
  tests/fixtures/module-runner-spike/manifest.json \
  tests/fixtures/module-runner-spike/canonical-artifacts.json
```

Execute them on the actual engine:

```sh
node packages/ibex-devtools/src/scripts/run-module-runner-spike.mjs \
  --hermes /path/to/hermes
```

The test262 sample and its regeneration instructions are described in
`TEST262-NOTICE.md`. Its threshold was frozen at 18/20 before execution; the
checked macOS arm64 result is 19/20. The one failed case remains raw evidence,
not an expected divergence selected after the run.
