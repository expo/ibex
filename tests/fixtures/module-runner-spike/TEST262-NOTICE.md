# test262 subset notice

`test262-subset.json` contains executable bodies derived from 20 files in
[`tc39/test262`](https://github.com/tc39/test262) at commit
`f2d1435644797268dca1f7988cad5a4e89ccd8d2`. Each entry records the complete
upstream file's SHA-256 as well as the extracted body's SHA-256. The upstream
files state that they are governed by test262's BSD license; the canonical
license text remains at `LICENSE` in that repository and commit.

Regenerate only from a detached checkout at the pinned commit:

```sh
node packages/ibex-devtools/src/scripts/generate-module-runner-test262-subset.mjs \
  /path/to/test262 tests/fixtures/module-runner-spike/test262-subset.json
```

Regenerate its factories with the explicit fixture-only Cargo feature:

```sh
cargo run --features module-runner-spike --example module_runner_test262_spike -- \
  tests/fixtures/module-runner-spike/test262-subset.json \
  tests/fixtures/module-runner-spike/test262-artifacts.json
```
