#!/usr/bin/env bash
# The named milestone-0 gate for the product-neutral SFE contracts, compiled
# stub, and catalog-to-HBC recipe. Run only after installing the host's patched
# Hermes toolchain; the final leg executes real catalog-produced HBC.
# @ref LLP 0047#3-milestone-0--restore-a-green-foundation
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash -n scripts/build-sfe-diagnostic-factory-table.sh
bash scripts/hermes-static-archive-normalization.test.sh
bash scripts/test-sfe-reproducibility.sh
cargo test --package ibex-sfe-format
cargo test --package ibex-sfe-catalog --all-targets
cargo test --package ibex-compiled-stub
cargo test --features sfe-dev-spike --bin ibex-sfe-dev-pack
cargo build --package ibex-compiled-stub
bun test packages/ibex-devtools/src/scripts/sfe-performance.test.mjs

# Exercise CapSec selection in a fresh process. The raw stub has no envelope,
# so a healthy early sanitizer reaches platform image/envelope admission; an
# environment/preinit refusal here catches loader-specific ordering regressions
# first.
stub_probe_stdout="$(mktemp -t ibex-sfe-stub-probe-stdout.XXXXXX)"
stub_probe_stderr="$(mktemp -t ibex-sfe-stub-probe-stderr.XXXXXX)"
cleanup_stub_probe() {
  rm -f "$stub_probe_stdout" "$stub_probe_stderr"
}
trap cleanup_stub_probe EXIT INT TERM
set +e
target/debug/ibex-compiled-stub --ibex-capsec >"$stub_probe_stdout" 2>"$stub_probe_stderr"
stub_probe_status=$?
set -e
if [[ "$stub_probe_status" -ne 1 ]] || [[ -s "$stub_probe_stdout" ]] ||
  ! grep -Eq 'SFE001 footer is absent or malformed|signed Mach-O has no __IBEX payload' "$stub_probe_stderr"; then
  echo "compiled-stub CapSec preinit probe did not reach envelope admission" >&2
  sed -n '1,20p' "$stub_probe_stderr" >&2
  exit 1
fi
cleanup_stub_probe
trap - EXIT INT TERM

cargo check --bin ibex-sfe-contract --features sfe-catalog-build
cargo test --lib module_loader::catalog_compiler::tests -- --test-threads=1
cargo test --bin ibex sfe::tests -- --test-threads=1
