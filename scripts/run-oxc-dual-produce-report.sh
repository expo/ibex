#!/usr/bin/env bash
set -euo pipefail

# Rebuild the LLP 0028 pre-rotation producer in an isolated worktree, produce
# both bundles, run both independently on real Hermes, and emit one
# content-addressed comparison report.
# @ref LLP 0028#1-toolchain-and-pin-rotation--atomic-with-identity-rotation

old_revision="9329a9123a10e379d6253afb6a90a33de5de928e"
repo_root="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
output_dir="${1:-$repo_root/target/oxc-dual-produce-evidence}"
hermes_binary="${IBEX_HERMES_BIN:-$repo_root/tools/hermes/hermes}"
hermes_compiler="${HERMESC:-$repo_root/tools/hermes/hermesc}"

if [[ ! -x "$hermes_compiler" && -x "$repo_root/tools/hermes/hermesc-macos-arm64" ]]; then
  hermes_compiler="$repo_root/tools/hermes/hermesc-macos-arm64"
fi

if [[ ! -x "$hermes_binary" ]]; then
  echo "real Hermes is required at $hermes_binary" >&2
  exit 1
fi
if [[ ! -x "$hermes_compiler" ]]; then
  echo "Hermes compiler is required at $hermes_compiler" >&2
  exit 1
fi
if ! git -C "$repo_root" cat-file -e "$old_revision^{commit}"; then
  echo "pre-rotation commit $old_revision is absent; fetch full history" >&2
  exit 1
fi

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/ibex-oxc-dual-produce.XXXXXX")"
old_root="$temporary_root/old"
old_target="${IBEX_OXC_OLD_TARGET_DIR:-$repo_root/target/oxc-dual-produce-old}"
new_target="${IBEX_OXC_NEW_TARGET_DIR:-$repo_root/target/oxc-dual-produce-new}"
old_artifacts="$temporary_root/old-artifacts.json"
new_artifacts="$temporary_root/new-artifacts.json"

cleanup() {
  if [[ -n "${old_root:-}" && "$old_root" == "$temporary_root/old" ]]; then
    git -C "$repo_root" worktree remove --force "$old_root" >/dev/null 2>&1 || true
  fi
  if [[ -n "${temporary_root:-}" && "$temporary_root" == */ibex-oxc-dual-produce.* ]]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT

git -C "$repo_root" worktree add --detach "$old_root" "$old_revision"

# The downloaded Hermes SDK is intentionally shared read-only by the two
# isolated Cargo target directories. It is not part of either Git worktree.
export HERMES_INCLUDE_DIR="$repo_root/ios/Frameworks/hermes-headers"
export JSI_INCLUDE_DIR="$repo_root/ios/Frameworks/hermes-headers"
export HERMES_LIB_DIR="$repo_root/ios/Frameworks"
export JSI_LIB_DIR="$repo_root/ios/Frameworks"
export HERMES_BIN_DIR="$(dirname "$hermes_binary")"
export HERMESC="$hermes_compiler"
if [[ "$(uname -s)" == "Darwin" ]]; then
  export DYLD_FRAMEWORK_PATH="$repo_root/ios/Frameworks${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}"
fi

CARGO_TARGET_DIR="$old_target" cargo +1.93.1 build \
  --locked \
  --release \
  --manifest-path "$old_root/Cargo.toml" \
  --example module_runner_spike \
  --features module-runner-spike

CARGO_TARGET_DIR="$new_target" cargo +1.97.0 build \
  --locked \
  --release \
  --manifest-path "$repo_root/Cargo.toml" \
  --example module_runner_spike \
  --features module-runner-spike

"$old_target/release/examples/module_runner_spike" \
  "$old_root/tests/fixtures/module-runner-spike/manifest.json" \
  "$old_artifacts"
"$new_target/release/examples/module_runner_spike" \
  "$repo_root/tests/fixtures/module-runner-spike/manifest.json" \
  "$new_artifacts"

node "$repo_root/packages/ibex-devtools/src/scripts/oxc-dual-produce-report.mjs" \
  --old-artifacts "$old_artifacts" \
  --new-artifacts "$new_artifacts" \
  --old-producer "$old_target/release/examples/module_runner_spike" \
  --new-producer "$new_target/release/examples/module_runner_spike" \
  --old-root "$old_root" \
  --new-root "$repo_root" \
  --old-manifest "$old_root/tests/fixtures/module-runner-spike/manifest.json" \
  --new-manifest "$repo_root/tests/fixtures/module-runner-spike/manifest.json" \
  --hermes "$hermes_binary" \
  --contract "$repo_root/issues/20260717-oxc-dual-produce-report.md" \
  --output-dir "$output_dir"
