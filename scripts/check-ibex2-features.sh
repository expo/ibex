#!/usr/bin/env bash
set -euo pipefail

# Keep the engine-free library and each independently supported feature door
# buildable. This list is intentionally explicit so a new cfg gate cannot hide
# a broken default, empty, bindings-only, either Intl data tier, crypto-only,
# or owning-runtime configuration. The final witness keeps ibex2/intl off
# while a direct linking dependency selects full ICU data.
for features in intl intl-all-locales; do
  build_tree="$(cargo tree -p ibex2 --no-default-features --features "$features" \
    -e build,features --format '{p} [{f}]')"
  build_dependency="$(printf '%s\n' "$build_tree" | grep 'hermes-lean-sys' || true)"
  if printf '%s\n' "$build_dependency" | grep -Eq 'icu-en-data|icu-full-data'; then
    echo "ibex2/$features leaked an ICU data tier into its build tree: $build_dependency" >&2
    exit 1
  fi
  printf 'ibex2/%s hermes build dependency: %s\n' \
    "$features" "${build_dependency:-<none>}"
done

cargo check -p ibex2
cargo check -p ibex2 --no-default-features
cargo check -p ibex2 --no-default-features --features bindings
cargo check -p ibex2 --no-default-features --features bindings,intl
cargo check -p ibex2 --no-default-features --features bindings,intl-all-locales
cargo check -p ibex2 --no-default-features --features crypto
cargo check -p ibex2-runtime --no-default-features
cargo check -p ibex2-runtime --no-default-features --features intl
cargo check -p ibex2-runtime --no-default-features --features intl-all-locales

# `pwd -W` (Git Bash/MSYS) yields a Windows path that the generated manifest
# can hand to native Cargo on Windows; elsewhere it fails and `pwd` is used.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/ibex2-icu-data-identity.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT
mkdir -p "$fixture_root/src"
printf '%s\n' \
  '[package]' \
  'name = "ibex2-icu-data-identity-witness"' \
  'version = "0.0.0"' \
  'edition = "2021"' \
  '' \
  '[dependencies]' \
  "ibex2 = { path = \"$repo_root/crates/ibex2\", default-features = false, features = [\"bindings\"] }" \
  "hermes-lean-sys = { path = \"$repo_root/crates/hermes-lean-sys\", default-features = false, features = [\"link\", \"icu-full-data\"] }" \
  '' \
  '[workspace]' \
  > "$fixture_root/Cargo.toml"
printf '%s\n' \
  'fn main() {' \
  '    hermes_lean_sys::ensure_linked();' \
  '    #[cfg(target_os = "linux")]' \
  '    {' \
  '        assert_eq!(ibex2::bindings::ICU_DATA_ARCHIVE, hermes_lean_sys::ICU_DATA_ARCHIVE);' \
  '        assert_eq!(ibex2::bindings::ICU_DATA_DIGEST, hermes_lean_sys::ICU_DATA_DIGEST);' \
  '        assert_eq!(ibex2::bindings::ICU_EN_DATA_ARCHIVE, hermes_lean_sys::ICU_EN_DATA_ARCHIVE);' \
  '        assert_eq!(ibex2::bindings::ICU_EN_DATA_DIGEST, hermes_lean_sys::ICU_EN_DATA_DIGEST);' \
  '        assert_eq!(ibex2::bindings::ICU_FULL_DATA_ARCHIVE, hermes_lean_sys::ICU_FULL_DATA_ARCHIVE);' \
  '        assert_eq!(ibex2::bindings::ICU_FULL_DATA_DIGEST, hermes_lean_sys::ICU_FULL_DATA_DIGEST);' \
  '        assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_ARCHIVE, hermes_lean_sys::ICU_FULL_DATA_ARCHIVE);' \
  '        assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_DIGEST, hermes_lean_sys::ICU_FULL_DATA_DIGEST);' \
  '        assert_ne!(hermes_lean_sys::LINKED_ICU_DATA_DIGEST, hermes_lean_sys::ICU_DATA_DIGEST);' \
  '    }' \
  '    #[cfg(windows)]' \
  '    assert_eq!(hermes_lean_sys::LINKED_OS_ICU, Some("icu.dll"));' \
  '    #[cfg(not(target_os = "linux"))]' \
  '    {' \
  '        assert_eq!(ibex2::bindings::ICU_DATA_ARCHIVE, None);' \
  '        assert_eq!(ibex2::bindings::ICU_EN_DATA_ARCHIVE, None);' \
  '        assert_eq!(ibex2::bindings::ICU_FULL_DATA_ARCHIVE, None);' \
  '        assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_ARCHIVE, None);' \
  '    }' \
  '}' \
  > "$fixture_root/src/main.rs"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}" \
  cargo run --quiet --manifest-path "$fixture_root/Cargo.toml"
