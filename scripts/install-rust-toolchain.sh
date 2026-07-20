#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain_file="$repo_root/rust-toolchain.toml"
channel="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' "$toolchain_file")"

if [[ -z "$channel" ]]; then
  echo "rust-toolchain.toml has no channel" >&2
  exit 1
fi

rustup toolchain install "$channel" \
  --profile minimal \
  --component rustfmt \
  --component clippy \
  --component rust-src

actual="$(cd "$repo_root" && rustc --version | awk '{print $2}')"
if [[ "$actual" != "$channel" ]]; then
  echo "rust-toolchain drift: rust-toolchain.toml selects $channel but rustc is $actual" >&2
  exit 1
fi
