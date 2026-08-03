#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Hermes static-archive normalization: skipped (Darwin-only transform)"
  exit 0
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/ibex-hermes-static-archive.XXXXXX")"
cleanup() {
  rm -rf "$fixture_root"
}
trap cleanup EXIT INT TERM

printf '%s\n' 'int ibex_archive_fixture(void) { return 47; }' >"$fixture_root/fixture.c"
for arch in arm64 x86_64; do
  xcrun clang -arch "$arch" -mmacosx-version-min=12.0 \
    -c "$fixture_root/fixture.c" -o "$fixture_root/$arch.o"
  for builder in first second; do
    mkdir -p "$fixture_root/$builder/$arch"
    cp "$fixture_root/$arch.o" "$fixture_root/$builder/$arch/fixture.o"
  done
  touch -t 202001010000 "$fixture_root/first/$arch/fixture.o"
  touch -t 202501010000 "$fixture_root/second/$arch/fixture.o"
  (
    cd "$fixture_root/first/$arch"
    ar -rcs "$fixture_root/first-$arch.a" fixture.o
  )
  (
    cd "$fixture_root/second/$arch"
    ar -rcs "$fixture_root/second-$arch.a" fixture.o
  )
done

lipo -create "$fixture_root/first-x86_64.a" "$fixture_root/first-arm64.a" \
  -output "$fixture_root/first.a"
lipo -create "$fixture_root/second-x86_64.a" "$fixture_root/second-arm64.a" \
  -output "$fixture_root/second.a"
if cmp -s "$fixture_root/first.a" "$fixture_root/second.a"; then
  echo "archive test fixture did not preserve distinct member metadata" >&2
  exit 1
fi

bash "$repo_root/scripts/build-hermes.sh" \
  --normalize-static-archive "$fixture_root/first.a"
bash "$repo_root/scripts/build-hermes.sh" \
  --normalize-static-archive "$fixture_root/second.a"
cmp "$fixture_root/first.a" "$fixture_root/second.a"

first_digest="$(shasum -a 256 "$fixture_root/first.a" | awk '{ print $1 }')"
bash "$repo_root/scripts/build-hermes.sh" \
  --normalize-static-archive "$fixture_root/first.a"
second_digest="$(shasum -a 256 "$fixture_root/first.a" | awk '{ print $1 }')"
[[ "$first_digest" == "$second_digest" ]]

symbols="$(nm -gU "$fixture_root/first.a")"
[[ "$symbols" == *ibex_archive_fixture* ]]
echo "Hermes static-archive normalization: ok ($first_digest)"
