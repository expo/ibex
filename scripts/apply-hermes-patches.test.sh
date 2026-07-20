#!/usr/bin/env bash
# Focused authority tests for scripts/apply-hermes-patches.sh.
# @ref LLP 0013#upstream-tracking-and-re-derivation — the pin plus the exact,
# sequentially verified patch transitions is the carried Hermes fork.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
subject="$repo_root/scripts/apply-hermes-patches.sh"
pinned_commit="ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138"
reviewed_final_tree="a6e9b222128ab97f9b740839e354f8edd357a388"

work="$(mktemp -d "${TMPDIR:-/tmp}/ibex-hermes-patch-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

passed=0
failed=0
ok() {
  printf 'ok   - %s\n' "$*"
  passed=$((passed + 1))
}
bad() {
  printf 'FAIL - %s\n' "$*" >&2
  failed=$((failed + 1))
}

different_oid() {
  local oid="$1"
  if [[ "${oid:0:1}" == "0" ]]; then
    printf '1%s' "${oid:1}"
  else
    printf '0%s' "${oid:1}"
  fi
}

replace_once() {
  local file="$1"
  local old="$2"
  local new="$3"
  local temporary="$file.rewrite"
  awk -v old="$old" -v new="$new" '
    !done && index($0, old) {
      before = substr($0, 1, index($0, old) - 1)
      after = substr($0, index($0, old) + length(old))
      $0 = before new after
      done = 1
    }
    { print }
    END { if (!done) exit 2 }
  ' "$file" >"$temporary"
  mv "$temporary" "$file"
}

make_fixture() {
  local name="$1"
  fixture_project="$work/$name"
  fixture_source="$fixture_project/hermes"
  fixture_patch="$fixture_project/patches/hermes/0001-fixture.patch"
  mkdir -p "$fixture_project/scripts" "$fixture_project/patches/hermes" "$fixture_source"
  cp "$subject" "$fixture_project/scripts/apply-hermes-patches.sh"
  chmod +x "$fixture_project/scripts/apply-hermes-patches.sh"

  git -C "$fixture_source" init -q
  git -C "$fixture_source" config user.name "Ibex patch test"
  git -C "$fixture_source" config user.email "patch-test@ibex.invalid"
  printf 'before\n' >"$fixture_source/change.txt"
  printf 'delete me\n' >"$fixture_source/delete.txt"
  printf 'must remain reviewed\n' >"$fixture_source/untouched.txt"
  printf 'ignored/\n' >"$fixture_source/.gitignore"
  git -C "$fixture_source" add .gitignore change.txt delete.txt untouched.txt
  git -C "$fixture_source" commit -qm base
  fixture_base_tree="$(git -C "$fixture_source" write-tree)"

  printf 'after\n' >"$fixture_source/change.txt"
  rm "$fixture_source/delete.txt"
  printf 'added\n' >"$fixture_source/add.txt"
  git -C "$fixture_source" add -N add.txt
  git -C "$fixture_source" diff --full-index --binary HEAD >"$fixture_patch"

  fixture_index="$fixture_project/expected.index"
  rm -f "$fixture_index"
  GIT_INDEX_FILE="$fixture_index" git -C "$fixture_source" read-tree HEAD
  GIT_INDEX_FILE="$fixture_index" git -C "$fixture_source" apply --cached "$fixture_patch"
  fixture_final_tree="$(GIT_INDEX_FILE="$fixture_index" git -C "$fixture_source" write-tree)"
  rm -f "$fixture_index" "$fixture_index.lock"

  git -C "$fixture_source" restore --staged --worktree :/
  rm -f "$fixture_source/add.txt"
}

fixture_change_oids() {
  local index_line pair
  index_line="$(awk '
    /^diff --git a\/change\.txt b\/change\.txt$/ { in_change = 1; next }
    /^diff --git / { in_change = 0 }
    in_change && /^index / { print; exit }
  ' "$fixture_patch")"
  pair="$(printf '%s\n' "$index_line" | awk '{ print $2 }')"
  fixture_old_oid="${pair%%..*}"
  fixture_new_oid="${pair##*..}"
}

expect_rejected() {
  local label="$1"
  local pattern="$2"
  local output="$fixture_project/output"
  local status_before
  status_before="$(git -C "$fixture_source" status --porcelain=v1 --ignored --untracked-files=all)"
  if "$fixture_project/scripts/apply-hermes-patches.sh" "$fixture_source" >"$output" 2>&1; then
    bad "$label exits nonzero"
  else
    ok "$label exits nonzero"
  fi
  if grep -Eq "$pattern" "$output"; then
    ok "$label names the rejected authority"
  else
    bad "$label names the rejected authority"
    sed -n '1,20p' "$output" >&2
  fi
  if [[ "$(git -C "$fixture_source" write-tree)" == "$fixture_base_tree" ]] \
    && [[ "$(git -C "$fixture_source" status --porcelain=v1 --ignored --untracked-files=all)" == "$status_before" ]]; then
    ok "$label leaves the real index and worktree untouched"
  else
    bad "$label leaves the real index and worktree untouched"
  fi
}

# A valid synthetic patch covers modification, addition, deletion, their full
# blob IDs, and the separate new/deleted mode authorities.
make_fixture valid
valid_output="$fixture_project/first.out"
if "$fixture_project/scripts/apply-hermes-patches.sh" "$fixture_source" >"$valid_output" 2>&1; then
  ok "valid modify/add/delete patch applies"
else
  bad "valid modify/add/delete patch applies"
  sed -n '1,30p' "$valid_output" >&2
fi
if grep -q "final tree: $fixture_final_tree" "$valid_output"; then
  ok "valid patch reports its verified final tree"
else
  bad "valid patch reports its verified final tree"
fi
if [[ "$(git -C "$fixture_source" write-tree)" == "$fixture_base_tree" ]]; then
  ok "valid patch leaves the real Git index untouched"
else
  bad "valid patch leaves the real Git index untouched"
fi
if [[ "$(cat "$fixture_source/change.txt")" == "after" ]] \
  && [[ "$(cat "$fixture_source/add.txt")" == "added" ]] \
  && [[ ! -e "$fixture_source/delete.txt" ]]; then
  ok "valid patch materializes the reviewed working-tree state"
else
  bad "valid patch materializes the reviewed working-tree state"
fi
if "$fixture_project/scripts/apply-hermes-patches.sh" "$fixture_source" >"$fixture_project/second.out" 2>&1 \
  && grep -q "already applied: 0001-fixture.patch" "$fixture_project/second.out"; then
  ok "fully applied stack is idempotent"
else
  bad "fully applied stack is idempotent"
fi

make_fixture stale-old
fixture_change_oids
replace_once "$fixture_patch" "$fixture_old_oid" "$(different_oid "$fixture_old_oid")"
expect_rejected "stale old blob" "preimage blob identity mismatch"

make_fixture stale-new
fixture_change_oids
replace_once "$fixture_patch" "$fixture_new_oid" "$(different_oid "$fixture_new_oid")"
expect_rejected "stale new blob" "postimage blob identity mismatch"

make_fixture abbreviated
fixture_change_oids
replace_once "$fixture_patch" "$fixture_old_oid" "${fixture_old_oid:0:12}"
expect_rejected "abbreviated blob ID" "full lowercase 40-hex object IDs"

make_fixture missing-index
awk '!removed && /^index / { removed = 1; next } { print }' \
  "$fixture_patch" >"$fixture_patch.rewrite"
mv "$fixture_patch.rewrite" "$fixture_patch"
expect_rejected "missing index line" "exactly one index line"

make_fixture duplicate-index
awk '!duplicated && /^index / { print; duplicated = 1 } { print }' \
  "$fixture_patch" >"$fixture_patch.rewrite"
mv "$fixture_patch.rewrite" "$fixture_patch"
expect_rejected "duplicate index line" "duplicate index line"

make_fixture stale-mode
fixture_change_oids
replace_once "$fixture_patch" "index $fixture_old_oid..$fixture_new_oid 100644" \
  "index $fixture_old_oid..$fixture_new_oid 100755"
expect_rejected "stale unchanged mode" "preimage mode mismatch"

make_fixture duplicate-add-mode
awk '!duplicated && /^new file mode / { print; duplicated = 1 } { print }' \
  "$fixture_patch" >"$fixture_patch.rewrite"
mv "$fixture_patch.rewrite" "$fixture_patch"
expect_rejected "duplicate addition mode" "duplicate or malformed new file mode"

make_fixture malformed-delete-mode
replace_once "$fixture_patch" "deleted file mode 100644" "deleted file mode 10064x"
expect_rejected "malformed deletion mode" "duplicate or malformed deleted file mode"

# The reported tree covers the complete candidate checkout, not merely paths
# mentioned by the stack. Both tracked drift and ignored/untracked inputs can
# affect compilation and therefore fail before any patch is materialized.
make_fixture unrelated-tracked-drift
printf 'unreviewed source mutation\n' >>"$fixture_source/untouched.txt"
expect_rejected "unrelated tracked drift" "complete checkout does not match any verified stack prefix"

make_fixture ignored-untracked-input
mkdir -p "$fixture_source/ignored"
printf 'unreviewed generated source\n' >"$fixture_source/ignored/injected.cpp"
expect_rejected "ignored untracked input" "complete checkout does not match any verified stack prefix"

# Replay the checked-in 12-patch stack against the real pin. A caller may point
# IBEX_HERMES_TEST_SOURCE_REPO at an existing object cache; otherwise this
# focused integration test fetches only the pinned commit.
real_source="$work/real-hermes"
if [[ -n "${IBEX_HERMES_TEST_SOURCE_REPO:-}" ]]; then
  git clone -q --no-checkout --shared "$IBEX_HERMES_TEST_SOURCE_REPO" "$real_source"
  git -C "$real_source" checkout -q --detach "$pinned_commit"
else
  mkdir -p "$real_source"
  git -C "$real_source" init -q
  git -C "$real_source" remote add origin https://github.com/facebook/hermes.git
  git -C "$real_source" fetch -q --depth=1 origin "$pinned_commit"
  git -C "$real_source" checkout -q --detach FETCH_HEAD
fi
real_base_tree="$(git -C "$real_source" write-tree)"
if "$subject" "$real_source" >"$work/real-first.out" 2>&1 \
  && grep -q "final tree: $reviewed_final_tree" "$work/real-first.out"; then
  ok "real 12-patch stack replays to the reviewed final tree"
else
  bad "real 12-patch stack replays to the reviewed final tree"
  sed -n '1,40p' "$work/real-first.out" >&2
fi
if [[ "$(git -C "$real_source" write-tree)" == "$real_base_tree" ]]; then
  ok "real stack replay preserves the checkout index"
else
  bad "real stack replay preserves the checkout index"
fi
if "$subject" "$real_source" >"$work/real-second.out" 2>&1 \
  && [[ "$(grep -c '^\[patches\] already applied:' "$work/real-second.out")" -eq 12 ]] \
  && grep -q "final tree: $reviewed_final_tree" "$work/real-second.out"; then
  ok "real fully applied stack is idempotent"
else
  bad "real fully applied stack is idempotent"
fi

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[[ "$failed" -eq 0 ]]
