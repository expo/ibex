#!/usr/bin/env bash

# @ref LLP 0013#upstream-tracking — apply the carried Hermes patch stack.
#
# The pin (hermes-version.sh) plus this ordered patch series *is* the fork
# (the Electron model at small scale): there is no separate long-lived fork
# repository. Each patch under patches/hermes/ carries a class header
# (A=additive-file / B=insertion-point / C=surgical-semantic). Class A/B rebase
# mechanically; Class C is re-read against the surrounding upstream change.
#
# Usage: apply-hermes-patches.sh <hermes-source-dir>
# Idempotent: recognizes every verified prefix, including the complete stack,
# without changing the checkout's real Git index.

set -euo pipefail

HERMES_SRC="${1:?usage: apply-hermes-patches.sh <hermes-source-dir>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PATCH_DIR="$PROJECT_ROOT/patches/hermes"

if [[ ! -d "$PATCH_DIR" ]]; then
  echo "[patches] no patches/hermes directory; nothing to apply"
  exit 0
fi

shopt -s nullglob
patches=("$PATCH_DIR"/*.patch)
live_patches=("${patches[@]}")
if [[ ${#live_patches[@]} -eq 0 ]]; then
  echo "[patches] no .patch files in $PATCH_DIR"
  exit 0
fi

ZERO_OID="0000000000000000000000000000000000000000"
VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ibex-hermes-patches.XXXXXX")"
VERIFIED_INDEX="$VERIFY_DIR/verified.index"
COMPARISON_INDEX="$VERIFY_DIR/comparison.index"
STAGES_FILE="$VERIFY_DIR/stages"
SNAPSHOT_DIR="$VERIFY_DIR/patches"

cleanup_patch_verification() {
  rm -rf "$VERIFY_DIR"
}
trap cleanup_patch_verification EXIT

patch_error() {
  echo "[patches] ERROR: $*" >&2
  exit 1
}

sha256_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{ print $1 }'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{ print $1 }'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{ print $NF }'
  else
    patch_error "no SHA-256 implementation is available"
  fi
}

# Open the reviewed inputs only once for replay. Both verification passes and
# the real worktree application consume these private snapshots. Re-hashing
# the public files before and after replay makes an accidental/concurrent
# authority change fail closed instead of mixing two patch generations.
mkdir -p "$SNAPSHOT_DIR"
patches=()
patch_digests=()
for live_patch in "${live_patches[@]}"; do
  name="$(basename "$live_patch")"
  if [[ ! -f "$live_patch" || -L "$live_patch" ]]; then
    patch_error "$name is not a regular, non-symbolic patch file"
  fi
  snapshot="$SNAPSHOT_DIR/$name"
  digest_before="$(sha256_file "$live_patch")"
  cp "$live_patch" "$snapshot"
  digest_snapshot="$(sha256_file "$snapshot")"
  digest_after="$(sha256_file "$live_patch")"
  if [[ "$digest_before" != "$digest_snapshot" || "$digest_snapshot" != "$digest_after" ]]; then
    patch_error "$name changed while its authority snapshot was captured"
  fi
  chmod 0444 "$snapshot"
  patches+=("$snapshot")
  patch_digests+=("$digest_snapshot")
done

verify_live_patch_authority() {
  local index live_patch expected_digest observed_digest name
  for ((index = 0; index < ${#live_patches[@]}; index += 1)); do
    live_patch="${live_patches[$index]}"
    name="$(basename "$live_patch")"
    if [[ ! -f "$live_patch" || -L "$live_patch" ]]; then
      patch_error "$name changed type after its authority snapshot was captured"
    fi
    observed_digest="$(sha256_file "$live_patch")"
    expected_digest="${patch_digests[$index]}"
    if [[ "$observed_digest" != "$expected_digest" ]]; then
      patch_error "$name changed after its authority snapshot was captured"
    fi
  done
}

# Emit one tab-delimited authority record per `diff --git` section:
# old path, new path, old blob, new blob, old mode, and new mode.
# Full blob IDs make the patch review independently checkable; abbreviated IDs
# are deliberately rejected rather than resolved through the local object DB.
parse_patch_authority() {
  local patch="$1"
  local output="$2"
  local name
  name="$(basename "$patch")"

  awk -v patch_name="$name" '
    function fail(message) {
      print "[patches] ERROR: " patch_name ": " message > "/dev/stderr"
      failed = 1
      exit 2
    }
    function valid_oid(value) {
      return length(value) == 40 && value !~ /[^0-9a-f]/
    }
    function valid_mode(value) {
      return length(value) == 6 && value !~ /[^0-7]/
    }
    function emit_section(  key, expected_old_marker, expected_new_marker, authoritative_old_mode, authoritative_new_mode) {
      if (!in_diff)
        return
      if (index_count != 1)
        fail("each diff section must contain exactly one index line for " old_path " -> " new_path)
      if (old_marker_count != 1 || new_marker_count != 1)
        fail("each diff section must contain exactly one ---/+++ path pair for " old_path " -> " new_path)
      if (!valid_oid(old_oid) || !valid_oid(new_oid))
        fail("index IDs must be full lowercase 40-hex object IDs for " old_path " -> " new_path)
      if (old_oid == zero && new_oid == zero)
        fail("index line cannot have two absent blob IDs for " old_path " -> " new_path)

      expected_old_marker = old_oid == zero ? "/dev/null" : "a/" old_path
      expected_new_marker = new_oid == zero ? "/dev/null" : "b/" new_path
      if (old_marker != expected_old_marker || new_marker != expected_new_marker)
        fail("index zero/nonzero IDs disagree with the ---/+++ paths for " old_path " -> " new_path)

      if (old_oid == zero) {
        if (index_mode != "-" || new_file_mode_count != 1 || deleted_file_mode_count != 0 || old_mode_count != 0 || new_mode_count != 0)
          fail("an addition must have exactly one authoritative new file mode for " new_path)
        authoritative_old_mode = "-"
        authoritative_new_mode = new_file_mode
      } else if (new_oid == zero) {
        if (index_mode != "-" || deleted_file_mode_count != 1 || new_file_mode_count != 0 || old_mode_count != 0 || new_mode_count != 0)
          fail("a deletion must have exactly one authoritative deleted file mode for " old_path)
        authoritative_old_mode = deleted_file_mode
        authoritative_new_mode = "-"
      } else {
        if (new_file_mode_count != 0 || deleted_file_mode_count != 0)
          fail("new/deleted file mode appears on a non-addition/deletion for " old_path " -> " new_path)
        if (index_mode != "-") {
          if (old_mode_count != 0 || new_mode_count != 0)
            fail("unchanged index mode conflicts with old/new mode directives for " old_path " -> " new_path)
          authoritative_old_mode = index_mode
          authoritative_new_mode = index_mode
        } else {
          if (old_mode_count != 1 || new_mode_count != 1)
            fail("a mode-changing diff must have exactly one old mode and one new mode for " old_path " -> " new_path)
          authoritative_old_mode = old_mode
          authoritative_new_mode = new_mode
        }
      }

      key = old_path SUBSEP new_path
      if (seen_pair[key] || seen_old[old_path] || seen_new[new_path])
        fail("duplicate diff path in one patch: " old_path " -> " new_path)
      seen_pair[key] = 1
      seen_old[old_path] = 1
      seen_new[new_path] = 1
      print old_path "\t" new_path "\t" old_oid "\t" new_oid "\t" authoritative_old_mode "\t" authoritative_new_mode
      section_count++
    }
    BEGIN {
      zero = "0000000000000000000000000000000000000000"
    }
    /^diff --git / {
      if (in_diff)
        emit_section()
      if (failed)
        exit 2

      diff_line = substr($0, length("diff --git ") + 1)
      field_count = split(diff_line, fields, /[[:space:]]+/)
      if (field_count != 2 || substr(fields[1], 1, 2) != "a/" || substr(fields[2], 1, 2) != "b/")
        fail("diff paths must be unquoted a/<path> and b/<path>")
      old_path = substr(fields[1], 3)
      new_path = substr(fields[2], 3)
      if (old_path == "" || new_path == "" || old_path ~ /[[:space:]]/ || new_path ~ /[[:space:]]/)
        fail("diff paths must be non-empty and whitespace-free")

      in_diff = 1
      index_count = 0
      old_marker_count = 0
      new_marker_count = 0
      old_oid = ""
      new_oid = ""
      index_mode = "-"
      new_file_mode_count = 0
      deleted_file_mode_count = 0
      old_mode_count = 0
      new_mode_count = 0
      new_file_mode = ""
      deleted_file_mode = ""
      old_mode = ""
      new_mode = ""
      old_marker = ""
      new_marker = ""
      next
    }
    /^new file mode / {
      if (!in_diff)
        fail("new file mode appears outside a diff section")
      new_file_mode_count++
      new_file_mode = substr($0, length("new file mode ") + 1)
      if (new_file_mode_count != 1 || !valid_mode(new_file_mode))
        fail("duplicate or malformed new file mode for " old_path " -> " new_path)
      next
    }
    /^deleted file mode / {
      if (!in_diff)
        fail("deleted file mode appears outside a diff section")
      deleted_file_mode_count++
      deleted_file_mode = substr($0, length("deleted file mode ") + 1)
      if (deleted_file_mode_count != 1 || !valid_mode(deleted_file_mode))
        fail("duplicate or malformed deleted file mode for " old_path " -> " new_path)
      next
    }
    /^old mode / {
      if (!in_diff)
        fail("old mode appears outside a diff section")
      old_mode_count++
      old_mode = substr($0, length("old mode ") + 1)
      if (old_mode_count != 1 || !valid_mode(old_mode))
        fail("duplicate or malformed old mode for " old_path " -> " new_path)
      next
    }
    /^new mode / {
      if (!in_diff)
        fail("new mode appears outside a diff section")
      new_mode_count++
      new_mode = substr($0, length("new mode ") + 1)
      if (new_mode_count != 1 || !valid_mode(new_mode))
        fail("duplicate or malformed new mode for " old_path " -> " new_path)
      next
    }
    /^index / {
      if (!in_diff)
        fail("index line appears outside a diff section")
      index_count++
      if (index_count != 1)
        fail("duplicate index line for " old_path " -> " new_path)

      index_line = $0
      field_count = split(index_line, fields, /[[:space:]]+/)
      if (field_count != 2 && field_count != 3)
        fail("malformed index line for " old_path " -> " new_path)
      oid_count = split(fields[2], oids, /\.\./)
      if (fields[1] != "index" || oid_count != 2 || !valid_oid(oids[1]) || !valid_oid(oids[2]))
        fail("index IDs must be full lowercase 40-hex object IDs for " old_path " -> " new_path)
      if (field_count == 3 && !valid_mode(fields[3]))
        fail("index mode must be a six-digit octal mode for " old_path " -> " new_path)
      old_oid = oids[1]
      new_oid = oids[2]
      index_mode = field_count == 3 ? fields[3] : "-"
      next
    }
    /^--- / {
      if (!in_diff)
        fail("--- path appears outside a diff section")
      old_marker_count++
      if (old_marker_count != 1)
        fail("duplicate --- path for " old_path " -> " new_path)
      old_marker = substr($0, 5)
      next
    }
    /^\+\+\+ / {
      if (!in_diff)
        fail("+++ path appears outside a diff section")
      new_marker_count++
      if (new_marker_count != 1)
        fail("duplicate +++ path for " old_path " -> " new_path)
      new_marker = substr($0, 5)
      next
    }
    END {
      if (!failed) {
        if (!in_diff)
          fail("patch contains no diff sections")
        emit_section()
        if (section_count == 0)
          fail("patch contains no authoritative diff sections")
      }
    }
  ' "$patch" >"$output"
}

validate_index_blob() {
  local index_file="$1"
  local source_path="$2"
  local expected_oid="$3"
  local expected_mode="$4"
  local phase="$5"
  local patch_name="$6"
  local entry mode observed_oid stage listed_path extra

  entry="$(GIT_INDEX_FILE="$index_file" git ls-files --stage -- "$source_path")"
  if [[ "$expected_oid" == "$ZERO_OID" ]]; then
    if [[ -n "$entry" ]]; then
      patch_error "$patch_name: $phase expects absent path $source_path, but the temporary index contains it"
    fi
    return
  fi
  if [[ -z "$entry" || "$entry" == *$'\n'* ]]; then
    patch_error "$patch_name: $phase expected exactly one stage-0 entry for $source_path"
  fi
  IFS=$' \t' read -r mode observed_oid stage listed_path extra <<<"$entry"
  if [[ "$stage" != "0" || "$listed_path" != "$source_path" || -n "${extra:-}" ]]; then
    patch_error "$patch_name: $phase found a malformed index entry for $source_path"
  fi
  if [[ "$observed_oid" != "$expected_oid" ]]; then
    patch_error "$patch_name: $phase blob identity mismatch for $source_path (reviewed $expected_oid, observed $observed_oid)"
  fi
  if [[ "$expected_mode" != "-" && "$mode" != "$expected_mode" ]]; then
    patch_error "$patch_name: $phase mode mismatch for $source_path (reviewed $expected_mode, observed $mode)"
  fi
}

tree_matches_worktree() {
  local candidate_tree="$1"
  local unexpected

  rm -f "$COMPARISON_INDEX" "$COMPARISON_INDEX.lock"
  GIT_INDEX_FILE="$COMPARISON_INDEX" git read-tree "$candidate_tree" \
    || return 1
  # Populate stat data so diff-files compares content/mode/type against the
  # candidate tree instead of reporting every freshly read index entry dirty.
  GIT_INDEX_FILE="$COMPARISON_INDEX" git update-index -q --refresh \
    >/dev/null 2>&1 || true
  if ! GIT_INDEX_FILE="$COMPARISON_INDEX" \
    git diff-files --quiet --ignore-submodules=none --; then
    return 1
  fi
  # No ignore exemption is safe here: an ignored CMake/source input can still
  # affect a build. Source builders must remove their build outputs before
  # invoking this verifier.
  unexpected="$(GIT_INDEX_FILE="$COMPARISON_INDEX" \
    git ls-files --others --directory --no-empty-directory)"
  [[ -z "$unexpected" ]]
}

cd "$HERMES_SRC"
git rev-parse --verify HEAD^{tree} >/dev/null 2>&1 \
  || patch_error "$HERMES_SRC is not a Git checkout with a readable HEAD tree"

# @ref LLP 0013#upstream-tracking-and-re-derivation — replay the fork into an
# isolated index before mutating the checkout. This authenticates every patch
# transition and leaves a reusable checkout's real staging area untouched.
rm -f "$VERIFIED_INDEX" "$VERIFIED_INDEX.lock"
GIT_INDEX_FILE="$VERIFIED_INDEX" git read-tree HEAD
base_tree="$(GIT_INDEX_FILE="$VERIFIED_INDEX" git write-tree)"
printf '0\t<base>\t%s\n' "$base_tree" >"$STAGES_FILE"

authority_index=0
for authority_patch in "${patches[@]}"; do
  authority_name="$(basename "$authority_patch")"
  manifest="$VERIFY_DIR/manifest.$authority_index"
  parse_patch_authority "$authority_patch" "$manifest"

  while IFS=$'\t' read -r old_path new_path old_oid new_oid old_mode new_mode; do
    validate_index_blob \
      "$VERIFIED_INDEX" "$old_path" "$old_oid" "$old_mode" \
      "preimage" "$authority_name"
  done <"$manifest"

  if ! GIT_INDEX_FILE="$VERIFIED_INDEX" git apply --cached --check "$authority_patch"; then
    patch_error "$authority_name does not apply cleanly to its reviewed preimage"
  fi
  GIT_INDEX_FILE="$VERIFIED_INDEX" git apply --cached "$authority_patch"

  while IFS=$'\t' read -r old_path new_path old_oid new_oid old_mode new_mode; do
    validate_index_blob \
      "$VERIFIED_INDEX" "$new_path" "$new_oid" "$new_mode" \
      "postimage" "$authority_name"
  done <"$manifest"

  authority_index=$((authority_index + 1))
  stage_tree="$(GIT_INDEX_FILE="$VERIFIED_INDEX" git write-tree)"
  printf '%s\t%s\t%s\n' "$authority_index" "$authority_name" "$stage_tree" \
    >>"$STAGES_FILE"
done

if ! GIT_INDEX_FILE="$VERIFIED_INDEX" git diff --cached --check; then
  patch_error "verified patch stack introduces whitespace errors"
fi
final_tree="$(GIT_INDEX_FILE="$VERIFIED_INDEX" git write-tree)"
verify_live_patch_authority

current_stage=-1
matching_stages=0
while IFS=$'\t' read -r stage_number stage_name stage_tree; do
  if tree_matches_worktree "$stage_tree"; then
    current_stage="$stage_number"
    matching_stages=$((matching_stages + 1))
  fi
done <"$STAGES_FILE"
if [[ "$matching_stages" -eq 0 ]]; then
  patch_error "complete checkout does not match any verified stack prefix; restore the pinned source and remove every untracked input"
fi
if [[ "$matching_stages" -ne 1 ]]; then
  patch_error "complete checkout ambiguously matches $matching_stages verified stack prefixes"
fi

patch_index=0
for patch in "${patches[@]}"; do
  name="$(basename "$patch")"
  if [[ "$patch_index" -lt "$current_stage" ]]; then
    echo "[patches] already applied: $name"
    patch_index=$((patch_index + 1))
    continue
  fi
  if ! git apply --check "$patch" >/dev/null 2>&1; then
    patch_error "$name does not apply cleanly to verified prefix $current_stage; see LLP 0013 pin-bump runbook"
  fi
  echo "[patches] applying: $name"
  git apply "$patch"
  patch_index=$((patch_index + 1))
done

verify_live_patch_authority
if ! tree_matches_worktree "$final_tree"; then
  patch_error "complete working tree does not match verified final tree $final_tree after patch application"
fi
echo "[patches] verified ${#patches[@]} patch(es); final tree: $final_tree"
