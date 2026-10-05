#!/usr/bin/env bash

# The sole Linux ICU source authority for Ibex 2. Linux builders verify this
# exact tag resolution and the checked-in trimmed-data filter before building.
IBEX_ICU_VERSION="${IBEX_ICU_VERSION:-74.2}"
IBEX_ICU_SOURCE_REF="${IBEX_ICU_SOURCE_REF:-release-74-2}"
IBEX_ICU_SOURCE_COMMIT="${IBEX_ICU_SOURCE_COMMIT:-2d029329c82c7792b985024b2bdab5fc7278fbc8}"
IBEX_ICU_TRIMMED_FILTER_SHA256="${IBEX_ICU_TRIMMED_FILTER_SHA256:-c5d1b182d6e92212ff4952d7a5c956f3d54611f300cb6fa1fdca39a6510f9702}"
IBEX_ICU_TRIMMED_DATA_BYTES="${IBEX_ICU_TRIMMED_DATA_BYTES:-1109808}"

ibex_verify_icu_trimmed_filter() {
  local filter="$1" actual
  actual="$(ibex_sha256 "$filter" | awk '{ print $1 }')"
  [[ "$actual" == "$IBEX_ICU_TRIMMED_FILTER_SHA256" ]] || {
    echo "ICU trimmed-data filter digest is $actual, expected $IBEX_ICU_TRIMMED_FILTER_SHA256" >&2
    return 1
  }
}

ibex_checkout_icu_source() {
  local source_dir="$1" resolved
  if [[ ! -d "$source_dir/.git" ]]; then
    mkdir -p "$source_dir"
    git -C "$source_dir" init -q
    git -C "$source_dir" remote add origin https://github.com/unicode-org/icu.git
  fi
  git -C "$source_dir" fetch --depth=1 --no-tags origin "refs/tags/$IBEX_ICU_SOURCE_REF"
  resolved="$(git -C "$source_dir" rev-parse FETCH_HEAD)"
  [[ "$resolved" == "$IBEX_ICU_SOURCE_COMMIT" ]] || {
    echo "ICU tag $IBEX_ICU_SOURCE_REF resolved to $resolved, expected $IBEX_ICU_SOURCE_COMMIT" >&2
    return 1
  }
  git -C "$source_dir" reset --hard "$IBEX_ICU_SOURCE_COMMIT"
  git -C "$source_dir" clean -ffdx
}

ibex_build_icu_linux() {
  local source_dir="$1" build_dir="$2" install_dir="$3" filter="${4:-}"
  local -a configure_env=(
    "CFLAGS=-Os -ffunction-sections -fdata-sections"
    "CXXFLAGS=-Os -ffunction-sections -fdata-sections"
  )
  rm -rf "$build_dir" "$install_dir"
  mkdir -p "$build_dir"
  (
    cd "$build_dir"
    if [[ -n "$filter" ]]; then
      export ICU_DATA_FILTER_FILE="$filter"
    fi
    env "${configure_env[@]}" \
      "$source_dir/icu4c/source/runConfigureICU" Linux \
        --prefix="$install_dir" \
        --enable-static --disable-shared \
        --with-data-packaging=static \
        --disable-tests --disable-samples --disable-extras
    make -j2
    make install
  )
}

ibex_icu_data_symbol_bytes() {
  local archive="$1" symbol="icudt74_dat" size
  size="$(nm -S --size-sort "$archive" | awk -v wanted="$symbol" '$4 == wanted { print $2 }')"
  [[ -n "$size" ]] || {
    echo "ICU data archive has no $symbol symbol: $archive" >&2
    return 1
  }
  printf '%d\n' "0x$size"
}

ibex_verify_icu_data_variants() {
  local trimmed="$1" full="$2" trimmed_bytes full_bytes
  trimmed_bytes="$(ibex_icu_data_symbol_bytes "$trimmed")"
  full_bytes="$(ibex_icu_data_symbol_bytes "$full")"
  [[ "$trimmed_bytes" == "$IBEX_ICU_TRIMMED_DATA_BYTES" ]] || {
    echo "trimmed ICU data is $trimmed_bytes bytes, expected $IBEX_ICU_TRIMMED_DATA_BYTES" >&2
    return 1
  }
  (( full_bytes > trimmed_bytes * 10 )) || {
    echo "full ICU data is unexpectedly small: $full_bytes bytes" >&2
    return 1
  }
}
