#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/hermes-version.sh"

HERMES_ANDROID_VERSION="${HERMES_ANDROID_VERSION:-$IBEX_HERMES_ANDROID_VERSION}"
REACT_ANDROID_VERSION="${REACT_ANDROID_VERSION:-$IBEX_REACT_ANDROID_VERSION}"
ANDROID_HERMES_VARIANT="${ANDROID_HERMES_VARIANT:-debug}"
MAVEN_REPO_URL="${MAVEN_REPO_URL:-https://repo1.maven.org/maven2}"
HERMES_ANDROID_AAR_SHA256="${HERMES_ANDROID_AAR_SHA256:-$IBEX_HERMES_ANDROID_DEBUG_AAR_SHA256}"
REACT_ANDROID_AAR_SHA256="${REACT_ANDROID_AAR_SHA256:-$IBEX_REACT_ANDROID_DEBUG_AAR_SHA256}"
ANDROID_ARTIFACT_DIR="${ANDROID_ARTIFACT_DIR:-$ROOT/android}"
ANDROID_ARTIFACT_CACHE="${ANDROID_ARTIFACT_CACHE:-$ANDROID_ARTIFACT_DIR/.cache}"

mkdir -p "$ANDROID_ARTIFACT_CACHE"

if [[ "$HERMES_ANDROID_VERSION" != "$IBEX_HERMES_VERSION" ]]; then
  echo "Android Hermes remains at reviewed artifact $HERMES_ANDROID_VERSION; published 260318099.0.1 predates the source pin's WeakRef read-barrier fix." >&2
fi

find_gradle_aar() {
  local group="$1"
  local module="$2"
  local version="$3"
  local file="$4"
  local gradle_root="${GRADLE_USER_HOME:-$HOME/.gradle}/caches/modules-2/files-2.1/$group/$module/$version"

  if [[ -d "$gradle_root" ]]; then
    find "$gradle_root" -type f -name "$file" | head -n 1
  fi
}

verify_aar_checksum() {
  local aar="$1"
  local expected="$2"
  local actual
  actual="$(ibex_sha256 "$aar" | awk '{ print $1 }')"
  if [[ "$actual" != "$expected" ]]; then
    echo "AAR checksum mismatch for $aar" >&2
    echo "  reviewed: $expected" >&2
    echo "  observed: $actual" >&2
    return 1
  fi
}

download_aar() {
  local group="$1"
  local module="$2"
  local version="$3"
  local variant="$4"
  local expected_sha256="$5"
  local group_path="${group//.//}"
  local file="$module-$version-$variant.aar"
  local cached dest url temporary
  if [[ ! "$expected_sha256" =~ ^[a-f0-9]{64}$ ]]; then
    echo "Missing reviewed SHA-256 for $group:$module:$version:$variant" >&2
    return 1
  fi
  cached="$(find_gradle_aar "$group" "$module" "$version" "$file" || true)"

  if [[ -n "$cached" ]]; then
    if verify_aar_checksum "$cached" "$expected_sha256"; then
      echo "$cached"
      return
    fi
    echo "Ignoring untrusted Gradle cache candidate and resolving the reviewed bytes." >&2
  fi

  dest="$ANDROID_ARTIFACT_CACHE/$file"
  if [[ -f "$dest" ]] && ! verify_aar_checksum "$dest" "$expected_sha256"; then
    rm -f "$dest"
  fi
  if [[ ! -f "$dest" ]]; then
    url="$MAVEN_REPO_URL/$group_path/$module/$version/$file"
    temporary="$(mktemp "${dest}.tmp.XXXXXX")"
    trap 'rm -f "$temporary"' RETURN
    echo "Downloading $url" >&2
    curl -fL --retry 3 "$url" -o "$temporary"
    verify_aar_checksum "$temporary" "$expected_sha256"
    mv -f "$temporary" "$dest"
    trap - RETURN
  fi
  verify_aar_checksum "$dest" "$expected_sha256"
  echo "$dest"
}

extract_module() {
  local aar="$1"
  local module="$2"
  local dest="$3"

  rm -rf "$dest"
  mkdir -p "$dest"
  unzip -q "$aar" "prefab/modules/$module/*" -d "$dest"
}

write_android_profile_receipts() {
  local aar="$1"
  local react_aar="$2"
  local module_root="$ANDROID_ARTIFACT_DIR/hermes-android/prefab/modules/hermesvm"
  local jsi_root="$ANDROID_ARTIFACT_DIR/react-android/prefab/modules/jsi"
  local package_hex react_package_hex binary jsi_binary abi architecture
  local binary_hex jsi_binary_hex output tmp count=0
  package_hex="$(ibex_sha256 "$aar" | awk '{ print $1 }')"
  react_package_hex="$(ibex_sha256 "$react_aar" | awk '{ print $1 }')"

  for value in "$HERMES_ANDROID_VERSION" "$ANDROID_HERMES_VARIANT" \
    "$REACT_ANDROID_VERSION" "$MAVEN_REPO_URL" "$package_hex" \
    "$react_package_hex"; do
    if [[ ! "$value" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
      echo "Unsafe Android Hermes provenance value: $value" >&2
      exit 1
    fi
  done

  while IFS= read -r -d '' binary; do
    abi="$(basename "$(dirname "$binary")")"
    abi="${abi#android.}"
    case "$abi" in
      arm64-v8a) architecture="aarch64" ;;
      armeabi-v7a) architecture="arm" ;;
      x86) architecture="x86" ;;
      x86_64) architecture="x86_64" ;;
      *)
        echo "Unsupported Hermes Prefab ABI in provenance receipt: $abi" >&2
        exit 1
        ;;
    esac
    jsi_binary="$jsi_root/libs/android.$abi/libjsi.so"
    if [[ ! -f "$jsi_binary" ]]; then
      echo "React Android JSI dependency is absent for Hermes ABI $abi: $jsi_binary" >&2
      exit 1
    fi
    binary_hex="$(ibex_sha256 "$binary" | awk '{ print $1 }')"
    jsi_binary_hex="$(ibex_sha256 "$jsi_binary" | awk '{ print $1 }')"
    output="$(dirname "$binary")/hermes-profile-provenance.json"
    tmp="$(mktemp "${output}.tmp.XXXXXX")"
    cat >"$tmp" <<EOF
{
  "schema": "ibex/hermes-profile-provenance-receipt/2",
  "profileId": "android-maven",
  "targetVariant": "android",
  "artifact": {
    "binaryDigest": "sha256-$binary_hex",
    "fileName": "libhermesvm.so",
    "targetArchitecture": "$architecture"
  },
  "origin": {
    "kind": "maven-aar",
    "packageCoordinate": "com.facebook.hermes:hermes-android:$HERMES_ANDROID_VERSION:$ANDROID_HERMES_VARIANT",
    "packageDigest": "sha256-$package_hex",
    "packageRepository": "$MAVEN_REPO_URL",
    "linkedDependency": {
      "artifact": {
        "binaryDigest": "sha256-$jsi_binary_hex",
        "fileName": "libjsi.so",
        "targetArchitecture": "$architecture"
      },
      "packageCoordinate": "com.facebook.react:react-android:$REACT_ANDROID_VERSION:$ANDROID_HERMES_VARIANT",
      "packageDigest": "sha256-$react_package_hex",
      "packageRepository": "$MAVEN_REPO_URL"
    },
    "reviewedProfileIdentity": {
      "artifact": "com.facebook.hermes:hermes-android",
      "packageDigest": "sha256-$package_hex",
      "linkedDependency": {
        "artifact": "com.facebook.react:react-android",
        "packageDigest": "sha256-$react_package_hex",
        "variant": "$ANDROID_HERMES_VARIANT",
        "version": "$REACT_ANDROID_VERSION"
      },
      "variant": "$ANDROID_HERMES_VARIANT",
      "version": "$HERMES_ANDROID_VERSION"
    }
  }
}
EOF
    chmod 0644 "$tmp"
    mv -f "$tmp" "$output"
    count=$((count + 1))
  done < <(find "$module_root/libs" -type f -name libhermesvm.so -print0)

  if [[ "$count" -eq 0 ]]; then
    echo "Extracted Hermes artifact has no Prefab runtime libraries" >&2
    exit 1
  fi
  echo "Wrote $count Android Hermes + linked JSI reviewed-package provenance receipts."
}

hermes_aar="$(download_aar "com.facebook.hermes" "hermes-android" "$HERMES_ANDROID_VERSION" "$ANDROID_HERMES_VARIANT" "$HERMES_ANDROID_AAR_SHA256")"
react_aar="$(download_aar "com.facebook.react" "react-android" "$REACT_ANDROID_VERSION" "$ANDROID_HERMES_VARIANT" "$REACT_ANDROID_AAR_SHA256")"

extract_module "$hermes_aar" "hermesvm" "$ANDROID_ARTIFACT_DIR/hermes-android"
extract_module "$react_aar" "jsi" "$ANDROID_ARTIFACT_DIR/react-android"
write_android_profile_receipts "$hermes_aar" "$react_aar"

if [[ ! -f "$ANDROID_ARTIFACT_DIR/hermes-android/prefab/modules/hermesvm/include/hermes/hermes.h" ]]; then
  echo "Extracted Hermes artifact is missing hermes/hermes.h" >&2
  exit 1
fi

if [[ ! -f "$ANDROID_ARTIFACT_DIR/react-android/prefab/modules/jsi/include/jsi/jsi.h" ||
      ! -f "$ANDROID_ARTIFACT_DIR/react-android/prefab/modules/jsi/include/jsi/hermes-interfaces.h" ]]; then
  echo "Extracted React Android artifact is missing required JSI headers." >&2
  echo "Use a REACT_ANDROID_VERSION whose PREFAB JSI module includes jsi/hermes-interfaces.h." >&2
  exit 1
fi

cat <<EOF
Installed Android Hermes artifacts:
  Hermes: $ANDROID_ARTIFACT_DIR/hermes-android/prefab/modules/hermesvm
  JSI:    $ANDROID_ARTIFACT_DIR/react-android/prefab/modules/jsi

Build with:
  ANDROID_TARGET=aarch64-linux-android ./scripts/cargo-android.sh

Override versions with:
  HERMES_ANDROID_VERSION=$HERMES_ANDROID_VERSION
  REACT_ANDROID_VERSION=$REACT_ANDROID_VERSION
  ANDROID_HERMES_VARIANT=$ANDROID_HERMES_VARIANT
EOF
