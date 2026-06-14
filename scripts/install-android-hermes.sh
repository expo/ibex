#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

HERMES_ANDROID_VERSION="${HERMES_ANDROID_VERSION:-250829098.0.14}"
REACT_ANDROID_VERSION="${REACT_ANDROID_VERSION:-0.86.0-rc.3}"
ANDROID_HERMES_VARIANT="${ANDROID_HERMES_VARIANT:-debug}"
MAVEN_REPO_URL="${MAVEN_REPO_URL:-https://repo1.maven.org/maven2}"
ANDROID_ARTIFACT_DIR="${ANDROID_ARTIFACT_DIR:-$ROOT/android}"
ANDROID_ARTIFACT_CACHE="${ANDROID_ARTIFACT_CACHE:-$ANDROID_ARTIFACT_DIR/.cache}"

mkdir -p "$ANDROID_ARTIFACT_CACHE"

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

download_aar() {
  local group="$1"
  local module="$2"
  local version="$3"
  local variant="$4"
  local group_path="${group//.//}"
  local file="$module-$version-$variant.aar"
  local cached
  cached="$(find_gradle_aar "$group" "$module" "$version" "$file" || true)"

  if [[ -n "$cached" ]]; then
    echo "$cached"
    return
  fi

  local dest="$ANDROID_ARTIFACT_CACHE/$file"
  if [[ ! -f "$dest" ]]; then
    local url="$MAVEN_REPO_URL/$group_path/$module/$version/$file"
    echo "Downloading $url" >&2
    curl -fL "$url" -o "$dest"
  fi
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

hermes_aar="$(download_aar "com.facebook.hermes" "hermes-android" "$HERMES_ANDROID_VERSION" "$ANDROID_HERMES_VARIANT")"
react_aar="$(download_aar "com.facebook.react" "react-android" "$REACT_ANDROID_VERSION" "$ANDROID_HERMES_VARIANT")"

extract_module "$hermes_aar" "hermesvm" "$ANDROID_ARTIFACT_DIR/hermes-android"
extract_module "$react_aar" "jsi" "$ANDROID_ARTIFACT_DIR/react-android"

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
