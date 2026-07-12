#!/usr/bin/env bash

# Execute the Android bridge's dependency-free behavioral state-machine tests
# on a host JVM. Keeping this layer free of Android/JNI/OkHttp dependencies
# makes it a fast CI prerequisite while the adapter remains app-device tested.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ibex-android-java.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT

JAVAC_BIN="${JAVAC:-javac}"
JAVA_BIN="${JAVA:-java}"

"$JAVAC_BIN" \
  -encoding UTF-8 \
  -Xlint:all \
  -Werror \
  -d "$BUILD_DIR" \
  "$ROOT/platform/android/java/dev/ibex/runtime/IbexWebSocketFlowController.java" \
  "$ROOT/platform/android/tests/dev/ibex/runtime/IbexWebSocketFlowControllerBehaviorTest.java"

"$JAVA_BIN" \
  -ea \
  -cp "$BUILD_DIR" \
  dev.ibex.runtime.IbexWebSocketFlowControllerBehaviorTest
