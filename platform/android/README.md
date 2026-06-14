# Ibex Android Platform Helpers

Ibex Android platform integration is split between native C++ and Android Java:

- `src/engine/native_android_networking.cc` implements the existing native
  `native_fetch_*` and `native_ws_*` symbols used by the Hermes runtime, plus
  JNI calls for raw DNS, clipboard, location, and platform environment data.
- `src/engine/hermes_runtime_android.cc` installs the Android-only Hermes
  globals consumed by clipboard, location, locale, screen,
  appearance/accessibility, and React Native compatibility shims.
- `java/dev/ibex/runtime/IbexNetworking.java` owns the Android app integration.
  It uses OkHttp for HTTP/WebSocket and Android framework services for the
  other platform data.

Embedding apps need to:

1. Add `platform/android/java` to the Android source set, or copy
   `dev.ibex.runtime.IbexNetworking` into the app.
2. Add OkHttp to the app dependencies, for example
   `implementation("com.squareup.okhttp3:okhttp:5.4.0")`.
3. Call `ex_android_initialize(JavaVM*, Context)` from a JNI thread before
   creating an Ibex runtime that should observe Android platform data or use
   fetch/WebSocket.

The bridge configures OkHttp with redirects disabled because Ibex's JS fetch
layer implements Fetch redirect policy itself.
