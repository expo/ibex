# Ibex Android Platform Helpers

Ibex Android platform integration is split between native C++ and Android Java:

- `src/engine/native_android_networking.cc` implements the existing native
  `native_fetch_*` and `native_ws_*` symbols used by the Hermes runtime, plus
  JNI calls for raw DNS, clipboard, location, camera permission/device
  metadata, app lifecycle/configuration events, deep links, and platform
  environment data.
- `src/engine/hermes_runtime_android.cc` installs the Android-only Hermes
  globals consumed by clipboard, location, camera, locale, screen,
  appearance/accessibility, app state/linking/dimensions, and React Native
  compatibility shims.
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

If initialization happens outside an `Activity`, embedders should forward
Activity state and deep links through `IbexNetworking.notifyActivityStarted()`,
`notifyActivityStopped()`, `notifyActivityResumed()`, `notifyActivityPaused()`,
and `notifyNewIntent()` so `AppState`, `Linking`, `Dimensions`, and window
events reflect the foreground app.

Initialization also exports Android app storage roots from the `Context`.
`filesDir` seeds `HOME`, `process.cwd()`, and relative filesystem operations;
`cacheDir` seeds `TMPDIR`, `TMP`, `TEMP`, and `os.tmpdir()`. The explicit
`EXACT_ANDROID_FILES_DIR`, `EXACT_ANDROID_CACHE_DIR`,
`EXACT_ANDROID_NO_BACKUP_FILES_DIR`, `EXACT_ANDROID_CODE_CACHE_DIR`, and
`EXACT_ANDROID_EXTERNAL_FILES_DIR` environment variables are available for
code that needs a named Android storage class.

The built-in camera host bridge exposes synchronous Android camera permission,
device inventory, and session-capability metadata through CameraManager. Apps
that want native preview and capture should install a CameraX-backed session
provider before creating the Ibex runtime:

```java
IbexNetworking.setCameraHostProvider(new IbexNetworking.CameraHostProvider() {
  @Override
  public String cameraHostCall(String operation, String payloadJson) throws Exception {
    if ("camera.provider.get".equals(operation)) {
      return "{\"backend\":\"app-camerax\",\"metadata\":true,"
          + "\"sessionProviderInstalled\":true,\"preview\":true,"
          + "\"photo\":true,\"snapshot\":true,\"video\":true,"
          + "\"frameCapture\":true,\"scene\":true,\"replay\":false}";
    }
    if (operation.startsWith("camera.session.")
        || operation.startsWith("camera.photo.")
        || operation.startsWith("camera.snapshot.")
        || operation.startsWith("camera.recording.")
        || operation.startsWith("camera.focus.")
        || operation.startsWith("camera.analysis.")
        || operation.startsWith("camera.scene.")
        || operation.startsWith("camera.replay.")) {
      // Route to the app's CameraX controller and return JSON shaped like the
      // ibex camera session/capture result types.
      return cameraXHostCall(operation, payloadJson);
    }
    return null; // fall back to built-in permission/device metadata.
  }
});
```

Without a provider, Android camera sessions report an explicit unsupported
operation instead of falling back to the DOM camera controller.

The bridge configures OkHttp with redirects disabled because Ibex's JS fetch
layer implements Fetch redirect policy itself.
