#include "hermes_runtime_internal.h"

#include <atomic>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(EXACT_PLATFORM_ANDROID)
extern "C" int android_clipboard_read_text(char** out_text, char* error, size_t error_capacity);
extern "C" int android_clipboard_write_text(const char* text, char* error, size_t error_capacity);
extern "C" int android_dialog_show(
    const char* type,
    const char* message,
    const char* default_value,
    char** out_result,
    int* out_is_null,
    char* error,
    size_t error_capacity);
extern "C" int android_post_animation_frame(
    uint64_t token, char* error, size_t error_capacity);

struct AndroidScreenInfo {
  double width = 0.0;
  double height = 0.0;
  double scale = 1.0;
  double font_scale = 1.0;
};

struct AndroidAccessibilityFlags {
  int prefers_reduced_motion = 0;
  int is_bold_text_enabled = 0;
  int prefers_high_contrast = 0;
  int prefers_reduced_transparency = 0;
  int is_screen_reader_enabled = 0;
  int color_scheme_dark = 0;
  int is_invert_colors_enabled = 0;
  int is_grayscale_enabled = 0;
};

struct AndroidLocationResult {
  double latitude = 0.0;
  double longitude = 0.0;
  double altitude = 0.0;
  double horizontal_accuracy = 0.0;
  double vertical_accuracy = 0.0;
  double timestamp = 0.0;
};

struct AndroidStoragePaths {
  char* files_dir = nullptr;
  char* cache_dir = nullptr;
  char* no_backup_files_dir = nullptr;
  char* code_cache_dir = nullptr;
  char* external_files_dir = nullptr;
};

extern "C" int android_get_platform_version(
    char** out_version, char* error, size_t error_capacity);
extern "C" int android_get_locale_snapshot(
    char** out_primary_tag,
    char** out_tags,
    int* uses_24_hour_clock,
    char* error,
    size_t error_capacity);
extern "C" int android_get_screen_info(
    AndroidScreenInfo* out_info, char* error, size_t error_capacity);
extern "C" int android_get_accessibility_flags(
    AndroidAccessibilityFlags* out_flags, char* error, size_t error_capacity);
extern "C" int android_location_permission_status(
    char** out_status, char* error, size_t error_capacity);
extern "C" int android_location_services_enabled(
    int* out_enabled, char* error, size_t error_capacity);
extern "C" int android_location_get_current(
    const char* accuracy,
    int timeout_ms,
    AndroidLocationResult* out_location,
    char* error,
    size_t error_capacity);
extern "C" int android_get_app_state(
    char** out_state, char* error, size_t error_capacity);
extern "C" int android_get_initial_url(
    char** out_url, char* error, size_t error_capacity);
extern "C" int android_get_storage_paths(
    AndroidStoragePaths* out_paths, char* error, size_t error_capacity);
extern "C" int android_drain_platform_events(
    char** out_events, char* error, size_t error_capacity);
extern "C" int android_camera_host_call(
    const char* operation,
    const char* payload_json,
    char** out_json,
    char* error,
    size_t error_capacity);

namespace {

std::mutex g_android_runtime_mutex;
std::unordered_set<ExactHermesRuntime*> g_android_runtimes;

struct AndroidAnimationFrameCallback {
  ExactHermesRuntime* runtime = nullptr;
  std::shared_ptr<facebook::jsi::Function> callback;
};

std::mutex g_android_animation_frame_mutex;
std::unordered_map<uint64_t, AndroidAnimationFrameCallback> g_android_animation_frame_callbacks;
std::atomic<uint64_t> g_next_android_animation_frame_token{1};

std::vector<std::string> splitLocaleTags(const char* value) {
  std::vector<std::string> tags;
  if (!value || !*value) {
    return tags;
  }
  const char* start = value;
  for (const char* cursor = value; ; ++cursor) {
    if (*cursor == '\n' || *cursor == '\0') {
      if (cursor > start) {
        tags.emplace_back(start, static_cast<size_t>(cursor - start));
      }
      if (*cursor == '\0') {
        break;
      }
      start = cursor + 1;
    }
  }
  return tags;
}

std::vector<std::string> splitLines(const std::string& value) {
  std::vector<std::string> lines;
  size_t start = 0;
  while (start < value.size()) {
    size_t end = value.find('\n', start);
    if (end == std::string::npos) {
      end = value.size();
    }
    if (end > start) {
      lines.emplace_back(value.substr(start, end - start));
    }
    start = end + 1;
  }
  return lines;
}

facebook::jsi::Array makeStringArray(
    facebook::jsi::Runtime& runtime,
    const std::vector<std::string>& values) {
  facebook::jsi::Array array(runtime, values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    array.setValueAtIndex(
        runtime, i, facebook::jsi::String::createFromUtf8(runtime, values[i]));
  }
  return array;
}

facebook::jsi::Object makeScreenInfoObject(
    facebook::jsi::Runtime& runtime,
    const AndroidScreenInfo& info) {
  facebook::jsi::Object result(runtime);
  result.setProperty(runtime, "width", facebook::jsi::Value(info.width));
  result.setProperty(runtime, "height", facebook::jsi::Value(info.height));
  result.setProperty(runtime, "scale", facebook::jsi::Value(info.scale));
  result.setProperty(runtime, "fontScale", facebook::jsi::Value(info.font_scale));
  return result;
}

facebook::jsi::Object makeDimensionsObject(
    facebook::jsi::Runtime& runtime,
    const AndroidScreenInfo& info) {
  facebook::jsi::Object dimensions(runtime);
  auto window = makeScreenInfoObject(runtime, info);
  auto screen = makeScreenInfoObject(runtime, info);
  dimensions.setProperty(runtime, "window", std::move(window));
  dimensions.setProperty(runtime, "screen", std::move(screen));
  return dimensions;
}

facebook::jsi::Object makeAccessibilityObject(
    facebook::jsi::Runtime& runtime,
    const AndroidAccessibilityFlags& flags,
    double font_scale) {
  const char* color_scheme = flags.color_scheme_dark ? "dark" : "light";
  facebook::jsi::Object accessibility(runtime);
  accessibility.setProperty(
      runtime, "prefersReducedMotion", flags.prefers_reduced_motion != 0);
  accessibility.setProperty(
      runtime, "isBoldTextEnabled", flags.is_bold_text_enabled != 0);
  accessibility.setProperty(
      runtime, "prefersHighContrast", flags.prefers_high_contrast != 0);
  accessibility.setProperty(
      runtime,
      "prefersReducedTransparency",
      flags.prefers_reduced_transparency != 0);
  accessibility.setProperty(runtime, "fontScale", facebook::jsi::Value(font_scale));
  accessibility.setProperty(
      runtime, "isScreenReaderEnabled", flags.is_screen_reader_enabled != 0);
  accessibility.setProperty(
      runtime, "colorScheme", facebook::jsi::String::createFromUtf8(runtime, color_scheme));
  accessibility.setProperty(
      runtime, "isInvertColorsEnabled", flags.is_invert_colors_enabled != 0);
  accessibility.setProperty(
      runtime, "isGrayscaleEnabled", flags.is_grayscale_enabled != 0);
  accessibility.setProperty(runtime, "dynamicTypeSize", facebook::jsi::Value::null());
  return accessibility;
}

facebook::jsi::Object makeAppearanceObject(
    facebook::jsi::Runtime& runtime,
    const AndroidAccessibilityFlags& flags) {
  facebook::jsi::Object appearance(runtime);
  appearance.setProperty(
      runtime,
      "colorScheme",
      facebook::jsi::String::createFromUtf8(runtime, flags.color_scheme_dark ? "dark" : "light"));
  appearance.setProperty(runtime, "reducedMotion", flags.prefers_reduced_motion != 0);
  return appearance;
}

void freeAndroidStoragePaths(AndroidStoragePaths& paths) {
  std::free(paths.files_dir);
  std::free(paths.cache_dir);
  std::free(paths.no_backup_files_dir);
  std::free(paths.code_cache_dir);
  std::free(paths.external_files_dir);
  paths = AndroidStoragePaths{};
}

facebook::jsi::Object makeStoragePathsObject(
    facebook::jsi::Runtime& runtime,
    const AndroidStoragePaths& paths) {
  facebook::jsi::Object storage(runtime);
  storage.setProperty(
      runtime,
      "filesDir",
      facebook::jsi::String::createFromUtf8(runtime, paths.files_dir ? paths.files_dir : ""));
  storage.setProperty(
      runtime,
      "cacheDir",
      facebook::jsi::String::createFromUtf8(runtime, paths.cache_dir ? paths.cache_dir : ""));
  storage.setProperty(
      runtime,
      "noBackupFilesDir",
      facebook::jsi::String::createFromUtf8(
          runtime, paths.no_backup_files_dir ? paths.no_backup_files_dir : ""));
  storage.setProperty(
      runtime,
      "codeCacheDir",
      facebook::jsi::String::createFromUtf8(
          runtime, paths.code_cache_dir ? paths.code_cache_dir : ""));
  storage.setProperty(
      runtime,
      "externalFilesDir",
      facebook::jsi::String::createFromUtf8(
          runtime, paths.external_files_dir ? paths.external_files_dir : ""));
  return storage;
}

facebook::jsi::Object makeAndroidPlatformState(facebook::jsi::Runtime& runtime) {
  char error[256] = {};
  facebook::jsi::Object state(runtime);

  // @ref LLP 0008#os-info - Android OS metadata uses the Java host SDK version, not Linux kernel identity.
  char* platform_version = nullptr;
  if (android_get_platform_version(&platform_version, error, sizeof(error)) > 0 &&
      platform_version) {
    state.setProperty(
        runtime,
        "platformVersion",
        facebook::jsi::String::createFromUtf8(runtime, platform_version));
  }
  std::free(platform_version);

  char* app_state = nullptr;
  if (android_get_app_state(&app_state, error, sizeof(error)) > 0 && app_state) {
    state.setProperty(
        runtime, "appState", facebook::jsi::String::createFromUtf8(runtime, app_state));
  } else {
    state.setProperty(
        runtime, "appState", facebook::jsi::String::createFromUtf8(runtime, "unknown"));
  }
  std::free(app_state);

  char* initial_url = nullptr;
  if (android_get_initial_url(&initial_url, error, sizeof(error)) > 0 && initial_url && *initial_url) {
    state.setProperty(
        runtime, "initialURL", facebook::jsi::String::createFromUtf8(runtime, initial_url));
  } else {
    state.setProperty(runtime, "initialURL", facebook::jsi::Value::null());
  }
  std::free(initial_url);

  char* primary_tag = nullptr;
  char* joined_tags = nullptr;
  int uses_24_hour_clock = 0;
  if (android_get_locale_snapshot(
          &primary_tag,
          &joined_tags,
          &uses_24_hour_clock,
          error,
          sizeof(error)) > 0 &&
      primary_tag &&
      joined_tags) {
    std::vector<std::string> tags = splitLocaleTags(joined_tags);
    if (tags.empty()) {
      tags.emplace_back(primary_tag);
    }
    facebook::jsi::Object locale(runtime);
    locale.setProperty(
        runtime, "tag", facebook::jsi::String::createFromUtf8(runtime, primary_tag));
    auto tags_array = makeStringArray(runtime, tags);
    locale.setProperty(runtime, "tags", std::move(tags_array));
    locale.setProperty(runtime, "uses24Hour", uses_24_hour_clock != 0);
    state.setProperty(runtime, "locale", std::move(locale));
  }
  std::free(primary_tag);
  std::free(joined_tags);

  AndroidScreenInfo screen_info;
  bool has_screen_info = android_get_screen_info(&screen_info, error, sizeof(error)) > 0;
  if (has_screen_info) {
    auto screen = makeScreenInfoObject(runtime, screen_info);
    auto dimensions = makeDimensionsObject(runtime, screen_info);
    state.setProperty(runtime, "screen", std::move(screen));
    state.setProperty(runtime, "dimensions", std::move(dimensions));
  }

  AndroidAccessibilityFlags flags;
  if (android_get_accessibility_flags(&flags, error, sizeof(error)) > 0) {
    auto appearance = makeAppearanceObject(runtime, flags);
    auto accessibility =
        makeAccessibilityObject(runtime, flags, has_screen_info ? screen_info.font_scale : 1.0);
    state.setProperty(runtime, "appearance", std::move(appearance));
    state.setProperty(runtime, "accessibility", std::move(accessibility));
  }

  AndroidStoragePaths storage_paths;
  if (android_get_storage_paths(&storage_paths, error, sizeof(error)) > 0) {
    auto storage = makeStoragePathsObject(runtime, storage_paths);
    state.setProperty(runtime, "storage", std::move(storage));
    freeAndroidStoragePaths(storage_paths);
  }

  return state;
}

void installAndroidEnvironmentGlobals(facebook::jsi::Runtime& rt) {
  char error[256] = {};

  char* platform_version = nullptr;
  if (android_get_platform_version(&platform_version, error, sizeof(error)) > 0 &&
      platform_version) {
    // @ref LLP 0008#os-info - Android OS metadata uses the Java host SDK version, not Linux kernel identity.
    std::string android_os_version = std::string("Android ") + platform_version;
    rt.global().setProperty(
        rt,
        "__exactPlatformVersion",
        facebook::jsi::String::createFromUtf8(rt, platform_version));
    auto process_value = rt.global().getProperty(rt, "process");
    if (process_value.isObject()) {
      auto process = process_value.asObject(rt);
      process.setProperty(
          rt,
          "__exactOSRelease",
          facebook::jsi::String::createFromUtf8(rt, platform_version));
      process.setProperty(
          rt,
          "__exactOSVersion",
          facebook::jsi::String::createFromUtf8(rt, android_os_version));
    }
    std::free(platform_version);
  }

  char* primary_tag = nullptr;
  char* joined_tags = nullptr;
  int uses_24_hour_clock = 0;
  if (android_get_locale_snapshot(
          &primary_tag,
          &joined_tags,
          &uses_24_hour_clock,
          error,
          sizeof(error)) > 0 &&
      primary_tag &&
      joined_tags) {
    std::vector<std::string> tags = splitLocaleTags(joined_tags);
    if (tags.empty()) {
      tags.emplace_back(primary_tag);
    }

    facebook::jsi::Object snapshot(rt);
    snapshot.setProperty(
        rt, "tag", facebook::jsi::String::createFromUtf8(rt, primary_tag));
    facebook::jsi::Array tags_array(rt, tags.size());
    for (size_t i = 0; i < tags.size(); ++i) {
      tags_array.setValueAtIndex(
          rt, i, facebook::jsi::String::createFromUtf8(rt, tags[i]));
    }
    snapshot.setProperty(rt, "tags", std::move(tags_array));
    snapshot.setProperty(rt, "uses24Hour", uses_24_hour_clock != 0);

    rt.global().setProperty(rt, "__exactLocaleSnapshot", std::move(snapshot));
    rt.global().setProperty(
        rt, "__exactLocale", facebook::jsi::String::createFromUtf8(rt, primary_tag));
    rt.global().setProperty(
        rt, "__exactLanguage", facebook::jsi::String::createFromUtf8(rt, primary_tag));
  }
  std::free(primary_tag);
  std::free(joined_tags);

  char* app_state = nullptr;
  if (android_get_app_state(&app_state, error, sizeof(error)) > 0 && app_state) {
    rt.global().setProperty(
        rt, "__exactAppState", facebook::jsi::String::createFromUtf8(rt, app_state));
  }
  std::free(app_state);

  char* initial_url = nullptr;
  if (android_get_initial_url(&initial_url, error, sizeof(error)) > 0 && initial_url && *initial_url) {
    rt.global().setProperty(
        rt, "__exactInitialURL", facebook::jsi::String::createFromUtf8(rt, initial_url));
  } else {
    rt.global().setProperty(rt, "__exactInitialURL", facebook::jsi::Value::null());
  }
  std::free(initial_url);

  AndroidStoragePaths storage_paths;
  if (android_get_storage_paths(&storage_paths, error, sizeof(error)) > 0) {
    // @ref LLP 0008#android-backend-matrix — Android app storage roots come
    // from Context directories and seed HOME/TMPDIR/cwd through the JNI bridge.
    auto storage = makeStoragePathsObject(rt, storage_paths);
    rt.global().setProperty(rt, "__exactAndroidStoragePaths", std::move(storage));
    freeAndroidStoragePaths(storage_paths);
  }

  AndroidScreenInfo initial_screen_info;
  bool has_screen_info =
      android_get_screen_info(&initial_screen_info, error, sizeof(error)) > 0;
  if (has_screen_info) {
    auto getScreenInfoFn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, "__exactGetScreenInfo"),
        0,
        [initial_screen_info](
            facebook::jsi::Runtime& runtime,
            const facebook::jsi::Value&,
            const facebook::jsi::Value*,
            size_t) -> facebook::jsi::Value {
          AndroidScreenInfo current_info;
          char current_error[256] = {};
          if (android_get_screen_info(
                  &current_info, current_error, sizeof(current_error)) <= 0) {
            current_info = initial_screen_info;
          }
          return makeScreenInfoObject(runtime, current_info);
        });
    rt.global().setProperty(rt, "__exactGetScreenInfo", std::move(getScreenInfoFn));
  }

  AndroidAccessibilityFlags flags;
  if (android_get_accessibility_flags(&flags, error, sizeof(error)) > 0) {
    const char* color_scheme = flags.color_scheme_dark ? "dark" : "light";

    // @ref LLP 0008#android-backend-matrix — Android environment globals are
    // populated from Resources/AccessibilityManager so JS platform shims do not
    // fall back to iOS-flavored defaults on Android.
    facebook::jsi::Object appearance(rt);
    appearance.setProperty(
        rt, "colorScheme", facebook::jsi::String::createFromUtf8(rt, color_scheme));
    appearance.setProperty(rt, "reducedMotion", flags.prefers_reduced_motion != 0);
    rt.global().setProperty(rt, "__exactAppearanceState", std::move(appearance));

    facebook::jsi::Object accessibility(rt);
    accessibility.setProperty(
        rt, "prefersReducedMotion", flags.prefers_reduced_motion != 0);
    accessibility.setProperty(
        rt, "isBoldTextEnabled", flags.is_bold_text_enabled != 0);
    accessibility.setProperty(
        rt, "prefersHighContrast", flags.prefers_high_contrast != 0);
    accessibility.setProperty(
        rt,
        "prefersReducedTransparency",
        flags.prefers_reduced_transparency != 0);
    accessibility.setProperty(
        rt,
        "fontScale",
        facebook::jsi::Value(has_screen_info ? initial_screen_info.font_scale : 1.0));
    accessibility.setProperty(
        rt, "isScreenReaderEnabled", flags.is_screen_reader_enabled != 0);
    accessibility.setProperty(
        rt, "colorScheme", facebook::jsi::String::createFromUtf8(rt, color_scheme));
    accessibility.setProperty(
        rt, "isInvertColorsEnabled", flags.is_invert_colors_enabled != 0);
    accessibility.setProperty(
        rt, "isGrayscaleEnabled", flags.is_grayscale_enabled != 0);
    accessibility.setProperty(rt, "dynamicTypeSize", facebook::jsi::Value::null());
    rt.global().setProperty(rt, "__exactAccessibilitySnapshot", std::move(accessibility));
  }
}

void installAndroidLocationBridge(facebook::jsi::Runtime& rt) {
  facebook::jsi::Object location(rt);

  auto permissionStatusFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getPermissionStatus"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char* status = nullptr;
        char error[256] = {};
        int rc = android_location_permission_status(&status, error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android location permission query failed");
        }
        std::string copy = status ? status : "denied";
        if (status) {
          std::free(status);
        }
        return facebook::jsi::String::createFromUtf8(runtime, copy);
      });
  location.setProperty(rt, "getPermissionStatus", std::move(permissionStatusFn));

  auto servicesEnabledFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "isLocationServicesEnabled"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        int enabled = 0;
        char error[256] = {};
        int rc = android_location_services_enabled(&enabled, error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android location services query failed");
        }
        return facebook::jsi::Value(enabled != 0);
      });
  location.setProperty(rt, "isLocationServicesEnabled", std::move(servicesEnabledFn));

  auto currentLocationFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "getCurrentLocation"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string accuracy =
            count > 0 ? valueToString(runtime, args[0]) : std::string("hundredMeters");
        int timeout_ms = 10000;
        if (count > 1 && args[1].isNumber()) {
          timeout_ms = static_cast<int>(args[1].asNumber());
        }
        AndroidLocationResult result;
        char error[256] = {};
        int rc = android_location_get_current(
            accuracy.c_str(), timeout_ms, &result, error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android current location query failed");
        }

        facebook::jsi::Object out(runtime);
        out.setProperty(runtime, "latitude", facebook::jsi::Value(result.latitude));
        out.setProperty(runtime, "longitude", facebook::jsi::Value(result.longitude));
        out.setProperty(runtime, "altitude", facebook::jsi::Value(result.altitude));
        out.setProperty(
            runtime,
            "horizontalAccuracy",
            facebook::jsi::Value(result.horizontal_accuracy));
        out.setProperty(
            runtime,
            "verticalAccuracy",
            facebook::jsi::Value(result.vertical_accuracy));
        out.setProperty(runtime, "timestamp", facebook::jsi::Value(result.timestamp));
        return out;
      });
  location.setProperty(rt, "getCurrentLocation", std::move(currentLocationFn));

  // @ref LLP 0008#android-backend-matrix — Android geolocation uses the
  // platform LocationManager through the initialized app Context.
  rt.global().setProperty(rt, "__exactAndroidLocation", std::move(location));
}

void installAndroidCameraBridge(facebook::jsi::Runtime& rt) {
  facebook::jsi::Object metadata(rt);
  metadata.setProperty(rt, "version", facebook::jsi::String::createFromUtf8(rt, "0.3.0"));
  metadata.setProperty(rt, "moduleId", facebook::jsi::Value::null());
  metadata.setProperty(rt, "stateOffset", facebook::jsi::Value::null());
  metadata.setProperty(rt, "stateSize", facebook::jsi::Value(0));
  metadata.setProperty(
      rt,
      "backend",
      facebook::jsi::String::createFromUtf8(rt, "android-framework"));
  rt.global().setProperty(rt, "__exactAndroidCameraMetadata", std::move(metadata));

  auto cameraHostCallFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAndroidCameraHostCall"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string operation = count > 0 ? valueToString(runtime, args[0]) : std::string("");
        std::string payload = count > 1 ? valueToString(runtime, args[1]) : std::string("{}");
        char* json = nullptr;
        char error[256] = {};
        int rc = android_camera_host_call(
            operation.c_str(), payload.c_str(), &json, error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android camera host call failed");
        }

        std::string json_copy = json ? json : "";
        if (json) {
          std::free(json);
        }
        if (json_copy.empty() || json_copy == "null" || json_copy == "undefined") {
          return facebook::jsi::Value::null();
        }

        auto jsonGlobal = runtime.global().getPropertyAsObject(runtime, "JSON");
        auto parseFn = jsonGlobal.getPropertyAsFunction(runtime, "parse");
        return parseFn.call(
            runtime, facebook::jsi::String::createFromUtf8(runtime, json_copy));
      });

  // @ref LLP 0008#android-backend-matrix — Android camera inventory and
  // permission state come from framework camera services instead of web
  // getUserMedia/virtual-camera fallbacks.
  rt.global().setProperty(
      rt, "__exactAndroidCameraHostCall", std::move(cameraHostCallFn));
}

bool dispatchAndroidPlatformEvents(ExactHermesRuntime* handle) {
  if (!handle || !handle->runtime) {
    return false;
  }
  auto& rt = *handle->runtime;
  auto handler_value = rt.global().getProperty(rt, "__exactAndroidDispatchPlatformEvent");
  if (!handler_value.isObject()) {
    return false;
  }
  auto handler_object = handler_value.asObject(rt);
  if (!handler_object.isFunction(rt)) {
    return false;
  }

  char* joined_events = nullptr;
  char error[256] = {};
  if (android_drain_platform_events(&joined_events, error, sizeof(error)) <= 0) {
    return false;
  }
  std::string events = joined_events ? joined_events : "";
  std::free(joined_events);
  if (events.empty()) {
    return true;
  }

  auto handler = handler_object.asFunction(rt);
  for (const auto& event_json : splitLines(events)) {
    auto state = makeAndroidPlatformState(rt);
    handler.call(
        rt,
        facebook::jsi::String::createFromUtf8(rt, event_json),
        std::move(state));
  }
  return true;
}

void registerAndroidRuntime(ExactHermesRuntime* handle) {
  if (!handle) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_android_runtime_mutex);
  g_android_runtimes.insert(handle);
}

uint64_t registerAndroidAnimationFrameCallback(
    ExactHermesRuntime* handle, facebook::jsi::Function callback) {
  uint64_t token = g_next_android_animation_frame_token.fetch_add(1, std::memory_order_relaxed);
  if (token == 0) {
    token = g_next_android_animation_frame_token.fetch_add(1, std::memory_order_relaxed);
  }
  std::lock_guard<std::mutex> lock(g_android_animation_frame_mutex);
  g_android_animation_frame_callbacks[token] = AndroidAnimationFrameCallback{
      handle, std::make_shared<facebook::jsi::Function>(std::move(callback))};
  return token;
}

void removeAndroidAnimationFrameCallback(uint64_t token) {
  std::lock_guard<std::mutex> lock(g_android_animation_frame_mutex);
  g_android_animation_frame_callbacks.erase(token);
}

void removeAndroidAnimationFrameCallbacksForRuntime(ExactHermesRuntime* handle) {
  std::lock_guard<std::mutex> lock(g_android_animation_frame_mutex);
  for (auto it = g_android_animation_frame_callbacks.begin();
       it != g_android_animation_frame_callbacks.end();) {
    if (it->second.runtime == handle) {
      it = g_android_animation_frame_callbacks.erase(it);
    } else {
      ++it;
    }
  }
}

} // namespace
#endif

void installAndroidHostFunctions(ExactHermesRuntime* handle) {
#if defined(EXACT_PLATFORM_ANDROID)
  registerAndroidRuntime(handle);

  auto& rt = *handle->runtime;
  installAndroidEnvironmentGlobals(rt);
  installAndroidLocationBridge(rt);
  installAndroidCameraBridge(rt);

  auto getPlatformStateFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAndroidGetPlatformState"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return makeAndroidPlatformState(runtime);
      });
  rt.global().setProperty(
      rt, "__exactAndroidGetPlatformState", std::move(getPlatformStateFn));

  auto drainPlatformEventsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAndroidDrainPlatformEvents"),
      0,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
        (void)runtime;
        dispatchAndroidPlatformEvents(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(
      rt, "__exactAndroidDrainPlatformEvents", std::move(drainPlatformEventsFn));

  auto clipboardReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactClipboardRead"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        char* text = nullptr;
        char error[256] = {};
        // @ref LLP 0008#android-backend-matrix — Android clipboard uses the
        // app Context's ClipboardManager through the Android Java bridge.
        int rc = android_clipboard_read_text(&text, error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android clipboard read failed");
        }
        std::string copy = text ? text : "";
        if (text) {
          std::free(text);
        }
        return facebook::jsi::String::createFromUtf8(runtime, copy);
      });
  rt.global().setProperty(rt, "__exactClipboardRead", std::move(clipboardReadFn));

  auto clipboardWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactClipboardWrite"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string text =
            count > 0 ? valueToString(runtime, args[0]) : std::string("");
        char error[256] = {};
        int rc = android_clipboard_write_text(text.c_str(), error, sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android clipboard write failed");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactClipboardWrite", std::move(clipboardWriteFn));

  auto requestAnimationFrameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRequestAnimationFrame"),
      1,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isObject() ||
            !args[0].asObject(runtime).isFunction(runtime)) {
          return facebook::jsi::Value(false);
        }
        auto callback = args[0].asObject(runtime).asFunction(runtime);
        uint64_t token = registerAndroidAnimationFrameCallback(handle, std::move(callback));
        char error[256] = {};
        // @ref LLP 0008#android-backend-matrix — Android RAF uses
        // Choreographer through the Java bridge and marshals back to Hermes.
        int rc = android_post_animation_frame(token, error, sizeof(error));
        if (rc <= 0) {
          removeAndroidAnimationFrameCallback(token);
          return facebook::jsi::Value(false);
        }
        return facebook::jsi::Value(true);
      });
  rt.global().setProperty(
      rt, "__exactRequestAnimationFrame", std::move(requestAnimationFrameFn));

  auto nativeDialogFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactNativeDialog"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string type = count > 0 ? valueToString(runtime, args[0]) : std::string("");
        std::string message = count > 1 ? valueToString(runtime, args[1]) : std::string("");
        std::string default_value =
            count > 2 ? valueToString(runtime, args[2]) : std::string("");
        char* result = nullptr;
        int is_null = 0;
        char error[256] = {};
        // @ref LLP 0008#android-backend-matrix - Android window dialogs use
        // the current Activity's native AlertDialog through the Java bridge.
        int rc = android_dialog_show(
            type.c_str(),
            message.c_str(),
            default_value.c_str(),
            &result,
            &is_null,
            error,
            sizeof(error));
        if (rc < 0) {
          throw facebook::jsi::JSError(
              runtime, error[0] ? error : "Android native dialog failed");
        }
        if (is_null) {
          return facebook::jsi::Value::null();
        }
        std::string copy = result ? result : "";
        if (result) {
          std::free(result);
        }
        return facebook::jsi::String::createFromUtf8(runtime, copy);
      });
  rt.global().setProperty(rt, "__exactNativeDialog", std::move(nativeDialogFn));
#else
  (void)handle;
#endif
}

void unregisterAndroidHostFunctions(ExactHermesRuntime* handle) {
#if defined(EXACT_PLATFORM_ANDROID)
  {
    std::lock_guard<std::mutex> lock(g_android_runtime_mutex);
    g_android_runtimes.erase(handle);
  }
  removeAndroidAnimationFrameCallbacksForRuntime(handle);
#else
  (void)handle;
#endif
}

extern "C" void android_animation_frame_callback(uint64_t token, int64_t frame_time_nanos) {
#if defined(EXACT_PLATFORM_ANDROID)
  AndroidAnimationFrameCallback entry;
  {
    std::lock_guard<std::mutex> lock(g_android_animation_frame_mutex);
    auto it = g_android_animation_frame_callbacks.find(token);
    if (it == g_android_animation_frame_callbacks.end()) {
      return;
    }
    entry = std::move(it->second);
    g_android_animation_frame_callbacks.erase(it);
  }
  if (!entry.runtime || !entry.callback || !runtimeIsAlive(entry.runtime)) {
    return;
  }
  double frame_time_ms = static_cast<double>(frame_time_nanos) / 1000000.0;
  pushRuntimeCallback(
      entry.runtime,
      [callback = entry.callback, frame_time_ms](facebook::jsi::Runtime& runtime) {
        callback->call(runtime, facebook::jsi::Value(frame_time_ms));
      });
#else
  (void)token;
  (void)frame_time_nanos;
#endif
}

extern "C" void android_platform_event_available(void) {
#if defined(EXACT_PLATFORM_ANDROID)
  std::vector<ExactHermesRuntime*> runtimes;
  {
    std::lock_guard<std::mutex> lock(g_android_runtime_mutex);
    runtimes.assign(g_android_runtimes.begin(), g_android_runtimes.end());
  }
  for (auto* runtime : runtimes) {
    if (!runtimeIsAlive(runtime)) {
      continue;
    }
    pushRuntimeCallback(runtime, [runtime](facebook::jsi::Runtime&) {
      dispatchAndroidPlatformEvents(runtime);
    });
  }
#endif
}
