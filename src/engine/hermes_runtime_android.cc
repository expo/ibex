#include "hermes_runtime_internal.h"

#include <cstdlib>
#include <string>
#include <vector>

#if defined(EXACT_PLATFORM_ANDROID)
extern "C" int android_clipboard_read_text(char** out_text, char* error, size_t error_capacity);
extern "C" int android_clipboard_write_text(const char* text, char* error, size_t error_capacity);

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

namespace {

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

void installAndroidEnvironmentGlobals(facebook::jsi::Runtime& rt) {
  char error[256] = {};

  char* platform_version = nullptr;
  if (android_get_platform_version(&platform_version, error, sizeof(error)) > 0 &&
      platform_version) {
    rt.global().setProperty(
        rt,
        "__exactPlatformVersion",
        facebook::jsi::String::createFromUtf8(rt, platform_version));
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

} // namespace
#endif

void installAndroidHostFunctions(ExactHermesRuntime* handle) {
#if defined(EXACT_PLATFORM_ANDROID)
  auto& rt = *handle->runtime;
  installAndroidEnvironmentGlobals(rt);

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
#else
  (void)handle;
#endif
}
