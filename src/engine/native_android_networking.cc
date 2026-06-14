/**
 * native_android_networking.cc
 *
 * Android Fetch/WebSocket plus app-context platform bridge implementation.
 *
 * @ref LLP 0008#android-backend-matrix — Android networking uses OkHttp
 * through a Java/JNI bridge while preserving Ibex's native C++ runtime ABI;
 * the same bridge exposes Android framework data that JS platform shims need.
 */

#include <jni.h>

#include <android/log.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

typedef void (*NativeFetchResponseCallback)(
    uint32_t request_id,
    int status,
    const char* status_text,
    const char* headers,
    const uint8_t* body,
    size_t body_length,
    void* context);

typedef void (*NativeWsOpenCallback)(
    uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(
    uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(
    uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);

extern "C" void native_ws_retain_context(void* context);
extern "C" void native_ws_release_context(void* context);
extern "C" void android_platform_event_available(void);

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

namespace {

constexpr const char* kLogTag = "IbexNetworking";
constexpr const char* kNetworkingClassSlash = "dev/ibex/runtime/IbexNetworking";
constexpr const char* kNetworkingClassDot = "dev.ibex.runtime.IbexNetworking";

struct AndroidFetchRequest {
  NativeFetchResponseCallback response_callback = nullptr;
  void* context = nullptr;
};

struct AndroidWebSocketEntry {
  uint32_t ws_id = 0;
  NativeWsOpenCallback open_cb = nullptr;
  NativeWsMessageCallback message_cb = nullptr;
  NativeWsCloseCallback close_cb = nullptr;
  NativeWsErrorCallback error_cb = nullptr;
  NativeWsBytesSentCallback bytes_sent_cb = nullptr;

  std::mutex context_mutex;
  void* context = nullptr;
  std::atomic<bool> closed{false};
};

struct AndroidNetworkingMethods {
  jclass cls = nullptr;
  jmethodID fetch = nullptr;
  jmethodID cancel_fetch = nullptr;
  jmethodID connect_ws = nullptr;
  jmethodID send_ws = nullptr;
  jmethodID close_ws = nullptr;
  jmethodID pause_ws = nullptr;
  jmethodID resume_ws = nullptr;
  jmethodID set_ws_flow_controlled = nullptr;
  jmethodID dns_query = nullptr;
  jmethodID clipboard_read_text = nullptr;
  jmethodID clipboard_write_text = nullptr;
  jmethodID platform_version = nullptr;
  jmethodID locale_tags = nullptr;
  jmethodID uses_24_hour_clock = nullptr;
  jmethodID screen_info = nullptr;
  jmethodID accessibility_flags = nullptr;
  jmethodID location_permission_status = nullptr;
  jmethodID location_services_enabled = nullptr;
  jmethodID current_location = nullptr;
  jmethodID app_state = nullptr;
  jmethodID initial_url = nullptr;
  jmethodID drain_platform_events = nullptr;
};

std::mutex g_jni_mutex;
JavaVM* g_java_vm = nullptr;
jobject g_application_context = nullptr;
jclass g_networking_class = nullptr;
jmethodID g_initialize = nullptr;
jmethodID g_fetch = nullptr;
jmethodID g_cancel_fetch = nullptr;
jmethodID g_connect_ws = nullptr;
jmethodID g_send_ws = nullptr;
jmethodID g_close_ws = nullptr;
jmethodID g_pause_ws = nullptr;
jmethodID g_resume_ws = nullptr;
jmethodID g_set_ws_flow_controlled = nullptr;
jmethodID g_dns_query = nullptr;
jmethodID g_clipboard_read_text = nullptr;
jmethodID g_clipboard_write_text = nullptr;
jmethodID g_platform_version = nullptr;
jmethodID g_locale_tags = nullptr;
jmethodID g_uses_24_hour_clock = nullptr;
jmethodID g_screen_info = nullptr;
jmethodID g_accessibility_flags = nullptr;
jmethodID g_location_permission_status = nullptr;
jmethodID g_location_services_enabled = nullptr;
jmethodID g_current_location = nullptr;
jmethodID g_app_state = nullptr;
jmethodID g_initial_url = nullptr;
jmethodID g_drain_platform_events = nullptr;

std::mutex g_fetch_mutex;
std::unordered_map<uint32_t, AndroidFetchRequest> g_fetch_requests;

std::mutex g_ws_mutex;
std::unordered_map<uint32_t, std::shared_ptr<AndroidWebSocketEntry>> g_ws_connections;
std::atomic<uint32_t> g_next_ws_id{1};

bool clear_pending_exception(JNIEnv* env, const char* where) {
  if (!env || !env->ExceptionCheck()) {
    return false;
  }
  env->ExceptionDescribe();
  env->ExceptionClear();
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "JNI exception in %s", where);
  return true;
}

class JniEnvScope {
 public:
  JniEnvScope() {
    JavaVM* vm = nullptr;
    {
      std::lock_guard<std::mutex> lock(g_jni_mutex);
      vm = g_java_vm;
    }
    if (!vm) {
      return;
    }

    void* raw_env = nullptr;
    const jint get_env_result = vm->GetEnv(&raw_env, JNI_VERSION_1_6);
    if (get_env_result == JNI_OK) {
      env_ = static_cast<JNIEnv*>(raw_env);
      return;
    }
    if (get_env_result == JNI_EDETACHED) {
      if (vm->AttachCurrentThread(&env_, nullptr) == JNI_OK) {
        vm_ = vm;
        attached_ = true;
      }
    }
  }

  ~JniEnvScope() {
    if (attached_ && vm_) {
      vm_->DetachCurrentThread();
    }
  }

  JNIEnv* env() const {
    return env_;
  }

 private:
  JavaVM* vm_ = nullptr;
  JNIEnv* env_ = nullptr;
  bool attached_ = false;
};

std::string jstring_to_string(JNIEnv* env, jstring value) {
  if (!env || !value) {
    return "";
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (!chars) {
    clear_pending_exception(env, "GetStringUTFChars");
    return "";
  }
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

char* malloc_string_copy(const std::string& value) {
  auto* copy = static_cast<char*>(std::malloc(value.size() + 1));
  if (!copy) {
    return nullptr;
  }
  std::memcpy(copy, value.c_str(), value.size() + 1);
  return copy;
}

jstring string_to_jstring(JNIEnv* env, const char* value) {
  if (!env) {
    return nullptr;
  }
  auto result = env->NewStringUTF(value ? value : "");
  clear_pending_exception(env, "NewStringUTF");
  return result;
}

jbyteArray bytes_to_jarray(JNIEnv* env, const uint8_t* data, size_t length) {
  if (!env) {
    return nullptr;
  }
  auto array = env->NewByteArray(static_cast<jsize>(length));
  if (!array || clear_pending_exception(env, "NewByteArray")) {
    return nullptr;
  }
  if (data && length > 0) {
    env->SetByteArrayRegion(
        array,
        0,
        static_cast<jsize>(length),
        reinterpret_cast<const jbyte*>(data));
    if (clear_pending_exception(env, "SetByteArrayRegion")) {
      env->DeleteLocalRef(array);
      return nullptr;
    }
  }
  return array;
}

std::vector<uint8_t> jarray_to_bytes(JNIEnv* env, jbyteArray array) {
  std::vector<uint8_t> out;
  if (!env || !array) {
    return out;
  }
  const jsize length = env->GetArrayLength(array);
  if (length <= 0) {
    return out;
  }
  out.resize(static_cast<size_t>(length));
  env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte*>(out.data()));
  if (clear_pending_exception(env, "GetByteArrayRegion")) {
    out.clear();
  }
  return out;
}

jclass find_networking_class(JNIEnv* env, jobject application_context) {
  if (!env) {
    return nullptr;
  }

  jclass direct = env->FindClass(kNetworkingClassSlash);
  if (direct && !clear_pending_exception(env, "FindClass IbexNetworking")) {
    return direct;
  }
  clear_pending_exception(env, "FindClass IbexNetworking");

  if (!application_context) {
    return nullptr;
  }

  jclass context_cls = env->GetObjectClass(application_context);
  if (!context_cls || clear_pending_exception(env, "Context.getClass")) {
    return nullptr;
  }

  jmethodID get_class_loader =
      env->GetMethodID(context_cls, "getClassLoader", "()Ljava/lang/ClassLoader;");
  env->DeleteLocalRef(context_cls);
  if (!get_class_loader || clear_pending_exception(env, "Context.getClassLoader method")) {
    return nullptr;
  }

  jobject class_loader = env->CallObjectMethod(application_context, get_class_loader);
  if (!class_loader || clear_pending_exception(env, "Context.getClassLoader")) {
    return nullptr;
  }

  jclass class_loader_cls = env->FindClass("java/lang/ClassLoader");
  if (!class_loader_cls || clear_pending_exception(env, "FindClass ClassLoader")) {
    env->DeleteLocalRef(class_loader);
    return nullptr;
  }

  jmethodID load_class =
      env->GetMethodID(class_loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  env->DeleteLocalRef(class_loader_cls);
  if (!load_class || clear_pending_exception(env, "ClassLoader.loadClass method")) {
    env->DeleteLocalRef(class_loader);
    return nullptr;
  }

  jstring class_name = env->NewStringUTF(kNetworkingClassDot);
  if (!class_name || clear_pending_exception(env, "NewStringUTF class name")) {
    env->DeleteLocalRef(class_loader);
    return nullptr;
  }

  auto loaded = static_cast<jclass>(env->CallObjectMethod(class_loader, load_class, class_name));
  env->DeleteLocalRef(class_name);
  env->DeleteLocalRef(class_loader);
  if (!loaded || clear_pending_exception(env, "ClassLoader.loadClass IbexNetworking")) {
    return nullptr;
  }
  return loaded;
}

void JNICALL android_fetch_did_complete(
    JNIEnv* env,
    jclass,
    jint request_id,
    jint status,
    jstring status_text,
    jstring headers,
    jbyteArray body) {
  AndroidFetchRequest request;
  {
    std::lock_guard<std::mutex> lock(g_fetch_mutex);
    auto it = g_fetch_requests.find(static_cast<uint32_t>(request_id));
    if (it == g_fetch_requests.end()) {
      return;
    }
    request = it->second;
    g_fetch_requests.erase(it);
  }

  if (!request.response_callback) {
    return;
  }

  std::string status_text_copy = jstring_to_string(env, status_text);
  std::string headers_copy = jstring_to_string(env, headers);
  std::vector<uint8_t> body_copy = jarray_to_bytes(env, body);

  request.response_callback(
      static_cast<uint32_t>(request_id),
      static_cast<int>(status),
      status_text_copy.c_str(),
      headers_copy.empty() ? nullptr : headers_copy.c_str(),
      body_copy.empty() ? nullptr : body_copy.data(),
      body_copy.size(),
      request.context);
}

std::shared_ptr<AndroidWebSocketEntry> get_ws_entry(uint32_t ws_id) {
  std::lock_guard<std::mutex> lock(g_ws_mutex);
  auto it = g_ws_connections.find(ws_id);
  return it == g_ws_connections.end() ? nullptr : it->second;
}

void* retain_ws_callback_context(const std::shared_ptr<AndroidWebSocketEntry>& entry) {
  if (!entry) {
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(entry->context_mutex);
  if (!entry->context) {
    return nullptr;
  }
  native_ws_retain_context(entry->context);
  return entry->context;
}

void release_ws_entry_context(const std::shared_ptr<AndroidWebSocketEntry>& entry) {
  if (!entry) {
    return;
  }
  void* context = nullptr;
  {
    std::lock_guard<std::mutex> lock(entry->context_mutex);
    context = entry->context;
    entry->context = nullptr;
  }
  if (context) {
    native_ws_release_context(context);
  }
}

void remove_ws_entry(uint32_t ws_id) {
  std::shared_ptr<AndroidWebSocketEntry> entry;
  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    auto it = g_ws_connections.find(ws_id);
    if (it == g_ws_connections.end()) {
      return;
    }
    entry = it->second;
    g_ws_connections.erase(it);
  }
  if (entry) {
    entry->closed.store(true, std::memory_order_relaxed);
    release_ws_entry_context(entry);
  }
}

void call_ws_open(
    const std::shared_ptr<AndroidWebSocketEntry>& entry,
    const char* protocol,
    const char* extensions) {
  void* context = retain_ws_callback_context(entry);
  if (!entry || !context || !entry->open_cb) {
    if (context) {
      native_ws_release_context(context);
    }
    return;
  }
  entry->open_cb(entry->ws_id, protocol ? protocol : "", extensions ? extensions : "", context);
  native_ws_release_context(context);
}

void call_ws_message(
    const std::shared_ptr<AndroidWebSocketEntry>& entry,
    const uint8_t* data,
    size_t length,
    bool is_text) {
  void* context = retain_ws_callback_context(entry);
  if (!entry || !context || !entry->message_cb) {
    if (context) {
      native_ws_release_context(context);
    }
    return;
  }
  const uint8_t empty = 0;
  entry->message_cb(
      entry->ws_id,
      data ? data : &empty,
      length,
      is_text ? 1 : 0,
      context);
  native_ws_release_context(context);
}

void call_ws_error(const std::shared_ptr<AndroidWebSocketEntry>& entry, const char* message) {
  void* context = retain_ws_callback_context(entry);
  if (!entry || !context || !entry->error_cb) {
    if (context) {
      native_ws_release_context(context);
    }
    return;
  }
  entry->error_cb(entry->ws_id, message ? message : "WebSocket error", context);
  native_ws_release_context(context);
}

void call_ws_close(
    const std::shared_ptr<AndroidWebSocketEntry>& entry,
    uint16_t code,
    const char* reason,
    bool was_clean) {
  void* context = retain_ws_callback_context(entry);
  if (!entry || !context || !entry->close_cb) {
    if (context) {
      native_ws_release_context(context);
    }
    return;
  }
  entry->close_cb(entry->ws_id, code, reason ? reason : "", was_clean ? 1 : 0, context);
  native_ws_release_context(context);
}

void call_ws_bytes_sent(const std::shared_ptr<AndroidWebSocketEntry>& entry, size_t bytes_sent) {
  void* context = retain_ws_callback_context(entry);
  if (!entry || !context || !entry->bytes_sent_cb) {
    if (context) {
      native_ws_release_context(context);
    }
    return;
  }
  entry->bytes_sent_cb(entry->ws_id, bytes_sent, context);
  native_ws_release_context(context);
}

void JNICALL android_ws_did_open(
    JNIEnv* env,
    jclass,
    jint ws_id,
    jstring protocol,
    jstring extensions) {
  auto entry = get_ws_entry(static_cast<uint32_t>(ws_id));
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  std::string protocol_copy = jstring_to_string(env, protocol);
  std::string extensions_copy = jstring_to_string(env, extensions);
  call_ws_open(entry, protocol_copy.c_str(), extensions_copy.c_str());
}

void JNICALL android_ws_did_message(
    JNIEnv* env,
    jclass,
    jint ws_id,
    jbyteArray data,
    jboolean is_text) {
  auto entry = get_ws_entry(static_cast<uint32_t>(ws_id));
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  std::vector<uint8_t> body = jarray_to_bytes(env, data);
  call_ws_message(entry, body.empty() ? nullptr : body.data(), body.size(), is_text == JNI_TRUE);
}

void JNICALL android_ws_did_close(
    JNIEnv* env,
    jclass,
    jint ws_id,
    jint code,
    jstring reason,
    jboolean was_clean) {
  auto entry = get_ws_entry(static_cast<uint32_t>(ws_id));
  if (!entry) {
    return;
  }
  std::string reason_copy = jstring_to_string(env, reason);
  call_ws_close(
      entry,
      static_cast<uint16_t>(code),
      reason_copy.c_str(),
      was_clean == JNI_TRUE);
  remove_ws_entry(static_cast<uint32_t>(ws_id));
}

void JNICALL android_ws_did_error(JNIEnv* env, jclass, jint ws_id, jstring message) {
  auto entry = get_ws_entry(static_cast<uint32_t>(ws_id));
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  std::string message_copy = jstring_to_string(env, message);
  call_ws_error(entry, message_copy.c_str());
}

void JNICALL android_ws_did_send_bytes(JNIEnv*, jclass, jint ws_id, jlong bytes_sent) {
  auto entry = get_ws_entry(static_cast<uint32_t>(ws_id));
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  call_ws_bytes_sent(entry, static_cast<size_t>(bytes_sent));
}

void JNICALL android_platform_event_available_jni(JNIEnv*, jclass) {
  android_platform_event_available();
}

bool register_native_callbacks(JNIEnv* env, jclass cls) {
  JNINativeMethod methods[] = {
      {const_cast<char*>("nativeFetchDidComplete"),
       const_cast<char*>("(IILjava/lang/String;Ljava/lang/String;[B)V"),
       reinterpret_cast<void*>(android_fetch_did_complete)},
      {const_cast<char*>("nativeWebSocketDidOpen"),
       const_cast<char*>("(ILjava/lang/String;Ljava/lang/String;)V"),
       reinterpret_cast<void*>(android_ws_did_open)},
      {const_cast<char*>("nativeWebSocketDidMessage"),
       const_cast<char*>("(I[BZ)V"),
       reinterpret_cast<void*>(android_ws_did_message)},
      {const_cast<char*>("nativeWebSocketDidClose"),
       const_cast<char*>("(IILjava/lang/String;Z)V"),
       reinterpret_cast<void*>(android_ws_did_close)},
      {const_cast<char*>("nativeWebSocketDidError"),
       const_cast<char*>("(ILjava/lang/String;)V"),
       reinterpret_cast<void*>(android_ws_did_error)},
      {const_cast<char*>("nativeWebSocketDidBytesSent"),
       const_cast<char*>("(IJ)V"),
       reinterpret_cast<void*>(android_ws_did_send_bytes)},
      {const_cast<char*>("nativePlatformEventAvailable"),
       const_cast<char*>("()V"),
       reinterpret_cast<void*>(android_platform_event_available_jni)},
  };
  const jint rc = env->RegisterNatives(cls, methods, sizeof(methods) / sizeof(methods[0]));
  if (rc != JNI_OK || clear_pending_exception(env, "RegisterNatives IbexNetworking")) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "Failed to register IbexNetworking natives");
    return false;
  }
  return true;
}

bool cache_networking_methods(JNIEnv* env, jclass cls) {
  g_initialize =
      env->GetStaticMethodID(cls, "initialize", "(Landroid/content/Context;)V");
  g_fetch = env->GetStaticMethodID(
      cls,
      "fetch",
      "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Z[B)V");
  g_cancel_fetch = env->GetStaticMethodID(cls, "cancelFetch", "(I)V");
  g_connect_ws = env->GetStaticMethodID(
      cls,
      "connectWebSocket",
      "(ILjava/lang/String;Ljava/lang/String;)V");
  g_send_ws = env->GetStaticMethodID(cls, "sendWebSocket", "(I[BZ)V");
  g_close_ws = env->GetStaticMethodID(cls, "closeWebSocket", "(IILjava/lang/String;)V");
  g_pause_ws = env->GetStaticMethodID(cls, "pauseWebSocket", "(I)V");
  g_resume_ws = env->GetStaticMethodID(cls, "resumeWebSocket", "(I)V");
  g_set_ws_flow_controlled =
      env->GetStaticMethodID(cls, "setWebSocketFlowControlled", "(IZ)V");
  g_dns_query = env->GetStaticMethodID(cls, "dnsQuery", "(Ljava/lang/String;I)[B");
  g_clipboard_read_text =
      env->GetStaticMethodID(cls, "clipboardReadText", "()Ljava/lang/String;");
  g_clipboard_write_text =
      env->GetStaticMethodID(cls, "clipboardWriteText", "(Ljava/lang/String;)V");
  g_platform_version =
      env->GetStaticMethodID(cls, "platformVersion", "()Ljava/lang/String;");
  g_locale_tags =
      env->GetStaticMethodID(cls, "localeTags", "()[Ljava/lang/String;");
  g_uses_24_hour_clock =
      env->GetStaticMethodID(cls, "uses24HourClock", "()Z");
  g_screen_info =
      env->GetStaticMethodID(cls, "screenInfo", "()[F");
  g_accessibility_flags =
      env->GetStaticMethodID(cls, "accessibilityFlags", "()[I");
  g_location_permission_status =
      env->GetStaticMethodID(cls, "locationPermissionStatus", "()Ljava/lang/String;");
  g_location_services_enabled =
      env->GetStaticMethodID(cls, "isLocationServicesEnabled", "()Z");
  g_current_location =
      env->GetStaticMethodID(cls, "getCurrentLocation", "(Ljava/lang/String;I)[D");
  g_app_state =
      env->GetStaticMethodID(cls, "appState", "()Ljava/lang/String;");
  g_initial_url =
      env->GetStaticMethodID(cls, "initialURL", "()Ljava/lang/String;");
  g_drain_platform_events =
      env->GetStaticMethodID(cls, "drainPlatformEvents", "()Ljava/lang/String;");

  if (clear_pending_exception(env, "cache IbexNetworking methods") ||
      !g_initialize ||
      !g_fetch ||
      !g_cancel_fetch ||
      !g_connect_ws ||
      !g_send_ws ||
      !g_close_ws ||
      !g_pause_ws ||
      !g_resume_ws ||
      !g_set_ws_flow_controlled ||
      !g_dns_query ||
      !g_clipboard_read_text ||
      !g_clipboard_write_text ||
      !g_platform_version ||
      !g_locale_tags ||
      !g_uses_24_hour_clock ||
      !g_screen_info ||
      !g_accessibility_flags ||
      !g_location_permission_status ||
      !g_location_services_enabled ||
      !g_current_location ||
      !g_app_state ||
      !g_initial_url ||
      !g_drain_platform_events) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "Missing IbexNetworking Java method");
    return false;
  }
  return true;
}

bool get_networking_methods(JNIEnv* env, AndroidNetworkingMethods* out) {
  if (!env || !out) {
    return false;
  }
  std::lock_guard<std::mutex> lock(g_jni_mutex);
  if (!g_java_vm || !g_networking_class) {
    return false;
  }
  out->cls = static_cast<jclass>(env->NewLocalRef(g_networking_class));
  out->fetch = g_fetch;
  out->cancel_fetch = g_cancel_fetch;
  out->connect_ws = g_connect_ws;
  out->send_ws = g_send_ws;
  out->close_ws = g_close_ws;
  out->pause_ws = g_pause_ws;
  out->resume_ws = g_resume_ws;
  out->set_ws_flow_controlled = g_set_ws_flow_controlled;
  out->dns_query = g_dns_query;
  out->clipboard_read_text = g_clipboard_read_text;
  out->clipboard_write_text = g_clipboard_write_text;
  out->platform_version = g_platform_version;
  out->locale_tags = g_locale_tags;
  out->uses_24_hour_clock = g_uses_24_hour_clock;
  out->screen_info = g_screen_info;
  out->accessibility_flags = g_accessibility_flags;
  out->location_permission_status = g_location_permission_status;
  out->location_services_enabled = g_location_services_enabled;
  out->current_location = g_current_location;
  out->app_state = g_app_state;
  out->initial_url = g_initial_url;
  out->drain_platform_events = g_drain_platform_events;
  return out->cls != nullptr;
}

void report_fetch_error(
    uint32_t request_id,
    const char* message,
    NativeFetchResponseCallback response_callback,
    void* context) {
  if (response_callback) {
    response_callback(request_id, 0, message, nullptr, nullptr, 0, context);
  }
}

bool call_android_fetch(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    int decompress,
    const uint8_t* body,
    size_t body_length) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return false;
  }

  jstring j_method = string_to_jstring(env, method ? method : "GET");
  jstring j_url = string_to_jstring(env, url ? url : "");
  jstring j_headers = string_to_jstring(env, headers ? headers : "");
  jbyteArray j_body = (body && body_length > 0) ? bytes_to_jarray(env, body, body_length) : nullptr;
  if (!j_method || !j_url || !j_headers) {
    env->DeleteLocalRef(methods.cls);
    if (j_method) env->DeleteLocalRef(j_method);
    if (j_url) env->DeleteLocalRef(j_url);
    if (j_headers) env->DeleteLocalRef(j_headers);
    if (j_body) env->DeleteLocalRef(j_body);
    return false;
  }

  env->CallStaticVoidMethod(
      methods.cls,
      methods.fetch,
      static_cast<jint>(request_id),
      j_method,
      j_url,
      j_headers,
      decompress ? JNI_TRUE : JNI_FALSE,
      j_body);
  const bool had_exception = clear_pending_exception(env, "IbexNetworking.fetch");

  env->DeleteLocalRef(methods.cls);
  env->DeleteLocalRef(j_method);
  env->DeleteLocalRef(j_url);
  env->DeleteLocalRef(j_headers);
  if (j_body) env->DeleteLocalRef(j_body);
  return !had_exception;
}

void call_android_cancel_fetch(uint32_t request_id) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  env->CallStaticVoidMethod(methods.cls, methods.cancel_fetch, static_cast<jint>(request_id));
  clear_pending_exception(env, "IbexNetworking.cancelFetch");
  env->DeleteLocalRef(methods.cls);
}

bool call_android_connect_ws(uint32_t ws_id, const char* url, const char* protocols) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return false;
  }

  jstring j_url = string_to_jstring(env, url ? url : "");
  jstring j_protocols = string_to_jstring(env, protocols ? protocols : "");
  if (!j_url || !j_protocols) {
    env->DeleteLocalRef(methods.cls);
    if (j_url) env->DeleteLocalRef(j_url);
    if (j_protocols) env->DeleteLocalRef(j_protocols);
    return false;
  }

  env->CallStaticVoidMethod(
      methods.cls,
      methods.connect_ws,
      static_cast<jint>(ws_id),
      j_url,
      j_protocols);
  const bool had_exception = clear_pending_exception(env, "IbexNetworking.connectWebSocket");

  env->DeleteLocalRef(methods.cls);
  env->DeleteLocalRef(j_url);
  env->DeleteLocalRef(j_protocols);
  return !had_exception;
}

void call_android_send_ws(uint32_t ws_id, const uint8_t* data, size_t length, bool is_text) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  jbyteArray j_data = bytes_to_jarray(env, data, length);
  if (!j_data) {
    env->DeleteLocalRef(methods.cls);
    return;
  }
  env->CallStaticVoidMethod(
      methods.cls,
      methods.send_ws,
      static_cast<jint>(ws_id),
      j_data,
      is_text ? JNI_TRUE : JNI_FALSE);
  clear_pending_exception(env, "IbexNetworking.sendWebSocket");
  env->DeleteLocalRef(j_data);
  env->DeleteLocalRef(methods.cls);
}

void call_android_close_ws(uint32_t ws_id, uint16_t code, const char* reason) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  jstring j_reason = string_to_jstring(env, reason ? reason : "");
  if (!j_reason) {
    env->DeleteLocalRef(methods.cls);
    return;
  }
  env->CallStaticVoidMethod(
      methods.cls,
      methods.close_ws,
      static_cast<jint>(ws_id),
      static_cast<jint>(code),
      j_reason);
  clear_pending_exception(env, "IbexNetworking.closeWebSocket");
  env->DeleteLocalRef(j_reason);
  env->DeleteLocalRef(methods.cls);
}

void call_android_ws_flow_control(uint32_t ws_id, bool enabled) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  env->CallStaticVoidMethod(
      methods.cls,
      methods.set_ws_flow_controlled,
      static_cast<jint>(ws_id),
      enabled ? JNI_TRUE : JNI_FALSE);
  clear_pending_exception(env, "IbexNetworking.setWebSocketFlowControlled");
  env->DeleteLocalRef(methods.cls);
}

} // namespace

extern "C" int ex_android_initialize(void* java_vm, void* application_context) {
  if (!java_vm) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "ex_android_initialize missing JavaVM");
    return -1;
  }

  auto* vm = static_cast<JavaVM*>(java_vm);
  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "ex_android_initialize requires a JNI thread");
    return -2;
  }

  jobject context = static_cast<jobject>(application_context);
  jclass local_class = find_networking_class(env, context);
  if (!local_class) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag, "IbexNetworking Java class not found");
    return -3;
  }

  {
    std::lock_guard<std::mutex> lock(g_jni_mutex);
    if (g_application_context) {
      env->DeleteGlobalRef(g_application_context);
      g_application_context = nullptr;
    }
    if (g_networking_class) {
      env->DeleteGlobalRef(g_networking_class);
      g_networking_class = nullptr;
    }

    g_java_vm = vm;
    g_application_context = context ? env->NewGlobalRef(context) : nullptr;
    g_networking_class = static_cast<jclass>(env->NewGlobalRef(local_class));
  }
  env->DeleteLocalRef(local_class);

  if (!g_networking_class ||
      !register_native_callbacks(env, g_networking_class) ||
      !cache_networking_methods(env, g_networking_class)) {
    return -4;
  }

  env->CallStaticVoidMethod(g_networking_class, g_initialize, g_application_context);
  if (clear_pending_exception(env, "IbexNetworking.initialize")) {
    return -5;
  }
  return 0;
}

extern "C" int android_get_platform_version(
    char** out_version,
    char* error,
    size_t error_capacity) {
  if (out_version) {
    *out_version = nullptr;
  }
  if (!out_version) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android platform version query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.platform_version));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android platform version query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string version = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  auto* copy = malloc_string_copy(version);
  if (!copy) {
    write_error("Failed to allocate Android platform version");
    return -1;
  }
  *out_version = copy;
  return 1;
}

extern "C" int android_get_locale_snapshot(
    char** out_primary_tag,
    char** out_tags,
    int* uses_24_hour_clock,
    char* error,
    size_t error_capacity) {
  if (out_primary_tag) {
    *out_primary_tag = nullptr;
  }
  if (out_tags) {
    *out_tags = nullptr;
  }
  if (uses_24_hour_clock) {
    *uses_24_hour_clock = 0;
  }
  if (!out_primary_tag || !out_tags || !uses_24_hour_clock) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android locale query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto tags_array = static_cast<jobjectArray>(
      env->CallStaticObjectMethod(methods.cls, methods.locale_tags));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android locale tags query failed");
    return -1;
  }

  jboolean uses_24_hour =
      env->CallStaticBooleanMethod(methods.cls, methods.uses_24_hour_clock);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    if (tags_array) {
      env->DeleteLocalRef(tags_array);
    }
    env->DeleteLocalRef(methods.cls);
    write_error("Android 24-hour clock query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string primary_tag;
  std::string joined_tags;
  if (tags_array) {
    const jsize count = env->GetArrayLength(tags_array);
    for (jsize i = 0; i < count; ++i) {
      auto tag = static_cast<jstring>(env->GetObjectArrayElement(tags_array, i));
      if (clear_pending_exception(env, "GetObjectArrayElement localeTags")) {
        env->DeleteLocalRef(tags_array);
        write_error("Failed to read Android locale tags");
        return -1;
      }
      std::string tag_copy = jstring_to_string(env, tag);
      if (tag) {
        env->DeleteLocalRef(tag);
      }
      if (tag_copy.empty()) {
        continue;
      }
      if (primary_tag.empty()) {
        primary_tag = tag_copy;
      }
      if (!joined_tags.empty()) {
        joined_tags.push_back('\n');
      }
      joined_tags.append(tag_copy);
    }
    env->DeleteLocalRef(tags_array);
  }

  if (primary_tag.empty()) {
    primary_tag = "en-US";
    joined_tags = primary_tag;
  }

  auto* primary_copy = malloc_string_copy(primary_tag);
  auto* tags_copy = malloc_string_copy(joined_tags);
  if (!primary_copy || !tags_copy) {
    std::free(primary_copy);
    std::free(tags_copy);
    write_error("Failed to allocate Android locale tags");
    return -1;
  }

  *out_primary_tag = primary_copy;
  *out_tags = tags_copy;
  *uses_24_hour_clock = uses_24_hour == JNI_TRUE ? 1 : 0;
  return 1;
}

extern "C" int android_get_screen_info(
    AndroidScreenInfo* out_info,
    char* error,
    size_t error_capacity) {
  if (!out_info) {
    return -1;
  }
  *out_info = AndroidScreenInfo{};

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android screen info query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jfloatArray>(
      env->CallStaticObjectMethod(methods.cls, methods.screen_info));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android screen info query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  if (!result || env->GetArrayLength(result) < 4) {
    if (result) {
      env->DeleteLocalRef(result);
    }
    write_error("Android screen info response was incomplete");
    return -1;
  }

  jfloat values[4] = {};
  env->GetFloatArrayRegion(result, 0, 4, values);
  env->DeleteLocalRef(result);
  if (clear_pending_exception(env, "GetFloatArrayRegion screenInfo")) {
    write_error("Failed to copy Android screen info");
    return -1;
  }

  out_info->width = values[0] > 0.0f ? values[0] : 0.0;
  out_info->height = values[1] > 0.0f ? values[1] : 0.0;
  out_info->scale = values[2] > 0.0f ? values[2] : 1.0;
  out_info->font_scale = values[3] > 0.0f ? values[3] : 1.0;
  return 1;
}

extern "C" int android_get_accessibility_flags(
    AndroidAccessibilityFlags* out_flags,
    char* error,
    size_t error_capacity) {
  if (!out_flags) {
    return -1;
  }
  *out_flags = AndroidAccessibilityFlags{};

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android accessibility query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jintArray>(
      env->CallStaticObjectMethod(methods.cls, methods.accessibility_flags));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android accessibility query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  if (!result || env->GetArrayLength(result) < 8) {
    if (result) {
      env->DeleteLocalRef(result);
    }
    write_error("Android accessibility response was incomplete");
    return -1;
  }

  jint values[8] = {};
  env->GetIntArrayRegion(result, 0, 8, values);
  env->DeleteLocalRef(result);
  if (clear_pending_exception(env, "GetIntArrayRegion accessibilityFlags")) {
    write_error("Failed to copy Android accessibility flags");
    return -1;
  }

  out_flags->prefers_reduced_motion = values[0] != 0 ? 1 : 0;
  out_flags->is_bold_text_enabled = values[1] != 0 ? 1 : 0;
  out_flags->prefers_high_contrast = values[2] != 0 ? 1 : 0;
  out_flags->prefers_reduced_transparency = values[3] != 0 ? 1 : 0;
  out_flags->is_screen_reader_enabled = values[4] != 0 ? 1 : 0;
  out_flags->color_scheme_dark = values[5] != 0 ? 1 : 0;
  out_flags->is_invert_colors_enabled = values[6] != 0 ? 1 : 0;
  out_flags->is_grayscale_enabled = values[7] != 0 ? 1 : 0;
  return 1;
}

extern "C" int android_location_permission_status(
    char** out_status,
    char* error,
    size_t error_capacity) {
  if (out_status) {
    *out_status = nullptr;
  }
  if (!out_status) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android location permission query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.location_permission_status));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android location permission query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string status = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  if (status.empty()) {
    status = "denied";
  }
  auto* copy = malloc_string_copy(status);
  if (!copy) {
    write_error("Failed to allocate Android location permission status");
    return -1;
  }
  *out_status = copy;
  return 1;
}

extern "C" int android_location_services_enabled(
    int* out_enabled,
    char* error,
    size_t error_capacity) {
  if (out_enabled) {
    *out_enabled = 0;
  }
  if (!out_enabled) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android location services query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  jboolean enabled =
      env->CallStaticBooleanMethod(methods.cls, methods.location_services_enabled);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android location services query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);
  *out_enabled = enabled == JNI_TRUE ? 1 : 0;
  return 1;
}

extern "C" int android_location_get_current(
    const char* accuracy,
    int timeout_ms,
    AndroidLocationResult* out_location,
    char* error,
    size_t error_capacity) {
  if (out_location) {
    *out_location = AndroidLocationResult{};
  }
  if (!out_location) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android current location query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  jstring j_accuracy = string_to_jstring(env, accuracy ? accuracy : "hundredMeters");
  if (!j_accuracy) {
    env->DeleteLocalRef(methods.cls);
    write_error("Failed to allocate Android location accuracy");
    return -1;
  }

  auto result = static_cast<jdoubleArray>(env->CallStaticObjectMethod(
      methods.cls,
      methods.current_location,
      j_accuracy,
      static_cast<jint>(timeout_ms)));
  env->DeleteLocalRef(j_accuracy);

  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android LocationManager current location failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  if (!result || env->GetArrayLength(result) < 6) {
    if (result) {
      env->DeleteLocalRef(result);
    }
    write_error("Android current location response was incomplete");
    return -1;
  }

  jdouble values[6] = {};
  env->GetDoubleArrayRegion(result, 0, 6, values);
  env->DeleteLocalRef(result);
  if (clear_pending_exception(env, "GetDoubleArrayRegion currentLocation")) {
    write_error("Failed to copy Android current location");
    return -1;
  }

  out_location->latitude = values[0];
  out_location->longitude = values[1];
  out_location->altitude = values[2];
  out_location->horizontal_accuracy = values[3];
  out_location->vertical_accuracy = values[4];
  out_location->timestamp = values[5];
  return 1;
}

extern "C" int android_get_app_state(
    char** out_state,
    char* error,
    size_t error_capacity) {
  if (out_state) {
    *out_state = nullptr;
  }
  if (!out_state) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android app state query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.app_state));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android app state query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string state = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  if (state.empty()) {
    state = "unknown";
  }
  auto* copy = malloc_string_copy(state);
  if (!copy) {
    write_error("Failed to allocate Android app state");
    return -1;
  }
  *out_state = copy;
  return 1;
}

extern "C" int android_get_initial_url(
    char** out_url,
    char* error,
    size_t error_capacity) {
  if (out_url) {
    *out_url = nullptr;
  }
  if (!out_url) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android initial URL query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.initial_url));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android initial URL query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string url = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  auto* copy = malloc_string_copy(url);
  if (!copy) {
    write_error("Failed to allocate Android initial URL");
    return -1;
  }
  *out_url = copy;
  return 1;
}

extern "C" int android_drain_platform_events(
    char** out_events,
    char* error,
    size_t error_capacity) {
  if (out_events) {
    *out_events = nullptr;
  }
  if (!out_events) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android platform event drain failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android runtime bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.drain_platform_events));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android platform event drain failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string events = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  auto* copy = malloc_string_copy(events);
  if (!copy) {
    write_error("Failed to allocate Android platform event buffer");
    return -1;
  }
  *out_events = copy;
  return 1;
}

extern "C" int android_dns_query(
    const char* hostname,
    int qtype,
    uint8_t* answer,
    size_t answer_capacity,
    size_t* answer_length,
    char* error,
    size_t error_capacity) {
  if (answer_length) {
    *answer_length = 0;
  }
  if (!hostname || !answer || answer_capacity == 0 || !answer_length) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android DNS query failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return 0;
  }

  jstring j_hostname = string_to_jstring(env, hostname);
  if (!j_hostname) {
    env->DeleteLocalRef(methods.cls);
    write_error("Failed to allocate Android DNS hostname");
    return -1;
  }

  auto result = static_cast<jbyteArray>(env->CallStaticObjectMethod(
      methods.cls,
      methods.dns_query,
      j_hostname,
      static_cast<jint>(qtype)));
  env->DeleteLocalRef(j_hostname);

  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android DnsResolver query failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  if (!result) {
    return 0;
  }

  const jsize result_length = env->GetArrayLength(result);
  if (result_length < 0 || static_cast<size_t>(result_length) > answer_capacity) {
    env->DeleteLocalRef(result);
    write_error("Android DnsResolver response exceeded buffer");
    return -1;
  }
  if (result_length > 0) {
    env->GetByteArrayRegion(result, 0, result_length, reinterpret_cast<jbyte*>(answer));
    if (clear_pending_exception(env, "GetByteArrayRegion dnsQuery")) {
      env->DeleteLocalRef(result);
      write_error("Failed to copy Android DnsResolver response");
      return -1;
    }
  }
  *answer_length = static_cast<size_t>(result_length);
  env->DeleteLocalRef(result);
  return 1;
}

extern "C" int android_clipboard_read_text(
    char** out_text,
    char* error,
    size_t error_capacity) {
  if (out_text) {
    *out_text = nullptr;
  }
  if (!out_text) {
    return -1;
  }

  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* text = message ? message : "Android clipboard read failed";
    std::strncpy(error, text, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android clipboard bridge is not initialized");
    return -1;
  }

  auto result = static_cast<jstring>(
      env->CallStaticObjectMethod(methods.cls, methods.clipboard_read_text));
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android ClipboardManager read failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);

  std::string text = jstring_to_string(env, result);
  if (result) {
    env->DeleteLocalRef(result);
  }
  auto* copy = static_cast<char*>(std::malloc(text.size() + 1));
  if (!copy) {
    write_error("Failed to allocate Android clipboard text");
    return -1;
  }
  std::memcpy(copy, text.c_str(), text.size() + 1);
  *out_text = copy;
  return 1;
}

extern "C" int android_clipboard_write_text(
    const char* text,
    char* error,
    size_t error_capacity) {
  auto write_error = [error, error_capacity](const char* message) {
    if (!error || error_capacity == 0) {
      return;
    }
    const char* value = message ? message : "Android clipboard write failed";
    std::strncpy(error, value, error_capacity - 1);
    error[error_capacity - 1] = '\0';
  };

  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    write_error("Android clipboard bridge is not initialized");
    return -1;
  }

  jstring j_text = string_to_jstring(env, text ? text : "");
  if (!j_text) {
    env->DeleteLocalRef(methods.cls);
    write_error("Failed to allocate Android clipboard text");
    return -1;
  }

  env->CallStaticVoidMethod(methods.cls, methods.clipboard_write_text, j_text);
  env->DeleteLocalRef(j_text);
  if (env->ExceptionCheck()) {
    env->ExceptionDescribe();
    env->ExceptionClear();
    env->DeleteLocalRef(methods.cls);
    write_error("Android ClipboardManager write failed");
    return -1;
  }
  env->DeleteLocalRef(methods.cls);
  return 1;
}

extern "C" void native_fetch_perform(
    uint32_t request_id,
    const char* method,
    const char* url,
    const char* headers,
    int decompress,
    const uint8_t* body,
    size_t body_length,
    NativeFetchResponseCallback response_callback,
    void* context) {
  if (!response_callback) {
    return;
  }
  if (!method || !url) {
    report_fetch_error(request_id, "Invalid request", response_callback, context);
    return;
  }

  {
    std::lock_guard<std::mutex> lock(g_fetch_mutex);
    g_fetch_requests[request_id] = AndroidFetchRequest{response_callback, context};
  }

  if (!call_android_fetch(request_id, method, url, headers, decompress, body, body_length)) {
    {
      std::lock_guard<std::mutex> lock(g_fetch_mutex);
      g_fetch_requests.erase(request_id);
    }
    report_fetch_error(
        request_id,
        "Android networking bridge is not initialized",
        response_callback,
        context);
  }
}

extern "C" void native_fetch_cancel(uint32_t request_id) {
  {
    std::lock_guard<std::mutex> lock(g_fetch_mutex);
    g_fetch_requests.erase(request_id);
  }
  call_android_cancel_fetch(request_id);
}

extern "C" uint32_t native_ws_connect(
    const char* url,
    const char* protocols,
    NativeWsOpenCallback open_cb,
    NativeWsMessageCallback message_cb,
    NativeWsCloseCallback close_cb,
    NativeWsErrorCallback error_cb,
    NativeWsBytesSentCallback bytes_sent_cb,
    void* context) {
  if (!url || !open_cb || !message_cb || !close_cb || !error_cb) {
    return 0;
  }

  auto entry = std::make_shared<AndroidWebSocketEntry>();
  entry->ws_id = g_next_ws_id.fetch_add(1, std::memory_order_relaxed);
  entry->open_cb = open_cb;
  entry->message_cb = message_cb;
  entry->close_cb = close_cb;
  entry->error_cb = error_cb;
  entry->bytes_sent_cb = bytes_sent_cb;
  entry->context = context;
  if (entry->context) {
    native_ws_retain_context(entry->context);
  }

  {
    std::lock_guard<std::mutex> lock(g_ws_mutex);
    g_ws_connections[entry->ws_id] = entry;
  }

  if (!call_android_connect_ws(entry->ws_id, url, protocols)) {
    call_ws_error(entry, "Android networking bridge is not initialized");
    remove_ws_entry(entry->ws_id);
    return 0;
  }

  return entry->ws_id;
}

extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text) {
  auto entry = get_ws_entry(ws_id);
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  call_android_send_ws(ws_id, data, length, is_text != 0);
}

extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason) {
  auto entry = get_ws_entry(ws_id);
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  call_android_close_ws(ws_id, code, reason);
}

extern "C" void native_ws_pause(uint32_t ws_id) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  env->CallStaticVoidMethod(methods.cls, methods.pause_ws, static_cast<jint>(ws_id));
  clear_pending_exception(env, "IbexNetworking.pauseWebSocket");
  env->DeleteLocalRef(methods.cls);
}

extern "C" void native_ws_resume(uint32_t ws_id) {
  JniEnvScope scope;
  JNIEnv* env = scope.env();
  AndroidNetworkingMethods methods;
  if (!env || !get_networking_methods(env, &methods)) {
    return;
  }
  env->CallStaticVoidMethod(methods.cls, methods.resume_ws, static_cast<jint>(ws_id));
  clear_pending_exception(env, "IbexNetworking.resumeWebSocket");
  env->DeleteLocalRef(methods.cls);
}

extern "C" void native_ws_set_flow_controlled(uint32_t ws_id, int enabled) {
  auto entry = get_ws_entry(ws_id);
  if (!entry || entry->closed.load(std::memory_order_relaxed)) {
    return;
  }
  call_android_ws_flow_control(ws_id, enabled != 0);
}

extern "C" void native_ws_destroy(uint32_t ws_id) {
  call_android_close_ws(ws_id, 1000, "");
  remove_ws_entry(ws_id);
}

extern "C" int native_ws_has_active(void) {
  std::lock_guard<std::mutex> lock(g_ws_mutex);
  for (const auto& pair : g_ws_connections) {
    const auto& entry = pair.second;
    if (entry && !entry->closed.load(std::memory_order_relaxed)) {
      return 1;
    }
  }
  return 0;
}
