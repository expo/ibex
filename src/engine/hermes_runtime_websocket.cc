#include "hermes_runtime_internal.h"

#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

typedef void (*NativeWsOpenCallback)(
    uint32_t ws_id, const char* protocol, const char* extensions, void* context);
typedef void (*NativeWsMessageCallback)(
    uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* context);
typedef void (*NativeWsCloseCallback)(
    uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* context);
typedef void (*NativeWsErrorCallback)(uint32_t ws_id, const char* message, void* context);
typedef void (*NativeWsBytesSentCallback)(uint32_t ws_id, size_t bytes_sent, void* context);
extern "C" uint32_t native_ws_connect(const char* url,
                                      const char* protocols,
                                      NativeWsOpenCallback open_cb,
                                      NativeWsMessageCallback message_cb,
                                      NativeWsCloseCallback close_cb,
                                      NativeWsErrorCallback error_cb,
                                      NativeWsBytesSentCallback bytes_sent_cb,
                                      void* context);
extern "C" void native_ws_send(uint32_t ws_id, const uint8_t* data, size_t length, int is_text);
extern "C" void native_ws_close(uint32_t ws_id, uint16_t code, const char* reason);
extern "C" void native_ws_pause(uint32_t ws_id);
extern "C" void native_ws_resume(uint32_t ws_id);
extern "C" void native_ws_set_flow_controlled(uint32_t ws_id, int enabled);
extern "C" void native_ws_destroy(uint32_t ws_id);
extern "C" uint64_t ex_hermes_current_runtime_nonce();

namespace {

struct WebSocketEntry {
  uint64_t runtime_nonce;
  uint64_t owner;
  std::string capability;
  NativeWebSocketCallbackContext* context;
  bool closing;
};

static std::mutex g_websocket_mutex;
static std::condition_variable g_websocket_cv;
static std::unordered_map<uint32_t, WebSocketEntry> g_websockets;

bool registerWebSocket(
    NativeWebSocketCallbackContext* context,
    uint32_t ws_id,
    uint64_t owner,
    const std::string& capability) {
  if (ws_id == 0 || !context || context->runtime_nonce == 0) {
    return false;
  }
  std::lock_guard<std::mutex> lock(g_websocket_mutex);
  // The native connect callback can fail on an I/O thread before
  // native_ws_connect returns to the runtime thread. The terminal callback
  // and this registration serialize on the same mutex and share the exact
  // per-connect context, so neither interleaving can leave a ghost entry.
  if (context && context->websocket_terminal) {
    context->websocket_registered = true;
    g_websocket_cv.notify_all();
    return false;
  }
  bool inserted = false;
  try {
    inserted = g_websockets
                   .emplace(
                       ws_id,
                       WebSocketEntry{
                           context->runtime_nonce, owner, capability, context, false})
                   .second;
  } catch (...) {
    // A native callback may already be waiting for registration. Publish a
    // terminal state before unwinding so it cannot retain the context (and the
    // runtime teardown pin) forever after an allocation failure.
    context->websocket_registered = true;
    context->websocket_terminal = true;
    g_websocket_cv.notify_all();
    throw;
  }
  context->websocket_registered = true;
  g_websocket_cv.notify_all();
  return inserted;
}

WebSocketEntry requireWebSocketOwner(
    facebook::jsi::Runtime& runtime,
    uint32_t ws_id,
    const char* syscall,
    bool requireLiveAuthority = true) {
  WebSocketEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_websocket_mutex);
    auto it = g_websockets.find(ws_id);
    if (it == g_websockets.end()) {
      throw facebook::jsi::JSError(runtime, std::string(syscall) + ": unknown WebSocket");
    }
    entry = it->second;
  }
  if (entry.runtime_nonce != ex_hermes_current_runtime_nonce()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": WebSocket belongs to a different runtime");
  }
  // Allow-all controls capability policy, not handle ownership. Principal and
  // runtime identity remain mandatory in permissive mode; otherwise any
  // package that guesses a small numeric id can operate another package's
  // socket whenever the host policy is permissive.
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": WebSocket belongs to a different principal");
  }
  if (requireLiveAuthority && !entry.capability.empty() &&
      !checkCapability(entry.capability)) {
    throw facebook::jsi::JSError(runtime, std::string("Permission denied: ") + syscall);
  }
  if (entry.closing) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": WebSocket is closing");
  }
  return entry;
}

bool markWebSocketClosing(uint32_t ws_id, uint64_t runtimeNonce) {
  std::lock_guard<std::mutex> lock(g_websocket_mutex);
  auto it = g_websockets.find(ws_id);
  if (it == g_websockets.end() || it->second.runtime_nonce != runtimeNonce ||
      it->second.closing) {
    return false;
  }
  it->second.closing = true;
  return true;
}

bool unregisterWebSocket(
    uint32_t ws_id,
    NativeWebSocketCallbackContext* context = nullptr) {
  std::lock_guard<std::mutex> lock(g_websocket_mutex);
  if (ws_id == 0) {
    if (!context || context->websocket_terminal) return false;
    context->websocket_terminal = true;
    g_websocket_cv.notify_all();
    return true;
  }
  auto it = g_websockets.find(ws_id);
  if (context) {
    if (context->websocket_terminal) return false;
    context->websocket_terminal = true;
    g_websocket_cv.notify_all();
    if (it != g_websockets.end() &&
        (it->second.runtime_nonce != context->runtime_nonce ||
         it->second.context != context)) {
      return false;
    }
  }
  // Idempotent for error+close, duplicate close, and explicit JS close. A
  // missing id is never retained, so terminal churn has bounded memory.
  if (it != g_websockets.end()) g_websockets.erase(it);
  return true;
}

bool webSocketCallbackIsCurrent(
    uint32_t ws_id,
    NativeWebSocketCallbackContext* context) {
  if (ws_id == 0 || !context) return false;
  std::unique_lock<std::mutex> lock(g_websocket_mutex);
  // A callback can win the race with runtime-thread registration while the
  // latter is stalled after native_ws_connect. Registration is guaranteed for
  // every nonzero connect result, so an arbitrary timeout only drops a valid
  // open/message event and strands JS in CONNECTING. Terminal callbacks wake
  // this wait as well, preventing a failed connection from hanging here.
  g_websocket_cv.wait(lock, [&] {
    return context->websocket_registered || context->websocket_terminal;
  });
  if (!context->websocket_registered || context->websocket_terminal) return false;
  auto it = g_websockets.find(ws_id);
  return it != g_websockets.end() &&
      it->second.runtime_nonce == context->runtime_nonce &&
      it->second.context == context && !it->second.closing;
}

} // namespace

extern "C" void exactCleanupRuntimeWebSockets(uint64_t runtimeNonce) {
  if (runtimeNonce == 0) return;

  std::vector<uint32_t> ownedIds;
  {
    std::lock_guard<std::mutex> lock(g_websocket_mutex);
    for (auto it = g_websockets.begin(); it != g_websockets.end();) {
      if (it->second.runtime_nonce == runtimeNonce) {
        if (it->second.context) {
          it->second.context->websocket_registered = true;
          it->second.context->websocket_terminal = true;
        }
        ownedIds.push_back(it->first);
        it = g_websockets.erase(it);
      } else {
        ++it;
      }
    }
    g_websocket_cv.notify_all();
  }
  for (uint32_t wsId : ownedIds) {
    native_ws_destroy(wsId);
  }
}

void installWebSocketGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto wsConnectFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsConnect"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value* args,
               size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactWsConnect: url, protocols, wsInstance required");
        }
        auto url = args[0].toString(runtime).utf8(runtime);
        auto protocols =
            args[1].isString() ? args[1].toString(runtime).utf8(runtime) : std::string("");
        ParsedNetworkUrl parsedUrl;
        const char* parseFailure = "unknown parse failure";
        if (!parseNetworkUrl(url, parsedUrl, &parseFailure)) {
          throw facebook::jsi::JSError(
              runtime,
              std::string("__exactWsConnect: malformed network URL (") +
                  parseFailure + ")");
        }
        if (parsedUrl.scheme != "ws" && parsedUrl.scheme != "wss") {
          throw facebook::jsi::JSError(
              runtime, "__exactWsConnect: unsupported network URL scheme");
        }
        // @ref LLP 0013#policy — WebSocket native I/O is the security boundary;
        // endpoint-scoped grants must authorize the concrete peer, not just JS.
        std::string connectCapability =
            "network:connect:" + formatNetworkEndpoint(parsedUrl.host, parsedUrl.port);
        if (!checkCapability(connectCapability)) {
          throw facebook::jsi::JSError(
              runtime, "Permission denied: network:connect capability required");
        }
        auto wsPrincipal = currentPrincipalId();
        auto runtimeNonce = ex_hermes_current_runtime_nonce();
        auto wsInstance = std::make_shared<facebook::jsi::Object>(args[2].asObject(runtime));
        auto target = exactRuntimeCallbackTarget(handle);
        if (!exactPinRuntimeNativeWorker(target)) {
          throw facebook::jsi::JSError(runtime, "WebSocket runtime is shutting down");
        }
        NativeWebSocketCallbackContext* callbackContext = nullptr;
        try {
          callbackContext = new NativeWebSocketCallbackContext();
          callbackContext->target = target;
          callbackContext->ws_instance = std::move(wsInstance);
          callbackContext->runtime_nonce = runtimeNonce;
          callbackContext->principal = wsPrincipal;
          callbackContext->capability = connectCapability;
          callbackContext->runtime_pin_held = true;
        } catch (...) {
          delete callbackContext;
          exactUnpinRuntimeNativeWorker(target);
          throw;
        }

        auto wsId = native_ws_connect(
            url.c_str(),
            protocols.empty() ? nullptr : protocols.c_str(),
            [](uint32_t ws_id, const char* protocol, const char* extensions, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->target || !context->ws_instance) {
                return;
              }
              if (!webSocketCallbackIsCurrent(ws_id, context)) return;
              auto target = context->target;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto protoCopy = std::string(protocol ? protocol : "");
              auto extCopy = std::string(extensions ? extensions : "");
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);

              pushRuntimeCallback(
                  target,
                  [wsObj = std::move(wsObj),
                   protoCopy,
                   extCopy,
                   principal,
                   context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleOpen");
                    fn.call(rt,
                            facebook::jsi::String::createFromUtf8(rt, protoCopy),
                            facebook::jsi::String::createFromUtf8(rt, extCopy));
                  });
            },
            [](uint32_t ws_id, const uint8_t* data, size_t length, int is_text, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->target || !context->ws_instance) {
                return;
              }
              if (!webSocketCallbackIsCurrent(ws_id, context)) return;
              auto target = context->target;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              if (is_text) {
                auto textCopy = std::string(reinterpret_cast<const char*>(data), length);
                pushRuntimeCallback(
                    target,
                    [wsObj = std::move(wsObj),
                     textCopy,
                     principal,
                     context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                      ScopedNativePrincipal nativePrincipal(principal);
                      auto fn = wsObj->getPropertyAsFunction(rt, "_handleMessage");
                      fn.call(rt, facebook::jsi::String::createFromUtf8(rt, textCopy));
                    });
              } else {
                auto dataCopy = std::make_shared<std::vector<uint8_t>>(data, data + length);
                pushRuntimeCallback(
                    target,
                    [wsObj = std::move(wsObj),
                     dataCopy,
                     principal,
                     context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                      ScopedNativePrincipal nativePrincipal(principal);
                      auto ab = rt.global()
                                    .getPropertyAsFunction(rt, "ArrayBuffer")
                                    .callAsConstructor(rt, static_cast<double>(dataCopy->size()))
                                    .asObject(rt)
                                    .getArrayBuffer(rt);
                      memcpy(ab.data(rt), dataCopy->data(), dataCopy->size());
                      auto fn = wsObj->getPropertyAsFunction(rt, "_handleMessage");
                      fn.call(rt, std::move(ab));
                    });
              }
            },
            [](uint32_t ws_id, uint16_t code, const char* reason, int was_clean, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->target || !context->ws_instance) {
                return;
              }
              auto target = context->target;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto reasonCopy = std::string(reason ? reason : "");
              auto codeCopy = code;
              auto cleanCopy = was_clean;
              if (!unregisterWebSocket(ws_id, context)) return;
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  target,
                  [wsObj = std::move(wsObj),
                   codeCopy,
                   reasonCopy,
                   cleanCopy,
                   principal,
                   context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleClose");
                    fn.call(rt,
                            facebook::jsi::Value(static_cast<int>(codeCopy)),
                            facebook::jsi::String::createFromUtf8(rt, reasonCopy),
                            facebook::jsi::Value(cleanCopy != 0));
                  });
            },
            [](uint32_t ws_id, const char* message, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->target || !context->ws_instance) {
                return;
              }
              auto target = context->target;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto msgCopy = std::string(message ? message : "Unknown error");
              auto closeAfterError = ws_id == 0;
              // An error event is not the terminal WebSocket notification:
              // native backends report fatal failures as error followed by
              // close. Keep a registered nonzero socket current so the close
              // callback can unregister it and deliver readyState=CLOSED.
              // A zero-id setup failure has no later registration/close path,
              // so retain the per-context exactly-once gate and synthesize its
              // unclean close after delivering the error.
              // @ref LLP 0003#websocket-bridge-threading-and-context-ownership —
              // handshake failure is error followed by close(1006, unclean)
              if (ws_id == 0) {
                if (!unregisterWebSocket(0, context)) return;
              } else if (!webSocketCallbackIsCurrent(ws_id, context)) {
                return;
              }
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  target,
                  [wsObj = std::move(wsObj),
                   msgCopy,
                   closeAfterError,
                   principal,
                   context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleError");
                    fn.call(rt, facebook::jsi::String::createFromUtf8(rt, msgCopy));
                    if (closeAfterError) {
                      auto closeFn = wsObj->getPropertyAsFunction(rt, "_handleClose");
                      closeFn.call(
                          rt,
                          facebook::jsi::Value(1006),
                          facebook::jsi::String::createFromUtf8(rt, ""),
                          facebook::jsi::Value(false));
                    }
                  });
            },
            [](uint32_t ws_id, size_t bytes_sent, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->target || !context->ws_instance) {
                return;
              }
              if (!webSocketCallbackIsCurrent(ws_id, context)) return;
              auto target = context->target;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto sentCopy = bytes_sent;
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  target,
                  [wsObj = std::move(wsObj),
                   sentCopy,
                   principal,
                   context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleBytesSent");
                    fn.call(rt, facebook::jsi::Value(static_cast<int>(sentCopy)));
                  });
            },
            callbackContext);
        if (wsId == 0) {
          native_ws_release_context(callbackContext);
          return facebook::jsi::Value::undefined();
        }
        bool registered = false;
        try {
          registered =
              registerWebSocket(callbackContext, wsId, wsPrincipal, connectCapability);
        } catch (...) {
          native_ws_destroy(wsId);
          throw;
        }
        if (!registered) {
          native_ws_destroy(wsId);
          return facebook::jsi::Value::undefined();
        }
        return facebook::jsi::Value(static_cast<int>(wsId));
      });
  rt.global().setProperty(rt, "__exactWsConnect", std::move(wsConnectFn));

  auto wsSendFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsSend"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        (void)requireWebSocketOwner(runtime, ws_id, "__exactWsSend");
        if (args[1].isString()) {
          auto text = args[1].toString(runtime).utf8(runtime);
          native_ws_send(
              ws_id, reinterpret_cast<const uint8_t*>(text.c_str()), text.size(), 1);
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          const uint8_t* viewData = nullptr;
          size_t viewLength = 0;
          // Handles ArrayBuffers and typed-array views alike. WHATWG:
          // send(new Uint8Array(0)) transmits a valid empty binary frame the
          // peer observes as an empty message event, so a zero-length
          // buffer/view must still reach the native layer (ENG-23469).
          if (extractArrayBufferView(runtime, obj, viewData, viewLength)) {
            native_ws_send(ws_id, viewData, viewLength, 0);
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsSend", std::move(wsSendFn));

  auto wsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsClose"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        // @ref LLP 0021#handles-dynamic-authority-and-generations — close is
        // authority-reducing and survives positive grant revocation.
        auto entry = requireWebSocketOwner(
            runtime, ws_id, "__exactWsClose", false);
        if (count > 3 && args[3].isBool() && args[3].getBool()) {
          return facebook::jsi::Value::undefined();
        }
        if (!markWebSocketClosing(ws_id, entry.runtime_nonce)) {
          return facebook::jsi::Value::undefined();
        }
        uint16_t code =
            count > 1 && args[1].isNumber() ? static_cast<uint16_t>(args[1].asNumber()) : 1005;
        std::string reason =
            count > 2 && args[2].isString() ? args[2].toString(runtime).utf8(runtime) : "";
        native_ws_close(ws_id, code, reason.c_str());
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsClose", std::move(wsCloseFn));

  auto wsPauseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsPause"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        (void)requireWebSocketOwner(runtime, ws_id, "__exactWsPause");
        native_ws_pause(ws_id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsPause", std::move(wsPauseFn));

  auto wsResumeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsResume"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        (void)requireWebSocketOwner(runtime, ws_id, "__exactWsResume");
        native_ws_resume(ws_id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsResume", std::move(wsResumeFn));

  auto wsSetFlowControlledFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWsSetFlowControlled"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) return facebook::jsi::Value::undefined();
        uint32_t ws_id = static_cast<uint32_t>(args[0].asNumber());
        (void)requireWebSocketOwner(runtime, ws_id, "__exactWsSetFlowControlled");
        int enabled = args[1].isBool() ? (args[1].getBool() ? 1 : 0) : 0;
        native_ws_set_flow_controlled(ws_id, enabled);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWsSetFlowControlled", std::move(wsSetFlowControlledFn));

#if defined(_WIN32)
  // @ref LLP 0003#windows-native-smoke-coverage — Windows skips the shared
  // runtime bundle, so expose a small public WebSocket constructor over the
  // WinHTTP native bridge here.
  static const char* windowsWebSocketShim = R"JS(
(function(g) {
  var exactWsConnect = g.__exactWsConnect;
  var exactWsSend = g.__exactWsSend;
  var exactWsClose = g.__exactWsClose;
  var exactNetOwner = g.__exactNetOwner;
  if (typeof g.WebSocket === 'function' ||
      typeof exactWsConnect !== 'function' ||
      typeof exactWsSend !== 'function' ||
      typeof exactWsClose !== 'function' ||
      typeof exactNetOwner !== 'function') return;

  var windowsWebSocketStates = new WeakMap();

  function windowsWebSocketState(socket) {
    var state = socket && windowsWebSocketStates.get(socket);
    if (!state) throw new TypeError('Illegal invocation');
    return state;
  }

  function ownedWindowsWebSocketState(socket) {
    var state = windowsWebSocketState(socket);
    exactNetOwner('assert', state.ownerStamp);
    return state;
  }

  function makeEvent(type, props) {
    var event = { type: type };
    props = props || {};
    for (var key in props) {
      if (Object.prototype.hasOwnProperty.call(props, key)) event[key] = props[key];
    }
    return event;
  }

  function handleOpen(socket, protocol, extensions) {
    var state = ownedWindowsWebSocketState(socket);
    // A close() racing the end of the async handshake must not resurrect
    // the socket (ENG-23469).
    if (state.readyState !== WebSocket.CONNECTING) return;
    state.readyState = WebSocket.OPEN;
    state.protocol = protocol || '';
    state.extensions = extensions || '';
    if (typeof state.onopen === 'function') state.onopen.call(socket, makeEvent('open'));
  }

  function handleMessage(socket, data) {
    var state = ownedWindowsWebSocketState(socket);
    if (state.readyState !== WebSocket.OPEN) return;
    if (typeof state.onmessage === 'function') {
      state.onmessage.call(socket, makeEvent('message', { data: data }));
    }
  }

  function handleClose(socket, code, reason, wasClean) {
    var state = ownedWindowsWebSocketState(socket);
    state.socketId = -1;
    state.readyState = WebSocket.CLOSED;
    if (typeof state.onclose === 'function') {
      state.onclose.call(socket, makeEvent('close', {
        code: code || 1005,
        reason: reason || '',
        wasClean: !!wasClean
      }));
    }
  }

  function handleError(socket, message) {
    var state = ownedWindowsWebSocketState(socket);
    if (typeof state.onerror === 'function') {
      state.onerror.call(socket, makeEvent('error', { message: message || 'WebSocket error' }));
    }
  }

  function handleBytesSent(socket, bytesSent) {
    var state = ownedWindowsWebSocketState(socket);
    state.bufferedAmount = Math.max(0, state.bufferedAmount - (bytesSent || 0));
  }

  function WebSocket(url, protocols) {
    if (!(this instanceof WebSocket)) {
      throw new TypeError("Failed to construct 'WebSocket': constructor requires 'new'");
    }
    var state = {
      url: String(url),
      protocol: '',
      extensions: '',
      readyState: WebSocket.CONNECTING,
      bufferedAmount: 0,
      binaryType: 'arraybuffer',
      socketId: -1,
      ownerStamp: exactNetOwner('new'),
      onopen: null,
      onmessage: null,
      onerror: null,
      onclose: null
    };
    // @ref LLP 0013#delegation-and-authority-flow — a retained wrapper may
    // cross a principal boundary, but its native selector remains private.
    windowsWebSocketStates.set(this, state);
    var self = this;
    var bridge = {
      _handleOpen: function(protocol, extensions) {
        handleOpen(self, protocol, extensions);
      },
      _handleMessage: function(data) {
        handleMessage(self, data);
      },
      _handleClose: function(code, reason, wasClean) {
        handleClose(self, code, reason, wasClean);
      },
      _handleError: function(message) {
        handleError(self, message);
      },
      _handleBytesSent: function(bytesSent) {
        handleBytesSent(self, bytesSent);
      }
    };
    var protocolList = Array.isArray(protocols) ? protocols.join(',') : (protocols || '');
    var id = exactWsConnect(state.url, String(protocolList), bridge);
    state.socketId = typeof id === 'number' ? id : -1;
    if (state.socketId < 0) {
      state.readyState = WebSocket.CLOSED;
    }
  }

  WebSocket.CONNECTING = 0;
  WebSocket.OPEN = 1;
  WebSocket.CLOSING = 2;
  WebSocket.CLOSED = 3;
  WebSocket.prototype.CONNECTING = 0;
  WebSocket.prototype.OPEN = 1;
  WebSocket.prototype.CLOSING = 2;
  WebSocket.prototype.CLOSED = 3;

  Object.defineProperties(WebSocket.prototype, {
    url: {
      get: function() { return ownedWindowsWebSocketState(this).url; },
      enumerable: true,
      configurable: true
    },
    protocol: {
      get: function() { return ownedWindowsWebSocketState(this).protocol; },
      enumerable: true,
      configurable: true
    },
    extensions: {
      get: function() { return ownedWindowsWebSocketState(this).extensions; },
      enumerable: true,
      configurable: true
    },
    readyState: {
      get: function() { return ownedWindowsWebSocketState(this).readyState; },
      enumerable: true,
      configurable: true
    },
    bufferedAmount: {
      get: function() { return ownedWindowsWebSocketState(this).bufferedAmount; },
      enumerable: true,
      configurable: true
    },
    binaryType: {
      get: function() { return ownedWindowsWebSocketState(this).binaryType; },
      set: function(value) {
        if (value === 'blob' || value === 'arraybuffer') {
          ownedWindowsWebSocketState(this).binaryType = value;
        }
      },
      enumerable: true,
      configurable: true
    },
    onopen: {
      get: function() { return ownedWindowsWebSocketState(this).onopen; },
      set: function(value) { ownedWindowsWebSocketState(this).onopen = typeof value === 'function' ? value : null; },
      enumerable: true,
      configurable: true
    },
    onmessage: {
      get: function() { return ownedWindowsWebSocketState(this).onmessage; },
      set: function(value) { ownedWindowsWebSocketState(this).onmessage = typeof value === 'function' ? value : null; },
      enumerable: true,
      configurable: true
    },
    onerror: {
      get: function() { return ownedWindowsWebSocketState(this).onerror; },
      set: function(value) { ownedWindowsWebSocketState(this).onerror = typeof value === 'function' ? value : null; },
      enumerable: true,
      configurable: true
    },
    onclose: {
      get: function() { return ownedWindowsWebSocketState(this).onclose; },
      set: function(value) { ownedWindowsWebSocketState(this).onclose = typeof value === 'function' ? value : null; },
      enumerable: true,
      configurable: true
    }
  });

  WebSocket.prototype.send = function(data) {
    var state = ownedWindowsWebSocketState(this);
    if (state.readyState === WebSocket.CONNECTING) {
      throw new Error('WebSocket is not open');
    }
    if (state.readyState !== WebSocket.OPEN) return;
    // Authenticate before inspecting caller-controlled data or reserving
    // bufferedAmount. An unsupported payload reaches the shared native owner
    // gate but never native_ws_send.
    exactWsSend(state.socketId, undefined);
    var bytes = 0;
    if (typeof data === 'string') bytes = data.length;
    else if (data && typeof data.byteLength === 'number') bytes = data.byteLength;
    state.bufferedAmount += bytes;
    try {
      exactWsSend(state.socketId, data);
    } catch (error) {
      state.bufferedAmount = Math.max(0, state.bufferedAmount - bytes);
      throw error;
    }
  };
  WebSocket.prototype.close = function(code, reason) {
    var state = ownedWindowsWebSocketState(this);
    if (state.readyState === WebSocket.CLOSED || state.readyState === WebSocket.CLOSING) return;
    // @ref LLP 0021#handles-dynamic-authority-and-generations — the native
    // call is the strict owner check. Commit terminal JS state only after it
    // succeeds so a denied retained-wrapper call leaves the owner a retry.
    exactWsClose(
      state.socketId,
      code == null ? 1005 : code,
      reason == null ? '' : String(reason)
    );
    if (state.readyState !== WebSocket.CLOSED) {
      state.readyState = WebSocket.CLOSING;
    }
  };

  Object.defineProperty(g, 'WebSocket', {
    value: WebSocket,
    writable: true,
    configurable: true
  });
})(globalThis);
)JS";
  try {
    auto buffer = std::make_shared<facebook::jsi::StringBuffer>(windowsWebSocketShim);
    rt.evaluateJavaScript(buffer, "<windows-websocket-shim>");
  } catch (const facebook::jsi::JSError& err) {
    ex_host_console_log(1, err.getMessage().c_str());
  } catch (const std::exception& err) {
    ex_host_console_log(1, err.what());
  }
#endif
}
