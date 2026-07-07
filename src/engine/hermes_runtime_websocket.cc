#include "hermes_runtime_internal.h"

#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
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

namespace {

struct WebSocketEntry {
  uint64_t owner;
  std::string capability;
};

static std::mutex g_websocket_mutex;
static std::unordered_map<uint32_t, WebSocketEntry> g_websockets;
// Connect handshakes run asynchronously (ENG-23469), so a fast failure can
// fire the close/error callbacks -- whose unregisterWebSocket runs on the io
// thread -- before the JS thread reaches registerWebSocket after
// native_ws_connect returns. ws_ids increase monotonically and are never
// reused, and registrations happen on the JS thread in id order, so an
// unregister for an id above the registration high-water mark can only be
// such an early death: remember it and drop the late registration instead of
// leaking a ghost entry.
static std::unordered_set<uint32_t> g_early_unregistered;
static uint32_t g_max_registered_ws_id = 0;

void registerWebSocket(uint32_t ws_id, uint64_t owner, const std::string& capability) {
  if (ws_id == 0 || isAllowAll()) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_websocket_mutex);
  if (ws_id > g_max_registered_ws_id) {
    g_max_registered_ws_id = ws_id;
  }
  if (g_early_unregistered.erase(ws_id) > 0) {
    return;  // the socket already died; nothing to track
  }
  g_websockets[ws_id] = WebSocketEntry{owner, capability};
}

WebSocketEntry requireWebSocketOwner(
    facebook::jsi::Runtime& runtime,
    uint32_t ws_id,
    const char* syscall) {
  if (isAllowAll()) {
    return WebSocketEntry{currentPrincipalId(), ""};
  }
  WebSocketEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_websocket_mutex);
    auto it = g_websockets.find(ws_id);
    if (it == g_websockets.end()) {
      throw facebook::jsi::JSError(runtime, std::string(syscall) + ": unknown WebSocket");
    }
    entry = it->second;
  }
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, std::string(syscall) + ": WebSocket belongs to a different principal");
  }
  if (!entry.capability.empty() && !checkCapability(entry.capability)) {
    throw facebook::jsi::JSError(runtime, std::string("Permission denied: ") + syscall);
  }
  return entry;
}

void unregisterWebSocket(uint32_t ws_id) {
  if (ws_id == 0 || isAllowAll()) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_websocket_mutex);
  if (g_websockets.erase(ws_id) > 0) {
    return;
  }
  if (ws_id > g_max_registered_ws_id) {
    // Died before the JS thread could register it (see comment above); the
    // marker is consumed by the upcoming registerWebSocket for this id.
    g_early_unregistered.insert(ws_id);
  }
}

} // namespace

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
        if (!parseNetworkUrl(url, parsedUrl) ||
            (parsedUrl.scheme != "ws" && parsedUrl.scheme != "wss")) {
          throw facebook::jsi::JSError(runtime, "__exactWsConnect: invalid network URL");
        }
        // @ref LLP 0013#policy — WebSocket native I/O is the security boundary;
        // endpoint-scoped grants must authorize the concrete peer, not just JS.
        std::string connectCapability =
            "network:connect:" + parsedUrl.host + ":" + std::to_string(parsedUrl.port);
        if (!checkCapability(connectCapability)) {
          throw facebook::jsi::JSError(
              runtime, "Permission denied: network:connect capability required");
        }
        auto wsPrincipal = currentPrincipalId();
        auto wsInstance = std::make_shared<facebook::jsi::Object>(args[2].asObject(runtime));
        auto* callbackContext =
            new NativeWebSocketCallbackContext{handle, wsInstance, wsPrincipal, connectCapability, 1};

        auto wsId = native_ws_connect(
            url.c_str(),
            protocols.empty() ? nullptr : protocols.c_str(),
            [](uint32_t, const char* protocol, const char* extensions, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->runtime || !context->ws_instance) {
                return;
              }
              auto runtime = context->runtime;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto protoCopy = std::string(protocol ? protocol : "");
              auto extCopy = std::string(extensions ? extensions : "");
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);

              pushRuntimeCallback(
                  runtime,
                  [wsObj,
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
            [](uint32_t, const uint8_t* data, size_t length, int is_text, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->runtime || !context->ws_instance) {
                return;
              }
              auto runtime = context->runtime;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              if (is_text) {
                auto textCopy = std::string(reinterpret_cast<const char*>(data), length);
                pushRuntimeCallback(
                    runtime,
                    [wsObj,
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
                    runtime,
                    [wsObj,
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
              if (!context || !context->runtime || !context->ws_instance) {
                return;
              }
              auto runtime = context->runtime;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto reasonCopy = std::string(reason ? reason : "");
              auto codeCopy = code;
              auto cleanCopy = was_clean;
              unregisterWebSocket(ws_id);
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  runtime,
                  [wsObj,
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
              if (!context || !context->runtime || !context->ws_instance) {
                return;
              }
              auto runtime = context->runtime;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto msgCopy = std::string(message ? message : "Unknown error");
              unregisterWebSocket(ws_id);
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  runtime,
                  [wsObj,
                   msgCopy,
                   principal,
                   context_guard = std::move(context_guard)](facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    auto fn = wsObj->getPropertyAsFunction(rt, "_handleError");
                    fn.call(rt, facebook::jsi::String::createFromUtf8(rt, msgCopy));
                  });
            },
            [](uint32_t, size_t bytes_sent, void* ctx) {
              auto* context = static_cast<NativeWebSocketCallbackContext*>(ctx);
              if (!context || !context->runtime || !context->ws_instance) {
                return;
              }
              auto runtime = context->runtime;
              auto wsObj = context->ws_instance;
              auto principal = context->principal;
              auto sentCopy = bytes_sent;
              native_ws_retain_context(context);
              auto context_guard = std::shared_ptr<void>(context, native_ws_release_context);
              pushRuntimeCallback(
                  runtime,
                  [wsObj,
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
        registerWebSocket(wsId, wsPrincipal, connectCapability);
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
        (void)requireWebSocketOwner(runtime, ws_id, "__exactWsClose");
        uint16_t code =
            count > 1 && args[1].isNumber() ? static_cast<uint16_t>(args[1].asNumber()) : 1005;
        std::string reason =
            count > 2 && args[2].isString() ? args[2].toString(runtime).utf8(runtime) : "";
        native_ws_close(ws_id, code, reason.c_str());
        unregisterWebSocket(ws_id);
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
  if (typeof g.WebSocket === 'function' || typeof g.__exactWsConnect !== 'function') return;

  function makeEvent(type, props) {
    var event = { type: type };
    props = props || {};
    for (var key in props) {
      if (Object.prototype.hasOwnProperty.call(props, key)) event[key] = props[key];
    }
    return event;
  }

  function WebSocket(url, protocols) {
    if (!(this instanceof WebSocket)) {
      throw new TypeError("Failed to construct 'WebSocket': constructor requires 'new'");
    }
    this.url = String(url);
    this.protocol = '';
    this.extensions = '';
    this.readyState = WebSocket.CONNECTING;
    this.bufferedAmount = 0;
    this.binaryType = 'arraybuffer';
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    var self = this;
    this._handleOpen = function(protocol, extensions) {
      WebSocket.prototype._handleOpen.call(self, protocol, extensions);
    };
    this._handleMessage = function(data) {
      WebSocket.prototype._handleMessage.call(self, data);
    };
    this._handleClose = function(code, reason, wasClean) {
      WebSocket.prototype._handleClose.call(self, code, reason, wasClean);
    };
    this._handleError = function(message) {
      WebSocket.prototype._handleError.call(self, message);
    };
    this._handleBytesSent = function(bytesSent) {
      WebSocket.prototype._handleBytesSent.call(self, bytesSent);
    };
    var protocolList = Array.isArray(protocols) ? protocols.join(',') : (protocols || '');
    var id = g.__exactWsConnect(this.url, String(protocolList), this);
    this._socketId = typeof id === 'number' ? id : -1;
    if (this._socketId < 0) {
      this.readyState = WebSocket.CLOSED;
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

  WebSocket.prototype._handleOpen = function(protocol, extensions) {
    // A close() racing the end of the async handshake must not resurrect
    // the socket (ENG-23469).
    if (this.readyState !== WebSocket.CONNECTING) return;
    this.readyState = WebSocket.OPEN;
    this.protocol = protocol || '';
    this.extensions = extensions || '';
    if (typeof this.onopen === 'function') this.onopen(makeEvent('open'));
  };
  WebSocket.prototype._handleMessage = function(data) {
    if (typeof this.onmessage === 'function') {
      this.onmessage(makeEvent('message', { data: data }));
    }
  };
  WebSocket.prototype._handleClose = function(code, reason, wasClean) {
    this.readyState = WebSocket.CLOSED;
    if (typeof this.onclose === 'function') {
      this.onclose(makeEvent('close', {
        code: code || 1005,
        reason: reason || '',
        wasClean: !!wasClean
      }));
    }
  };
  WebSocket.prototype._handleError = function(message) {
    if (typeof this.onerror === 'function') {
      this.onerror(makeEvent('error', { message: message || 'WebSocket error' }));
    }
  };
  WebSocket.prototype._handleBytesSent = function(bytesSent) {
    this.bufferedAmount = Math.max(0, this.bufferedAmount - (bytesSent || 0));
  };
  WebSocket.prototype.send = function(data) {
    if (this.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket is not open');
    }
    if (typeof data === 'string') this.bufferedAmount += data.length;
    else if (data && typeof data.byteLength === 'number') this.bufferedAmount += data.byteLength;
    g.__exactWsSend(this._socketId, data);
  };
  WebSocket.prototype.close = function(code, reason) {
    if (this.readyState === WebSocket.CLOSED || this.readyState === WebSocket.CLOSING) return;
    this.readyState = WebSocket.CLOSING;
    g.__exactWsClose(this._socketId, code || 1005, reason || '');
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
