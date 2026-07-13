// TLS bridge host functions for the `tls` builtin (ENG-23492).
//
// Thin JSI marshalling shims over the Rust sans-IO TLS engine
// (src/engine/tls_bridge.rs, `ibex_tls_*`). The JS side (src/builtins/tls.js)
// owns all socket I/O and drives the engine from the event loop; these
// functions only move bytes and JSON strings across the JSI boundary. Native
// reads return exact-size ArrayBuffers that tls.js wraps as Buffers; writes
// accept byte views. null means end-of-stream and "" means would-block/no-data.
// @ref LLP 0004#the-tls-builtin — native TLS bridge host surface
//
// Installed from installNetHostFunctions, so availability tracks the platform
// TCP host functions the bridge rides (Unix hermes_runtime_net.cc, Windows
// hermes_runtime_platform_windows.cc).

#include "hermes_runtime_internal.h"

#include <cmath>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

extern "C" {
uint64_t ibex_tls_client_new(const char* config_json);
char* ibex_tls_last_error();
int64_t ibex_tls_write_tls(uint64_t id, const uint8_t* data, size_t len);
int64_t ibex_tls_tls_read_begin(uint64_t id, size_t max_bytes, void** lease_out);
int64_t ibex_tls_write_plain(uint64_t id, const uint8_t* data, size_t len);
int64_t ibex_tls_plaintext_read_begin(
    uint64_t id,
    size_t max_bytes,
    void** lease_out);
int64_t ibex_tls_read_finish(void* lease, uint8_t* buf, size_t cap);
void ibex_tls_read_cancel(void* lease);
void ibex_tls_transport_eof(uint64_t id);
void ibex_tls_shutdown(uint64_t id);
char* ibex_tls_status_json(uint64_t id);
char* ibex_tls_peer_certs_json(uint64_t id);
int32_t ibex_tls_check_owner(uint64_t id);
int32_t ibex_tls_free(uint64_t id);
uint64_t ibex_tls_owner_token_new();
int32_t ibex_tls_owner_token_check(uint64_t id);
int32_t ibex_tls_owner_token_free(uint64_t id);
void ibex_tls_string_free(char* s);
}

namespace {

uint64_t requireTlsEngineHandle(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* fnName) {
  if (count < 1 || !args[0].isNumber()) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": engine handle required").c_str());
  }
  const double value = args[0].asNumber();
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!std::isfinite(value) || value < 1.0 || value > kMaxSafeInteger ||
      std::floor(value) != value) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": invalid engine handle").c_str());
  }
  return static_cast<uint64_t>(value);
}

uint64_t requireTlsEngineId(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* fnName) {
  const uint64_t id = requireTlsEngineHandle(runtime, args, count, fnName);
  const int32_t owner = ibex_tls_check_owner(id);
  if (owner == 0) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": unknown engine handle").c_str());
  }
  if (owner < 0) {
    throw facebook::jsi::JSError(
        runtime,
        (std::string(fnName) + ": engine belongs to another runtime or principal")
            .c_str());
  }
  return id;
}

size_t requireTlsReadLimit(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* fnName) {
  constexpr double kDefaultReadLimit = 65536.0;
  if (count < 2 || args[1].isUndefined()) {
    return static_cast<size_t>(kDefaultReadLimit);
  }
  if (!args[1].isNumber()) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": maxBytes must be a number").c_str());
  }
  const double value = args[1].asNumber();
  if (!std::isfinite(value) || value < 1.0 || value > kDefaultReadLimit ||
      std::floor(value) != value) {
    throw facebook::jsi::JSError(
        runtime,
        (std::string(fnName) + ": maxBytes must be an integer from 1 to 65536")
            .c_str());
  }
  return static_cast<size_t>(value);
}

constexpr int64_t kTlsReadEmpty = 0;
constexpr int64_t kTlsReadEof = -1;
constexpr int64_t kTlsReadTlsError = -2;
constexpr int64_t kTlsReadUnknownEngine = -3;
constexpr int64_t kTlsReadWrongOwner = -4;
constexpr int64_t kTlsReadProbeError = -5;
constexpr int64_t kTlsReadBusy = -6;
constexpr int64_t kTlsReadInvalidArgument = -7;
constexpr int64_t kTlsReadInternalError = -8;

[[noreturn]] void throwTlsReadError(
    facebook::jsi::Runtime& runtime,
    const char* fnName,
    int64_t status) {
  const char* detail = "unexpected native read status";
  if (status == kTlsReadTlsError) {
    detail = "TLS error";
  } else if (status == kTlsReadUnknownEngine) {
    detail = "unknown engine handle";
  } else if (status == kTlsReadWrongOwner) {
    detail = "engine belongs to another runtime or principal";
  } else if (status == kTlsReadProbeError) {
    detail = "pending-length probe failed";
  } else if (status == kTlsReadBusy) {
    detail = "engine already has an in-progress read";
  } else if (status == kTlsReadInvalidArgument) {
    detail = "invalid native read lease";
  } else if (status == kTlsReadInternalError) {
    detail = "native read did not satisfy its reservation";
  }
  throw facebook::jsi::JSError(
      runtime, (std::string(fnName) + ": " + detail).c_str());
}

// A successful begin call moves the engine into an opaque Rust lease while we
// allocate the exact-size JSI buffer. This guard guarantees allocation
// exceptions restore the untouched engine. finish() consumes the lease and
// fills that buffer directly, without a second engine-registry lookup or a
// staging copy.
class TlsReadLease {
 public:
  explicit TlsReadLease(void* lease) : lease_(lease) {}
  TlsReadLease(const TlsReadLease&) = delete;
  TlsReadLease& operator=(const TlsReadLease&) = delete;

  ~TlsReadLease() {
    if (lease_ != nullptr) {
      ibex_tls_read_cancel(lease_);
    }
  }

  int64_t finish(uint8_t* data, size_t size) {
    void* lease = lease_;
    lease_ = nullptr;
    return ibex_tls_read_finish(lease, data, size);
  }

 private:
  void* lease_;
};

uint64_t requireTlsOwnerToken(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* action) {
  if (count < 2 || !args[1].isNumber()) {
    throw facebook::jsi::JSError(
        runtime, "__exactTlsOwnerToken: numeric token required");
  }
  const double value = args[1].asNumber();
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!std::isfinite(value) || value < 1.0 || value > kMaxSafeInteger ||
      std::floor(value) != value) {
    throw facebook::jsi::JSError(
        runtime, "__exactTlsOwnerToken: invalid token");
  }
  const uint64_t id = static_cast<uint64_t>(value);
  const int32_t ownership = ibex_tls_owner_token_check(id);
  if (ownership == 0) {
    throw facebook::jsi::JSError(
        runtime, "__exactTlsOwnerToken: unknown token");
  }
  if (ownership < 0) {
    throw facebook::jsi::JSError(
        runtime,
        (std::string("__exactTlsOwnerToken ") + action +
         ": token belongs to another runtime or principal")
            .c_str());
  }
  return id;
}

void requireTlsBytes(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* fnName,
    const uint8_t*& data,
    size_t& length) {
  if (count < 2 || !args[1].isObject() ||
      !extractArrayBufferView(runtime, args[1].asObject(runtime), data, length)) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": byte buffer required").c_str());
  }
}

facebook::jsi::ArrayBuffer makeTlsReadBuffer(
    facebook::jsi::Runtime& runtime,
    size_t size,
    const std::shared_ptr<facebook::jsi::Function>& arrayBufferIntrinsic) {
#if defined(EXACT_HAVE_JSI_MUTABLE_BUFFER)
  // This object does not become reachable from JavaScript until the host
  // function returns, after the lease has filled it. In particular, do not
  // consult a mutable global constructor while Rust has the engine reserved:
  // a replacement constructor could retain and later observe the buffer.
  (void)arrayBufferIntrinsic;
  auto backing = std::make_shared<VectorBuffer>(std::vector<uint8_t>(size));
  return facebook::jsi::ArrayBuffer(runtime, backing);
#else
  // Older JSI headers cannot construct an external ArrayBuffer. Capture the
  // original intrinsic during host installation, before application code can
  // replace the global. Calling that stable builtin cannot re-enter user JS.
  auto object =
      arrayBufferIntrinsic->callAsConstructor(runtime, static_cast<double>(size))
          .getObject(runtime);
  return object.getArrayBuffer(runtime);
#endif
}

// Rust returns an owned C string; copy into std::string and free the original.
std::string takeRustString(char* s) {
  if (s == nullptr) {
    return std::string();
  }
  std::string out(s);
  ibex_tls_string_free(s);
  return out;
}

}  // namespace

void installTlsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  // Keep a stable allocation fallback for JSI versions without external
  // MutableBuffer support. This runs during runtime setup, before application
  // code can replace the global constructor.
  auto tlsArrayBufferIntrinsic = std::make_shared<facebook::jsi::Function>(
      rt.global().getPropertyAsFunction(rt, "ArrayBuffer"));

  // One compact host surface mints, checks, and releases the lightweight
  // runtime/principal token protecting JS-side TLS queues before a wire engine
  // exists (and throughout loopback emulation).
  auto tlsOwnerTokenFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsOwnerToken"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactTlsOwnerToken: action required");
        }
        const std::string action = args[0].asString(runtime).utf8(runtime);
        if (action == "new") {
          const uint64_t id = ibex_tls_owner_token_new();
          if (id == 0) {
            throw facebook::jsi::JSError(
                runtime, "__exactTlsOwnerToken: token allocation failed");
          }
          return facebook::jsi::Value(static_cast<double>(id));
        }
        const uint64_t id = requireTlsOwnerToken(
            runtime, args, count, action.c_str());
        if (action == "assert") {
          return facebook::jsi::Value::undefined();
        }
        if (action == "close") {
          if (ibex_tls_owner_token_free(id) != 1) {
            throw facebook::jsi::JSError(
                runtime, "__exactTlsOwnerToken close failed");
          }
          return facebook::jsi::Value::undefined();
        }
        throw facebook::jsi::JSError(
            runtime, "__exactTlsOwnerToken: unsupported action");
      });
  rt.global().setProperty(
      rt, "__exactTlsOwnerToken", std::move(tlsOwnerTokenFn));

  // __exactTlsEngineNew(configJson) -> engine handle (number); throws on
  // invalid config (bad ca PEM, unsupported version range, bad servername).
  auto tlsNewFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineNew"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactTlsEngineNew: config JSON string required");
        }
        std::string config = args[0].asString(runtime).utf8(runtime);
        uint64_t id = ibex_tls_client_new(config.c_str());
        if (id == 0) {
          std::string message = takeRustString(ibex_tls_last_error());
          if (message.empty()) {
            message = "failed to create TLS engine";
          }
          throw facebook::jsi::JSError(
              runtime, ("__exactTlsEngineNew: " + message).c_str());
        }
        return facebook::jsi::Value(static_cast<double>(id));
      });
  rt.global().setProperty(rt, "__exactTlsEngineNew", std::move(tlsNewFn));

  // __exactTlsEngineWriteTls(handle, bytes) -> bytes consumed, or -1 on a
  // fatal TLS error (fetch details via __exactTlsEngineStatus).
  auto tlsWriteTlsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineWriteTls"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineWriteTls");
        if (count < 2) {
          throw facebook::jsi::JSError(
              runtime, "__exactTlsEngineWriteTls: data required");
        }
        const uint8_t* data = nullptr;
        size_t length = 0;
        requireTlsBytes(
            runtime, args, count, "__exactTlsEngineWriteTls", data, length);
        int64_t consumed = ibex_tls_write_tls(id, data, length);
        return facebook::jsi::Value(static_cast<double>(consumed));
      });
  rt.global().setProperty(rt, "__exactTlsEngineWriteTls", std::move(tlsWriteTlsFn));

  // __exactTlsEngineReadTls(handle, maxBytes) -> ArrayBuffer (ciphertext to
  // send) or "" when the engine has nothing pending.
  auto tlsReadTlsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineReadTls"), 2,
      [tlsArrayBufferIntrinsic](
          facebook::jsi::Runtime& runtime,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        uint64_t id =
            requireTlsEngineHandle(runtime, args, count, "__exactTlsEngineReadTls");
        const size_t maxBytes =
            requireTlsReadLimit(runtime, args, count, "__exactTlsEngineReadTls");
        void* rawLease = nullptr;
        const int64_t pending = ibex_tls_tls_read_begin(id, maxBytes, &rawLease);
        if (pending == kTlsReadEmpty) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        if (pending < 0) {
          throwTlsReadError(runtime, "__exactTlsEngineReadTls", pending);
        }
        if (rawLease == nullptr) {
          throwTlsReadError(
              runtime, "__exactTlsEngineReadTls", kTlsReadInternalError);
        }
        const size_t readBytes = static_cast<size_t>(pending);
        TlsReadLease lease(rawLease);
        auto buffer =
            makeTlsReadBuffer(runtime, readBytes, tlsArrayBufferIntrinsic);
        // The ArrayBuffer is not reachable from JavaScript until this host
        // function returns. Fill it only after allocation succeeds; if that
        // allocation throws, the lease guard restores the untouched engine.
        const int64_t n = lease.finish(buffer.data(runtime), readBytes);
        if (n != pending) {
          throwTlsReadError(
              runtime,
              "__exactTlsEngineReadTls",
              n < 0 ? n : kTlsReadInternalError);
        }
        return facebook::jsi::Value(std::move(buffer));
      });
  rt.global().setProperty(rt, "__exactTlsEngineReadTls", std::move(tlsReadTlsFn));

  // __exactTlsEngineWritePlain(handle, data) -> bytes accepted (may be short;
  // caller re-offers the remainder after pumping ciphertext), or -1 on error.
  auto tlsWritePlainFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineWritePlain"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineWritePlain");
        if (count < 2) {
          throw facebook::jsi::JSError(
              runtime, "__exactTlsEngineWritePlain: data required");
        }
        const uint8_t* data = nullptr;
        size_t length = 0;
        requireTlsBytes(
            runtime, args, count, "__exactTlsEngineWritePlain", data, length);
        int64_t accepted = ibex_tls_write_plain(id, data, length);
        return facebook::jsi::Value(static_cast<double>(accepted));
      });
  rt.global().setProperty(rt, "__exactTlsEngineWritePlain", std::move(tlsWritePlainFn));

  // __exactTlsEngineReadPlain(handle, maxBytes) -> ArrayBuffer (data),
  // null (end-of-stream), "" (no data yet); throws on fatal TLS error.
  auto tlsReadPlainFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineReadPlain"), 2,
      [tlsArrayBufferIntrinsic](
          facebook::jsi::Runtime& runtime,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        uint64_t id =
            requireTlsEngineHandle(runtime, args, count, "__exactTlsEngineReadPlain");
        const size_t maxBytes =
            requireTlsReadLimit(runtime, args, count, "__exactTlsEngineReadPlain");
        void* rawLease = nullptr;
        const int64_t pending =
            ibex_tls_plaintext_read_begin(id, maxBytes, &rawLease);
        if (pending == kTlsReadEmpty) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        if (pending == kTlsReadEof) {
          return facebook::jsi::Value::null();
        }
        if (pending < 0) {
          throwTlsReadError(runtime, "__exactTlsEngineReadPlain", pending);
        }
        if (rawLease == nullptr) {
          throwTlsReadError(
              runtime, "__exactTlsEngineReadPlain", kTlsReadInternalError);
        }
        const size_t readBytes = static_cast<size_t>(pending);
        TlsReadLease lease(rawLease);
        auto buffer =
            makeTlsReadBuffer(runtime, readBytes, tlsArrayBufferIntrinsic);
        const int64_t n = lease.finish(buffer.data(runtime), readBytes);
        if (n != pending) {
          throwTlsReadError(
              runtime,
              "__exactTlsEngineReadPlain",
              n < 0 ? n : kTlsReadInternalError);
        }
        return facebook::jsi::Value(std::move(buffer));
      });
  rt.global().setProperty(rt, "__exactTlsEngineReadPlain", std::move(tlsReadPlainFn));

  // __exactTlsEngineTransportEof(handle) -> undefined
  auto tlsEofFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineTransportEof"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineTransportEof");
        ibex_tls_transport_eof(id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTlsEngineTransportEof", std::move(tlsEofFn));

  // __exactTlsEngineShutdown(handle) -> undefined (queues close_notify)
  auto tlsShutdownFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineShutdown"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineShutdown");
        ibex_tls_shutdown(id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTlsEngineShutdown", std::move(tlsShutdownFn));

  // __exactTlsEngineStatus(handle) -> JSON string (see tls_bridge.rs docs).
  auto tlsStatusFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineStatus"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineStatus");
        std::string json = takeRustString(ibex_tls_status_json(id));
        if (json.empty()) {
          throw facebook::jsi::JSError(
              runtime, "__exactTlsEngineStatus: unknown engine handle");
        }
        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactTlsEngineStatus", std::move(tlsStatusFn));

  // __exactTlsEnginePeerCerts(handle) -> JSON array of base64 DER strings,
  // leaf first, exactly as presented on the wire.
  auto tlsPeerCertsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEnginePeerCerts"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEnginePeerCerts");
        std::string json = takeRustString(ibex_tls_peer_certs_json(id));
        if (json.empty()) {
          json = "[]";
        }
        return facebook::jsi::String::createFromUtf8(runtime, json);
      });
  rt.global().setProperty(rt, "__exactTlsEnginePeerCerts", std::move(tlsPeerCertsFn));

  // __exactTlsEngineClose(handle) -> undefined (releases the engine)
  auto tlsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineClose"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineClose");
        const int32_t closed = ibex_tls_free(id);
        if (closed == -2) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactTlsEngineClose: engine has an in-progress read");
        }
        if (closed < 0) {
          throw facebook::jsi::JSError(
              runtime,
              "__exactTlsEngineClose: engine belongs to another runtime or principal");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTlsEngineClose", std::move(tlsCloseFn));
}
