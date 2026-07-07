// TLS bridge host functions for the `tls` builtin (ENG-23492).
//
// Thin JSI marshalling shims over the Rust sans-IO TLS engine
// (src/engine/tls_bridge.rs, `ibex_tls_*`). The JS side (src/builtins/tls.js)
// owns all socket I/O and drives the engine from the event loop; these
// functions only move bytes and JSON strings across the JSI boundary. Byte
// conventions mirror __exactTcpRead/__exactTcpWrite: Uint8Array for data,
// null for end-of-stream, "" for would-block/no-data.
// @ref LLP 0004#the-tls-builtin — native TLS bridge host surface
//
// Not compiled on Windows (build.rs); the Rust engine module is likewise
// cfg-gated off there. Installed from installNetHostFunctions
// (hermes_runtime_net.cc), so availability tracks the TCP host functions the
// bridge rides.

#include "hermes_runtime_internal.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" {
uint64_t ibex_tls_client_new(const char* config_json);
char* ibex_tls_last_error();
int64_t ibex_tls_write_tls(uint64_t id, const uint8_t* data, size_t len);
int64_t ibex_tls_read_tls(uint64_t id, uint8_t* buf, size_t cap);
int64_t ibex_tls_write_plain(uint64_t id, const uint8_t* data, size_t len);
int64_t ibex_tls_read_plain(uint64_t id, uint8_t* buf, size_t cap);
void ibex_tls_transport_eof(uint64_t id);
void ibex_tls_shutdown(uint64_t id);
char* ibex_tls_status_json(uint64_t id);
char* ibex_tls_peer_certs_json(uint64_t id);
void ibex_tls_free(uint64_t id);
void ibex_tls_string_free(char* s);
}

namespace {

uint64_t requireTlsEngineId(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    const char* fnName) {
  if (count < 1 || !args[0].isNumber()) {
    throw facebook::jsi::JSError(
        runtime, (std::string(fnName) + ": engine handle required").c_str());
  }
  return static_cast<uint64_t>(args[0].asNumber());
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
        std::vector<uint8_t> bytes = extractBytes(runtime, args[1]);
        int64_t consumed =
            ibex_tls_write_tls(id, bytes.empty() ? nullptr : bytes.data(), bytes.size());
        return facebook::jsi::Value(static_cast<double>(consumed));
      });
  rt.global().setProperty(rt, "__exactTlsEngineWriteTls", std::move(tlsWriteTlsFn));

  // __exactTlsEngineReadTls(handle, maxBytes) -> Uint8Array (ciphertext to
  // send) or "" when the engine has nothing pending.
  auto tlsReadTlsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineReadTls"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineReadTls");
        int maxBytes = 65536;
        if (count > 1 && args[1].isNumber()) {
          maxBytes = static_cast<int>(args[1].asNumber());
          if (maxBytes <= 0) maxBytes = 65536;
        }
        std::vector<uint8_t> buf(static_cast<size_t>(maxBytes));
        int64_t n = ibex_tls_read_tls(id, buf.data(), buf.size());
        if (n <= 0) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        buf.resize(static_cast<size_t>(n));
        return makeUint8Array(runtime, std::move(buf));
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
        std::vector<uint8_t> bytes = extractBytes(runtime, args[1]);
        int64_t accepted =
            ibex_tls_write_plain(id, bytes.empty() ? nullptr : bytes.data(), bytes.size());
        return facebook::jsi::Value(static_cast<double>(accepted));
      });
  rt.global().setProperty(rt, "__exactTlsEngineWritePlain", std::move(tlsWritePlainFn));

  // __exactTlsEngineReadPlain(handle, maxBytes) -> Uint8Array (data),
  // null (end-of-stream), "" (no data yet); throws on fatal TLS error.
  auto tlsReadPlainFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTlsEngineReadPlain"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        uint64_t id = requireTlsEngineId(runtime, args, count, "__exactTlsEngineReadPlain");
        int maxBytes = 65536;
        if (count > 1 && args[1].isNumber()) {
          maxBytes = static_cast<int>(args[1].asNumber());
          if (maxBytes <= 0) maxBytes = 65536;
        }
        std::vector<uint8_t> buf(static_cast<size_t>(maxBytes));
        int64_t n = ibex_tls_read_plain(id, buf.data(), buf.size());
        if (n > 0) {
          buf.resize(static_cast<size_t>(n));
          return makeUint8Array(runtime, std::move(buf));
        }
        if (n == 0) {
          return facebook::jsi::String::createFromUtf8(runtime, "");
        }
        if (n == -1) {
          return facebook::jsi::Value::null();
        }
        throw facebook::jsi::JSError(runtime, "__exactTlsEngineReadPlain: TLS error");
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
        ibex_tls_free(id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTlsEngineClose", std::move(tlsCloseFn));
}
