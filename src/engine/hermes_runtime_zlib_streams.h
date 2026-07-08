#pragma once

#include "hermes_runtime_internal.h"

#include <atomic>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <zlib.h>

namespace ibex_zlib_streams {

// @ref LLP 0004#the-zlib-builtin — the stream host ABI keeps z_stream state
// native-side so JS does not concatenate whole streaming payloads.
struct ZlibStreamState {
  z_stream stream{};
  bool deflater = false;
  int mode = 0;
  int window_bits = 15;
  bool initialized = false;
  bool finished = false;
  std::vector<uint8_t> dictionary;

  ~ZlibStreamState() {
    if (!initialized) {
      return;
    }
    if (deflater) {
      deflateEnd(&stream);
    } else {
      inflateEnd(&stream);
    }
  }
};

inline std::mutex& zlibStreamMutex() {
  static auto* mutex = new std::mutex();
  return *mutex;
}

inline std::unordered_map<uint32_t, std::unique_ptr<ZlibStreamState>>& zlibStreams() {
  static auto* streams = new std::unordered_map<uint32_t, std::unique_ptr<ZlibStreamState>>();
  return *streams;
}

inline std::atomic<uint32_t>& nextZlibStreamId() {
  static auto* next = new std::atomic<uint32_t>(1);
  return *next;
}

inline int windowBitsForMode(bool deflater, int mode) {
  if (mode == 2) {
    return -15;
  }
  if (mode == 1) {
    return deflater ? 15 + 16 : 15 + 32;
  }
  return 15;
}

inline std::string zlibErrorMessage(const char* operation, int ret, const z_stream& stream) {
  std::ostringstream out;
  out << operation << " failed";
  if (ret == Z_STREAM_ERROR) {
    out << ": stream error";
  } else if (ret == Z_MEM_ERROR) {
    out << ": memory error";
  } else if (ret == Z_DATA_ERROR) {
    out << ": data error";
  } else if (ret == Z_NEED_DICT) {
    out << ": dictionary required";
  } else if (ret == Z_BUF_ERROR) {
    out << ": buffer error";
  } else if (ret != Z_OK && ret != Z_STREAM_END) {
    out << ": zlib error " << ret;
  }
  if (stream.msg) {
    out << ": " << stream.msg;
  }
  return out.str();
}

inline void throwZlibError(
    facebook::jsi::Runtime& runtime,
    const char* operation,
    int ret,
    const z_stream& stream) {
  throw facebook::jsi::JSError(runtime, zlibErrorMessage(operation, ret, stream));
}

inline bool looksLikeGzipHeader(const Bytef* data, uInt length) {
  return length >= 2 && data[0] == 0x1f && data[1] == 0x8b;
}

inline void resetInflateForNextGzipMember(
    facebook::jsi::Runtime& runtime,
    ZlibStreamState& state,
    const Bytef* next_in,
    uInt avail_in) {
  inflateEnd(&state.stream);
  state.stream = {};
  int ret = inflateInit2(&state.stream, state.window_bits);
  if (ret != Z_OK) {
    state.initialized = false;
    throw facebook::jsi::JSError(runtime, "inflateInit2 failed for next gzip member");
  }
  state.initialized = true;
  state.finished = false;
  state.stream.next_in = const_cast<Bytef*>(next_in);
  state.stream.avail_in = avail_in;
}

inline std::vector<uint8_t> deflateStreamWrite(
    facebook::jsi::Runtime& runtime,
    ZlibStreamState& state,
    const std::vector<uint8_t>& input,
    int flush) {
  if (state.finished) {
    throw facebook::jsi::JSError(runtime, "deflate stream already finished");
  }

  state.stream.next_in = const_cast<Bytef*>(input.empty() ? nullptr : input.data());
  state.stream.avail_in = static_cast<uInt>(input.size());

  std::vector<uint8_t> output;
  uint8_t out_buf[32768];
  int ret = Z_OK;

  do {
    uInt before_in = state.stream.avail_in;
    size_t before_out = output.size();

    state.stream.next_out = out_buf;
    state.stream.avail_out = sizeof(out_buf);
    ret = deflate(&state.stream, flush);
    if (ret == Z_STREAM_ERROR || ret == Z_MEM_ERROR) {
      throwZlibError(runtime, "deflate", ret, state.stream);
    }

    size_t have = sizeof(out_buf) - state.stream.avail_out;
    output.insert(output.end(), out_buf, out_buf + have);

    if (flush == Z_FINISH && ret == Z_STREAM_END) {
      state.finished = true;
      break;
    }
    if (ret == Z_BUF_ERROR &&
        state.stream.avail_in == before_in &&
        output.size() == before_out) {
      break;
    }
  } while (
      state.stream.avail_in > 0 ||
      state.stream.avail_out == 0 ||
      (flush == Z_FINISH && ret != Z_STREAM_END));

  if (flush == Z_FINISH && ret != Z_STREAM_END) {
    throwZlibError(runtime, "deflate", ret, state.stream);
  }

  return output;
}

inline std::vector<uint8_t> inflateStreamWrite(
    facebook::jsi::Runtime& runtime,
    ZlibStreamState& state,
    const std::vector<uint8_t>& input,
    int flush,
    bool final,
    bool lenient) {
  if (state.finished) {
    if (state.mode == 1 && !input.empty() && looksLikeGzipHeader(input.data(), static_cast<uInt>(input.size()))) {
      resetInflateForNextGzipMember(runtime, state, input.data(), static_cast<uInt>(input.size()));
    } else {
      return {};
    }
  } else {
    state.stream.next_in = const_cast<Bytef*>(input.empty() ? nullptr : input.data());
    state.stream.avail_in = static_cast<uInt>(input.size());
  }

  std::vector<uint8_t> output;
  uint8_t out_buf[32768];
  int ret = Z_OK;

  do {
    uInt before_in = state.stream.avail_in;
    size_t before_out = output.size();

    state.stream.next_out = out_buf;
    state.stream.avail_out = sizeof(out_buf);
    ret = inflate(&state.stream, flush);

    if (ret == Z_NEED_DICT) {
      if (state.dictionary.empty()) {
        throwZlibError(runtime, "inflate", ret, state.stream);
      }
      int dict_ret = inflateSetDictionary(
          &state.stream,
          state.dictionary.data(),
          static_cast<uInt>(state.dictionary.size()));
      if (dict_ret != Z_OK) {
        throwZlibError(runtime, "inflateSetDictionary", dict_ret, state.stream);
      }
      continue;
    }
    if (ret == Z_MEM_ERROR) {
      throwZlibError(runtime, "inflate", ret, state.stream);
    }
    if (ret == Z_DATA_ERROR) {
      if (!lenient) {
        throwZlibError(runtime, "inflate", ret, state.stream);
      }
      break;
    }

    size_t have = sizeof(out_buf) - state.stream.avail_out;
    output.insert(output.end(), out_buf, out_buf + have);

    if (ret == Z_STREAM_END) {
      if (state.mode == 1 && state.stream.avail_in > 0) {
        const Bytef* next_in = state.stream.next_in;
        uInt remaining = state.stream.avail_in;
        if (looksLikeGzipHeader(next_in, remaining)) {
          resetInflateForNextGzipMember(runtime, state, next_in, remaining);
          ret = Z_OK;
          continue;
        }
      }
      state.finished = true;
      break;
    }

    if (ret == Z_BUF_ERROR &&
        state.stream.avail_in == before_in &&
        output.size() == before_out) {
      break;
    }
  } while (state.stream.avail_in > 0 || state.stream.avail_out == 0);

  if (final && !state.finished && !lenient) {
    throw facebook::jsi::JSError(runtime, "inflate failed: unexpected end of file");
  }

  return output;
}

inline std::vector<uint8_t> deflateStreamParams(
    facebook::jsi::Runtime& runtime,
    ZlibStreamState& state,
    int level,
    int strategy) {
  if (!state.deflater) {
    throw facebook::jsi::JSError(runtime, "deflateParams called on an inflate stream");
  }
  if (state.finished) {
    throw facebook::jsi::JSError(runtime, "deflate stream already finished");
  }

  std::vector<uint8_t> output;
  uint8_t out_buf[32768];
  int ret = Z_OK;

  do {
    state.stream.next_out = out_buf;
    state.stream.avail_out = sizeof(out_buf);
    ret = deflateParams(&state.stream, level, strategy);
    size_t have = sizeof(out_buf) - state.stream.avail_out;
    output.insert(output.end(), out_buf, out_buf + have);
  } while (state.stream.avail_out == 0);

  if (ret != Z_OK) {
    throwZlibError(runtime, "deflateParams", ret, state.stream);
  }

  return output;
}

inline uint32_t allocateZlibStreamId() {
  uint32_t id = nextZlibStreamId().fetch_add(1, std::memory_order_relaxed);
  if (id == 0) {
    id = nextZlibStreamId().fetch_add(1, std::memory_order_relaxed);
  }
  return id;
}

inline uint32_t readZlibStreamId(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, "zlib stream id must be a number");
  }
  double raw = value.asNumber();
  if (raw <= 0 || raw > static_cast<double>(std::numeric_limits<uint32_t>::max())) {
    throw facebook::jsi::JSError(runtime, "invalid zlib stream id");
  }
  return static_cast<uint32_t>(raw);
}

inline void installZlibStreamHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto createFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactZlibCreate"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactZlibCreate: kind and mode required");
        }

        auto state = std::make_unique<ZlibStreamState>();
        state->deflater = static_cast<int>(args[0].asNumber()) == 0;
        state->mode = static_cast<int>(args[1].asNumber());
        int level = Z_DEFAULT_COMPRESSION;
        if (count > 2 && args[2].isNumber()) {
          level = static_cast<int>(args[2].asNumber());
        }
        int strategy = Z_DEFAULT_STRATEGY;
        if (count > 3 && args[3].isNumber()) {
          strategy = static_cast<int>(args[3].asNumber());
        }
        if (count > 4 && !args[4].isUndefined() && !args[4].isNull()) {
          state->dictionary = extractBytes(runtime, args[4]);
        }

        state->window_bits = windowBitsForMode(state->deflater, state->mode);
        int ret = Z_OK;
        if (state->deflater) {
          ret = deflateInit2(
              &state->stream,
              level,
              Z_DEFLATED,
              state->window_bits,
              8,
              strategy);
          if (ret == Z_OK && !state->dictionary.empty() && state->mode != 1) {
            ret = deflateSetDictionary(
                &state->stream,
                state->dictionary.data(),
                static_cast<uInt>(state->dictionary.size()));
          }
        } else {
          ret = inflateInit2(&state->stream, state->window_bits);
        }
        if (ret != Z_OK) {
          throwZlibError(runtime, state->deflater ? "deflateInit2" : "inflateInit2", ret, state->stream);
        }
        state->initialized = true;

        uint32_t id = allocateZlibStreamId();
        {
          std::lock_guard<std::mutex> lock(zlibStreamMutex());
          zlibStreams()[id] = std::move(state);
        }
        return facebook::jsi::Value(static_cast<double>(id));
      });
  rt.global().setProperty(rt, "__exactZlibCreate", std::move(createFn));

  auto writeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactZlibWrite"),
      5,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactZlibWrite: id and data required");
        }
        uint32_t id = readZlibStreamId(runtime, args[0]);
        auto input = extractBytes(runtime, args[1]);
        int flush = Z_NO_FLUSH;
        if (count > 2 && args[2].isNumber()) {
          flush = static_cast<int>(args[2].asNumber());
        }
        bool final = count > 3 && args[3].isBool() && args[3].getBool();
        bool lenient = count > 4 && args[4].isBool() && args[4].getBool();

        std::lock_guard<std::mutex> lock(zlibStreamMutex());
        auto it = zlibStreams().find(id);
        if (it == zlibStreams().end()) {
          throw facebook::jsi::JSError(runtime, "unknown zlib stream id");
        }
        auto& state = *it->second;
        auto output = state.deflater
            ? deflateStreamWrite(runtime, state, input, final ? Z_FINISH : flush)
            : inflateStreamWrite(runtime, state, input, flush, final, lenient);
        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactZlibWrite", std::move(writeFn));

  auto paramsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactZlibParams"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[1].isNumber() || !args[2].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactZlibParams: id, level, and strategy required");
        }
        uint32_t id = readZlibStreamId(runtime, args[0]);
        int level = static_cast<int>(args[1].asNumber());
        int strategy = static_cast<int>(args[2].asNumber());

        std::lock_guard<std::mutex> lock(zlibStreamMutex());
        auto it = zlibStreams().find(id);
        if (it == zlibStreams().end()) {
          throw facebook::jsi::JSError(runtime, "unknown zlib stream id");
        }
        auto output = deflateStreamParams(runtime, *it->second, level, strategy);
        return makeUint8Array(runtime, std::move(output));
      });
  rt.global().setProperty(rt, "__exactZlibParams", std::move(paramsFn));

  auto closeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactZlibClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          return facebook::jsi::Value::undefined();
        }
        uint32_t id = readZlibStreamId(runtime, args[0]);
        std::lock_guard<std::mutex> lock(zlibStreamMutex());
        zlibStreams().erase(id);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactZlibClose", std::move(closeFn));
}

} // namespace ibex_zlib_streams
