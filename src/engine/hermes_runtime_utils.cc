#include <iomanip>
#include <sstream>

#include "hermes_runtime_internal.h"

std::string escapeJson(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '\"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec;
        } else {
          out << c;
        }
    }
  }
  return out.str();
}

static bool isValidUtf8(const uint8_t* bytes, size_t len) {
  size_t i = 0;
  while (i < len) {
    uint8_t byte1 = bytes[i++];
    if (byte1 < 0x80) {
      continue;
    }

    size_t needed = 0;
    uint32_t codepoint = 0;

    if ((byte1 & 0xE0) == 0xC0) {
      if (byte1 < 0xC2) {
        return false;
      }
      needed = 1;
      codepoint = byte1 & 0x1F;
    } else if ((byte1 & 0xF0) == 0xE0) {
      needed = 2;
      codepoint = byte1 & 0x0F;
    } else if ((byte1 & 0xF8) == 0xF0) {
      if (byte1 > 0xF4) {
        return false;
      }
      needed = 3;
      codepoint = byte1 & 0x07;
    } else {
      return false;
    }

    if (i + needed > len) {
      return false;
    }

    if (needed >= 1) {
      uint8_t cont1 = bytes[i];
      if ((byte1 == 0xE0 && cont1 < 0xA0) || (byte1 == 0xED && cont1 > 0x9F) ||
          (byte1 == 0xF0 && cont1 < 0x90) || (byte1 == 0xF4 && cont1 > 0x8F)) {
        return false;
      }
    }

    for (size_t j = 0; j < needed; j++) {
      uint8_t cont = bytes[i + j];
      if ((cont & 0xC0) != 0x80) {
        return false;
      }
      codepoint = (codepoint << 6) | (cont & 0x3F);
    }
    i += needed;

    if (codepoint > 0x10FFFF || (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
      return false;
    }
  }
  return true;
}

bool appendEscapedJsonText(std::string& out, const uint8_t* bytes, size_t len) {
  if (!isValidUtf8(bytes, len)) {
    return false;
  }
  out += "\"";
  out += escapeJson(std::string(reinterpret_cast<const char*>(bytes), len));
  out += "\"";
  return true;
}

std::string jsonString(const std::string& value) {
  return std::string("\"") + escapeJson(value) + "\"";
}

std::string makeRemoteObject(
    facebook::jsi::Runtime& rt,
    const facebook::jsi::Value& value) {
  if (value.isUndefined()) {
    return "{\"type\":\"undefined\"}";
  }
  if (value.isNull()) {
    return "{\"type\":\"object\",\"subtype\":\"null\",\"value\":null}";
  }
  if (value.isBool()) {
    return std::string("{\"type\":\"boolean\",\"value\":") +
           (value.getBool() ? "true" : "false") + "}";
  }
  if (value.isNumber()) {
    std::ostringstream out;
    out << "{\"type\":\"number\",\"value\":" << value.getNumber() << "}";
    return out.str();
  }
  if (value.isString()) {
    auto text = value.toString(rt).utf8(rt);
    return std::string("{\"type\":\"string\",\"value\":") + jsonString(text) + "}";
  }
  if (value.isObject()) {
    return "{\"type\":\"object\",\"description\":\"[object Object]\"}";
  }
  return "{\"type\":\"undefined\"}";
}

std::string stringifyValue(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  if (value.isUndefined() || value.isNull()) {
    return "null";
  }
  auto jsonObj = runtime.global().getPropertyAsObject(runtime, "JSON");
  auto stringify = jsonObj.getPropertyAsFunction(runtime, "stringify");
  auto json = stringify.call(runtime, value);
  if (!json.isString()) {
    return "null";
  }
  return json.asString(runtime).utf8(runtime);
}

facebook::jsi::Value parseJsonValue(
    facebook::jsi::Runtime& runtime,
    const char* json) {
  auto jsonObj = runtime.global().getPropertyAsObject(runtime, "JSON");
  auto parse = jsonObj.getPropertyAsFunction(runtime, "parse");
  return parse.call(runtime, facebook::jsi::String::createFromUtf8(runtime, json));
}

void pushDebugEvent(ExactHermesRuntime* runtime, const std::string& event) {
  if (!runtime) {
    return;
  }
  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  runtime->debug_events.push_back(event);
}

std::shared_ptr<facebook::hermes::debugger::AsyncDebuggerAPI> snapshotDebugger(
    ExactHermesRuntime* runtime) {
  if (!runtime || !runtime->debugger_available.load()) {
    return nullptr;
  }

  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  if (!runtime->debugger || !runtime->debugger_available.load()) {
    return nullptr;
  }
  return runtime->debugger;
}

void clearDebugger(ExactHermesRuntime* runtime) {
  if (!runtime) {
    return;
  }

  std::lock_guard<std::mutex> lock(runtime->debug_mutex);
  runtime->debugger.reset();
  runtime->debugger_callback_set = false;
}

void disableDebugger(ExactHermesRuntime* runtime) {
  if (!runtime) {
    return;
  }

  runtime->debugger_attached.store(false);
  runtime->debugger_available.store(false);
  clearDebugger(runtime);
}

static std::string pauseReasonToString(facebook::hermes::debugger::PauseReason reason) {
  using facebook::hermes::debugger::PauseReason;
  switch (reason) {
    case PauseReason::DebuggerStatement:
      return "debuggerStatement";
    case PauseReason::Breakpoint:
      return "breakpoint";
    case PauseReason::StepFinish:
      return "step";
    case PauseReason::Exception:
      return "exception";
    case PauseReason::AsyncTriggerExplicit:
      return "pause";
    case PauseReason::AsyncTriggerImplicit:
      return "pause";
    default:
      return "other";
  }
}

std::string buildPausedEvent(facebook::hermes::debugger::Debugger& debugger) {
  using facebook::hermes::debugger::kInvalidLocation;
  const auto& state = debugger.getProgramState();
  auto reason = pauseReasonToString(state.getPauseReason());
  auto stack = state.getStackTrace();

  std::ostringstream out;
  out << "{\"method\":\"Debugger.paused\",\"params\":{";
  out << "\"reason\":" << jsonString(reason) << ",";
  out << "\"callFrames\":[";

  for (uint32_t i = 0; i < stack.callFrameCount(); ++i) {
    auto frame = stack.callFrameForIndex(i);
    auto loc = frame.location;
    uint32_t line = loc.line == kInvalidLocation ? 0 : (loc.line > 0 ? loc.line - 1 : 0);
    uint32_t column =
        loc.column == kInvalidLocation ? 0 : (loc.column > 0 ? loc.column - 1 : 0);

    if (i > 0) {
      out << ",";
    }
    out << "{";
    out << "\"callFrameId\":" << jsonString("frame-" + std::to_string(i)) << ",";
    out << "\"functionName\":" << jsonString(frame.functionName) << ",";
    out << "\"location\":{";
    out << "\"scriptId\":" << jsonString(std::to_string(loc.fileId)) << ",";
    out << "\"lineNumber\":" << line << ",";
    out << "\"columnNumber\":" << column;
    out << "},";
    out << "\"url\":" << jsonString(loc.fileName) << ",";
    out << "\"scopeChain\":[]";
    out << "}";
  }

  out << "],";
  out << "\"hitBreakpoints\":[";
  if (state.getPauseReason() == facebook::hermes::debugger::PauseReason::Breakpoint) {
    auto id = state.getBreakpoint();
    if (id != facebook::hermes::debugger::kInvalidBreakpoint) {
      out << jsonString(std::to_string(id));
    }
  }
  out << "]";
  out << "}}";
  return out.str();
}
