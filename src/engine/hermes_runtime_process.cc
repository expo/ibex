#include "hermes_runtime_internal.h"

// PATH_MAX / realpath live in <limits.h> on Linux; macOS pulls them in
// transitively. Spell it out so the realpath() path-resolution helpers build
// on Linux. @ref LLP 0008#sockets-dns-and-process
#include <limits.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#if defined(__APPLE__)
#include <crt_externs.h>
#else
extern "C" char** environ;
#endif

namespace {
// @ref LLP 0008#sockets-dns-and-process — a cancellable timeout watchdog for the
// SYNCHRONOUS child_process paths (ENG-23113: __exactExecSync /
// __exactSpawnSync). Its destructor cancels + JOINS the worker, so the worker
// thread can never outlive this object's frame (the old code detached a thread
// that captured stack `std::atomic<bool>`s BY REFERENCE — on a fast child it woke
// after the host function returned and read/wrote the freed frame, and for
// spawnSync could `kill(pid, SIGKILL)` an unrelated recycled PID). Once the child
// is reaped the main path calls cancelAndJoin(): the worker either already fired
// while the child was alive (a real timeout) or is cancelled before it can wake.
struct SyncTimeoutWatchdog {
  std::mutex mtx;
  std::condition_variable cv;
  bool finished = false;  // set by the main path to cancel the worker
  std::atomic<bool> timedOut{false};
  std::atomic<bool> childExited{false};
  std::thread worker;

  ~SyncTimeoutWatchdog() { cancelAndJoin(); }

  // Cancel the watchdog (so it will not fire) and join the worker. Idempotent —
  // the main path calls it once the child is reaped; the destructor is a no-op
  // second call on every early-exit / exception path.
  void cancelAndJoin() {
    {
      std::lock_guard<std::mutex> lk(mtx);
      finished = true;
    }
    cv.notify_all();
    if (worker.joinable()) worker.join();
  }
};
}  // namespace

static std::string s_parseEnvJsonStr(const std::string& value, size_t& pos) {
  std::string out;
  if (pos >= value.size() || value[pos] != '"') return out;
  ++pos;
  while (pos < value.size()) {
    char ch = value[pos++];
    if (ch == '\\' && pos < value.size()) {
      char escaped = value[pos++];
      if (escaped == 'n') out.push_back('\n');
      else if (escaped == 't') out.push_back('\t');
      else if (escaped == 'r') out.push_back('\r');
      else if (escaped == '"') out.push_back('"');
      else if (escaped == '\\') out.push_back('\\');
      else if (escaped == '/') out.push_back('/');
      else out.push_back(escaped);
      continue;
    }
    if (ch == '"') break;
    out.push_back(ch);
  }
  return out;
}

static std::vector<std::string> s_parseEnvFromOpts(const std::string& optsJson) {
  std::vector<std::string> envVec;
  auto envPos = optsJson.find("\"env\":{");
  if (envPos == std::string::npos) return envVec;
  size_t pos = envPos + 7;
  while (pos < optsJson.size()) {
    while (pos < optsJson.size() && (optsJson[pos] == ' ' || optsJson[pos] == ',' ||
           optsJson[pos] == '\n' || optsJson[pos] == '\r' || optsJson[pos] == '\t')) pos++;
    if (pos >= optsJson.size() || optsJson[pos] == '}') break;
    if (optsJson[pos] != '"') break;
    auto key = s_parseEnvJsonStr(optsJson, pos);
    while (pos < optsJson.size() && (optsJson[pos] == ':' || optsJson[pos] == ' ')) pos++;
    if (pos >= optsJson.size()) break;
    if (optsJson[pos] == '"') {
      auto val = s_parseEnvJsonStr(optsJson, pos);
      envVec.push_back(key + "=" + val);
    } else {
      while (pos < optsJson.size() && optsJson[pos] != ',' && optsJson[pos] != '}') pos++;
    }
  }
  return envVec;
}

// (ENG-23485) Parse options.uid/options.gid for the spawn child. Trust a
// "uid"/"gid" key only when it appears BEFORE the env object in the options
// JSON — JS serializes credentials ahead of env, so an env *value* containing
// the byte sequence '"uid":0' can never be mistaken for the option (raw fd/
// credential integers are forgeable inputs; see LLP 0013's policy concerns).
// The digit guard rejects quoted lookalikes such as {"env":{"uid":"1000"}}.
static void s_parseSpawnCredentials(const std::string& optsJson,
                                    long& spawnUid,
                                    long& spawnGid) {
  auto envKeyPos = optsJson.find("\"env\":");
  auto readCredential = [&](const char* key) -> long {
    auto pos = optsJson.find(key);
    if (pos == std::string::npos) return -1;
    if (envKeyPos != std::string::npos && pos > envKeyPos) return -1;
    const char* p = optsJson.c_str() + pos + std::strlen(key);
    if (*p < '0' || *p > '9') return -1;
    return std::strtol(p, nullptr, 10);
  };
  spawnUid = readCredential("\"uid\":");
  spawnGid = readCredential("\"gid\":");
}

// (ENG-23485) Apply options.gid/options.uid in the forked child, gid before
// uid (once uid drops privileges setgid would fail) — libuv's order. Returns
// 0 on success; on failure returns the errno so the caller can report it
// through the exec error pipe instead of silently running the child with the
// parent's credentials.
static int s_applySpawnCredentials(long spawnGid, long spawnUid) {
  if (spawnGid >= 0 && setgid(static_cast<gid_t>(spawnGid)) != 0) {
    return errno != 0 ? errno : EPERM;
  }
  if (spawnUid >= 0 && setuid(static_cast<uid_t>(spawnUid)) != 0) {
    return errno != 0 ? errno : EPERM;
  }
  return 0;
}

void installChildProcessHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

#if defined(EXACT_PLATFORM_ANDROID)
  const char* unavailableMessage =
      "child_process is not available in Android app sandboxes";
  const char* spawnSyncUnavailableJson =
      "{\"stdout\":\"\",\"stderr\":\"\",\"status\":null,\"pid\":0,"
      "\"error\":\"child_process is not available in Android app sandboxes\","
      "\"code\":\"ERR_FEATURE_UNAVAILABLE_ON_PLATFORM\",\"errno\":0,"
      "\"message\":\"child_process is not available in Android app sandboxes\","
      "\"platform\":\"android\"}";
  const char* spawnUnavailableJson =
      "{\"error\":\"child_process is not available in Android app sandboxes\","
      "\"code\":\"ERR_FEATURE_UNAVAILABLE_ON_PLATFORM\",\"errno\":0,"
      "\"message\":\"child_process is not available in Android app sandboxes\","
      "\"platform\":\"android\"}";

  auto installUnsupportedJsonFn = [&rt](const char* name, const char* json) {
    auto fn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, name),
        3,
        [json](facebook::jsi::Runtime& runtime,
               const facebook::jsi::Value&,
               const facebook::jsi::Value*,
               size_t) -> facebook::jsi::Value {
          // @ref LLP 0013#phase-0 — the canonical capability is `process:spawn`
          // (capability_bits.rs bit 9). The old `child_process` string was not
          // in the manifest, so this check could never match a policy grant.
          if (!checkCapability("process:spawn")) {
            throw facebook::jsi::JSError(
                runtime,
                "Permission denied: process:spawn capability required");
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        });
    rt.global().setProperty(rt, name, std::move(fn));
  };

  // @ref LLP 0008#android-backend-matrix — Android app sandboxes do not offer
  // desktop Node child_process semantics, so fail explicitly instead of
  // attempting POSIX fork/exec/popen in app code.
  installUnsupportedJsonFn("__exactExecSync", spawnSyncUnavailableJson);
  installUnsupportedJsonFn("__exactSpawnSync", spawnSyncUnavailableJson);
  installUnsupportedJsonFn("__exactSpawn", spawnUnavailableJson);

  auto emptyReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::String::createFromUtf8(runtime, "");
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(emptyReadFn));

  auto falseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(falseFn));

  auto killFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(killFn));

  auto closeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(closeFn));

  auto pollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [unavailableMessage](facebook::jsi::Runtime& runtime,
                           const facebook::jsi::Value&,
                           const facebook::jsi::Value*,
                           size_t) -> facebook::jsi::Value {
        std::string json =
            std::string("{\"exited\":true,\"status\":null,\"signal\":null,\"error\":\"")
            + unavailableMessage + "\"}";
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, json));
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(pollFn));

  auto getFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactSpawnGetFd", std::move(getFdFn));

  auto sendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSendMsg"),
      3,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        // -1 (hard failure), not 0/false: 0 means EAGAIN to the JS send queue
        // (ENG-23231), which would retry forever on platforms without spawn.
        return facebook::jsi::Value(-1);
      });
  rt.global().setProperty(rt, "__exactSpawnSendMsg", std::move(sendMsgFn));

  auto recvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRecvMsg"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, "{\"messages\":[]}"));
      });
  rt.global().setProperty(rt, "__exactSpawnRecvMsg", std::move(recvMsgFn));
  return;
#endif

  // __exactExecSync(command, optionsJSON) -> JSON string { stdout, stderr, status, error }
  // Executes a shell command synchronously using popen and returns result.
  auto execSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactExecSync"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactExecSync: command string required");
        }
        auto command = args[0].toString(runtime).utf8(runtime);

        // Parse options
        std::string cwd;
        uint32_t timeout_ms = 0;
        uint32_t max_buffer = 1024 * 1024; // 1MB default

        if (count > 1 && args[1].isString()) {
          auto optsJson = args[1].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          auto timeoutPos = optsJson.find("\"timeout\":");
          if (timeoutPos != std::string::npos) {
            auto start = timeoutPos + 10;
            timeout_ms = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
          auto maxBufPos = optsJson.find("\"maxBuffer\":");
          if (maxBufPos != std::string::npos) {
            auto start = maxBufPos + 12;
            max_buffer = static_cast<uint32_t>(std::stoul(optsJson.substr(start)));
          }
        }

        // Redirect stderr to a temp file so we can capture it separately
        char stderrTmpPath[] = "/tmp/ex_stderr_XXXXXX";
        int stderrFd = mkstemp(stderrTmpPath);
        if (stderrFd < 0) {
          throw facebook::jsi::JSError(runtime, "Failed to create temp file for stderr");
        }
        int stdoutPipe[2] = {-1, -1};
        if (pipe(stdoutPipe) != 0) {
          close(stderrFd);
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to create stdout pipe");
        }

        // ENG-23113 — cancellable, self-joining timeout watchdog (see
        // SyncTimeoutWatchdog): the previous detached thread wrote a stack
        // `timedOut` that had been freed once a fast command returned.
        SyncTimeoutWatchdog watchdog;

        pid_t pid = fork();
        if (pid < 0) {
          close(stderrFd);
          close(stdoutPipe[0]);
          close(stdoutPipe[1]);
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to execute command");
        }
        if (pid == 0) {
          close(stdoutPipe[0]);
          dup2(stdoutPipe[1], STDOUT_FILENO);
          close(stdoutPipe[1]);
          dup2(stderrFd, STDERR_FILENO);
          close(stderrFd);
          if (!cwd.empty() && chdir(cwd.c_str()) != 0) {
            _exit(127);
          }
          execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
          _exit(127);
        }

        close(stderrFd);
        close(stdoutPipe[1]);

        // Start timeout thread if needed
        if (timeout_ms > 0) {
          watchdog.worker = std::thread([&watchdog, timeout_ms]() {
            std::unique_lock<std::mutex> lk(watchdog.mtx);
            if (!watchdog.cv.wait_for(
                    lk, std::chrono::milliseconds(timeout_ms),
                    [&] { return watchdog.finished; })) {
              watchdog.timedOut.store(true);
            }
          });
        }

        // Read stdout
        std::string stdoutStr;
        char buf[4096];
        bool stdoutOpen = true;
        bool childReaped = false;
        int childStatus = 0;
        while (stdoutOpen || !childReaped) {
          if (watchdog.timedOut.load() && !childReaped) {
            kill(pid, SIGKILL);
          }
          if (stdoutOpen) {
            struct pollfd pfd;
            pfd.fd = stdoutPipe[0];
            pfd.events = POLLIN | POLLHUP | POLLERR;
            pfd.revents = 0;
            int pollResult = poll(&pfd, 1, 20);
            if (pollResult > 0 && (pfd.revents & (POLLIN | POLLHUP | POLLERR))) {
              ssize_t bytesRead = read(stdoutPipe[0], buf, sizeof(buf));
              if (bytesRead < 0) {
                if (errno != EINTR) {
                  stdoutOpen = false;
                }
              } else if (bytesRead == 0) {
                stdoutOpen = false;
              } else if (stdoutStr.size() < max_buffer) {
                size_t remaining = max_buffer - stdoutStr.size();
                size_t toAppend = std::min(static_cast<size_t>(bytesRead), remaining);
                stdoutStr.append(buf, toAppend);
              }
            } else if (pollResult < 0 && errno != EINTR) {
              stdoutOpen = false;
            }
          }
          if (!childReaped) {
            pid_t waited = waitpid(pid, &childStatus, WNOHANG);
            if (waited == pid) {
              childReaped = true;
            } else if (waited < 0 && errno != EINTR) {
              childReaped = true;
            }
          }
        }
        close(stdoutPipe[0]);

        int exitStatus = WIFEXITED(childStatus) ? WEXITSTATUS(childStatus) : -1;

        // Command finished: cancel + join the watchdog before this frame can
        // return (or throw building the result), so it can never wake late and
        // write freed memory. ENG-23113
        watchdog.cancelAndJoin();

        // Read stderr from temp file
        std::string stderrStr;
        FILE* stderrFile = fopen(stderrTmpPath, "r");
        if (stderrFile) {
          while (true) {
            size_t bytesRead = fread(buf, 1, sizeof(buf), stderrFile);
            if (bytesRead == 0) break;
            stderrStr.append(buf, bytesRead);
          }
          fclose(stderrFile);
        }
        unlink(stderrTmpPath);

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        std::string errorStr = "";
        if (watchdog.timedOut.load()) {
          errorStr = "Command timed out";
          exitStatus = -1;
        }

        std::string resultJson = "{\"stdout\":\"" + jsonEscape(stdoutStr)
            + "\",\"stderr\":\"" + jsonEscape(stderrStr)
            + "\",\"status\":" + std::to_string(exitStatus);
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactExecSync", std::move(execSyncFn));

  // Env helpers defined as static functions above (s_parseEnvJsonStr, s_parseEnvFromOpts)

  // __exactSpawnSync(file, argsJSON, optionsJSON) -> JSON string { stdout, stderr, status, pid, error }
  // Spawns a process synchronously using fork/exec and returns result.
  auto spawnSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSync"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawnSync: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        std::string shellPath; // (ENG-23032) custom shell binary; empty -> /bin/sh
        uint32_t timeout_ms = 0;
        // (ENG-23008) maxBuffer is now enforced here (byte-counted, child killed
        // on exceed) instead of post-hoc in JS. Default matches Node (1MB); a
        // value of 0 means unlimited (JS maps Infinity -> 0). kill_signal is the
        // numeric signal to send when the limit is exceeded (Node killSignal,
        // default SIGTERM=15).
        size_t max_buffer = 1024 * 1024;
        bool max_buffer_unlimited = false;
        int kill_signal = 15;
        std::vector<std::string> envEntries;
        std::string stdinInput;
        bool hasStdinInput = false;
        bool inputIsBase64 = false;
        std::string argv0;
        // (ENG-23025) Per-fd stdio modes. Default: capture stdout/stderr, leave
        // stdin inherited (or fed from `input`). Set together by the string form
        // ("pipe"/"inherit"/"ignore") and per-index by the array form.
        std::string stdinMode = "pipe";
        std::string stdoutMode = "pipe";
        std::string stderrMode = "pipe";
        // (ENG-23485) options.uid/options.gid for the child; -1 = not set.
        long spawnUid = -1;
        long spawnGid = -1;

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          if (optsJson.find("\"shell\":true") != std::string::npos) {
            useShell = true;
          }
          auto shellPos = optsJson.find("\"shell\":\"");
          if (shellPos != std::string::npos) {
            useShell = true;
            // (ENG-23032) Extract the requested shell binary instead of always
            // exec'ing /bin/sh. A path never contains a JSON quote, so scan to
            // the next '"' (same shape as the cwd parse above).
            auto sstart = shellPos + 9;
            auto send = optsJson.find("\"", sstart);
            if (send != std::string::npos) {
              shellPath = optsJson.substr(sstart, send - sstart);
            }
          }
          auto timeoutPos = optsJson.find("\"timeout\":");
          if (timeoutPos != std::string::npos) {
            auto start = timeoutPos + 10;
            timeout_ms = static_cast<uint32_t>(std::strtoul(optsJson.c_str() + start, nullptr, 10));
          }
          auto maxBufPos = optsJson.find("\"maxBuffer\":");
          if (maxBufPos != std::string::npos) {
            auto start = maxBufPos + 12;
            // strtoull (not stoul) so a non-digit (e.g. JSON null) never throws.
            unsigned long long parsed = std::strtoull(optsJson.c_str() + start, nullptr, 10);
            if (parsed == 0ULL) {
              max_buffer_unlimited = true;
            } else {
              max_buffer = static_cast<size_t>(parsed);
            }
          }
          auto killSigPos = optsJson.find("\"killSignal\":");
          if (killSigPos != std::string::npos) {
            auto start = killSigPos + 13;
            int parsedSig = static_cast<int>(std::strtol(optsJson.c_str() + start, nullptr, 10));
            if (parsedSig > 0) kill_signal = parsedSig;
          }
          s_parseSpawnCredentials(optsJson, spawnUid, spawnGid);
          envEntries = s_parseEnvFromOpts(optsJson);
          // Parse stdio: string form ("inherit"/"pipe"/"ignore") sets all three
          // fds; (ENG-23025) array form ["ignore","inherit","inherit"] sets them
          // per-index. JS serializes mixed modes as a JSON array, but this path
          // previously parsed only the string form and silently left the default
          // "pipe" — so an array-form stdio was ignored (stdout/stderr captured
          // instead of reaching the terminal; stdin left inherited).
          auto strPos = optsJson.find("\"stdio\":\"");
          if (strPos != std::string::npos) {
            auto start = strPos + 9;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              std::string mode = optsJson.substr(start, end - start);
              stdinMode = mode;
              stdoutMode = mode;
              stderrMode = mode;
            }
          } else {
            auto arrPos = optsJson.find("\"stdio\":[");
            if (arrPos != std::string::npos) {
              size_t pos = arrPos + 9;
              std::string* slots[3] = {&stdinMode, &stdoutMode, &stderrMode};
              int slot = 0;
              while (pos < optsJson.size() && optsJson[pos] != ']') {
                while (pos < optsJson.size() &&
                       (optsJson[pos] == ' ' || optsJson[pos] == ',')) pos++;
                if (pos >= optsJson.size() || optsJson[pos] == ']') break;
                if (optsJson[pos] == '"') {
                  pos++;
                  std::string val;
                  while (pos < optsJson.size() && optsJson[pos] != '"') {
                    val += optsJson[pos++];
                  }
                  if (pos < optsJson.size()) pos++; // closing quote
                  if (slot < 3) *slots[slot] = val;
                } else {
                  // non-string entry (number fd / null): skip, keep default
                  while (pos < optsJson.size() && optsJson[pos] != ',' &&
                         optsJson[pos] != ']') pos++;
                }
                slot++;
              }
            }
          }
          // Parse input option for stdin
          auto inputPos = optsJson.find("\"input\":\"");
          if (inputPos != std::string::npos) {
            auto start = inputPos + 9;
            std::string inputStr;
            while (start < optsJson.size() && optsJson[start] != '"') {
              if (optsJson[start] == '\\' && start + 1 < optsJson.size()) {
                start++;
                if (optsJson[start] == 'n') inputStr += '\n';
                else if (optsJson[start] == 't') inputStr += '\t';
                else if (optsJson[start] == 'r') inputStr += '\r';
                else inputStr += optsJson[start];
              } else {
                inputStr += optsJson[start];
              }
              start++;
            }
            stdinInput = inputStr;
            hasStdinInput = true;
          }
          // (ENG-23009) When JS marks the stdin payload as base64 the raw bytes
          // were preserved across the JSON boundary; decode below before writing.
          if (optsJson.find("\"inputEncoding\":\"base64\"") != std::string::npos) {
            inputIsBase64 = true;
          }
          // Parse argv0 option for custom process.argv[0]
          auto argv0Pos = optsJson.find("\"argv0\":\"");
          if (argv0Pos != std::string::npos) {
            auto start = argv0Pos + 9;
            std::string argv0Str;
            while (start < optsJson.size() && optsJson[start] != '"') {
              if (optsJson[start] == '\\' && start + 1 < optsJson.size()) {
                start++;
                if (optsJson[start] == 'n') argv0Str += '\n';
                else if (optsJson[start] == 't') argv0Str += '\t';
                else if (optsJson[start] == 'r') argv0Str += '\r';
                else argv0Str += optsJson[start];
              } else {
                argv0Str += optsJson[start];
              }
              start++;
            }
            argv0 = argv0Str;
          }
        }

        const bool syncStdoutPipe = (stdoutMode == "pipe");
        const bool syncStderrPipe = (stderrMode == "pipe");
        const bool syncStdoutIgnore = (stdoutMode == "ignore");
        const bool syncStderrIgnore = (stderrMode == "ignore");
        // stdin is fed from `input` when present (pipe); otherwise "ignore" ->
        // /dev/null and anything else -> inherit the parent's stdin.
        const bool syncStdinIgnore = (stdinMode == "ignore");

        // (ENG-23485) fd:N stdio entries (Node numeric stdio semantics:
        // "share this parent fd with the child"), dup2'd in the child below.
        // The trusted JS layer resolves fd:N-equals-slot to 'inherit' before
        // it reaches this bridge (Node's stdio:[0,1,2]), so every fd:N seen
        // here is a genuinely foreign fd and must pass the capability layer —
        // raw fd integers are forgeable
        // (@ref LLP 0013#policy — same rule as the async spawn redirects).
        auto parseSyncFdMode = [](const std::string& mode) -> int {
          if (mode.size() > 3 && mode.compare(0, 3, "fd:") == 0) {
            return std::atoi(mode.c_str() + 3);
          }
          return -1;
        };
        int syncStdinFdRedirect = parseSyncFdMode(stdinMode);
        int syncStdoutFdRedirect = parseSyncFdMode(stdoutMode);
        int syncStderrFdRedirect = parseSyncFdMode(stderrMode);
        if (!isAllowAll()) {
          if (syncStdinFdRedirect >= 0) {
            exactRequireFdReadable(runtime, syncStdinFdRedirect, "__exactSpawnSync stdio[0]");
          }
          if (syncStdoutFdRedirect >= 0) {
            exactRequireFdWritable(runtime, syncStdoutFdRedirect, "__exactSpawnSync stdio[1]");
          }
          if (syncStderrFdRedirect >= 0) {
            exactRequireFdWritable(runtime, syncStderrFdRedirect, "__exactSpawnSync stdio[2]");
          }
        }

        // JSON escape helper
        auto jsonEscape = [](const std::string& s) -> std::string {
          std::string result;
          result.reserve(s.size() + 16);
          for (char c : s) {
            switch (c) {
              case '"': result += "\\\""; break;
              case '\\': result += "\\\\"; break;
              case '\n': result += "\\n"; break;
              case '\r': result += "\\r"; break;
              case '\t': result += "\\t"; break;
              case '\b': result += "\\b"; break;
              case '\f': result += "\\f"; break;
              default:
                if (static_cast<unsigned char>(c) < 0x20) {
                  char hex[8];
                  snprintf(hex, sizeof(hex), "\\u%04x", static_cast<unsigned char>(c));
                  result += hex;
                } else {
                  result += c;
                }
                break;
            }
          }
          return result;
        };

        // (ENG-23009) Base64 transport for binary stdout/stderr/stdin. JSON
        // strings must be valid UTF-8 for createFromUtf8, but child output is
        // arbitrary bytes; base64 (ASCII) is a byte-preserving, JSON-safe
        // channel that survives the native->JS boundary without corruption.
        auto base64Encode = [](const std::string& in) -> std::string {
          static const char* tbl =
              "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
          std::string out;
          out.reserve(((in.size() + 2) / 3) * 4);
          size_t i = 0;
          while (i + 2 < in.size()) {
            uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                         (static_cast<uint8_t>(in[i + 1]) << 8) |
                         static_cast<uint8_t>(in[i + 2]);
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back(tbl[(n >> 6) & 63]);
            out.push_back(tbl[n & 63]);
            i += 3;
          }
          size_t rem = in.size() - i;
          if (rem == 1) {
            uint32_t n = static_cast<uint8_t>(in[i]) << 16;
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back('=');
            out.push_back('=');
          } else if (rem == 2) {
            uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                         (static_cast<uint8_t>(in[i + 1]) << 8);
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back(tbl[(n >> 6) & 63]);
            out.push_back('=');
          }
          return out;
        };
        auto base64Decode = [](const std::string& in) -> std::string {
          auto dec = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
          };
          std::string out;
          out.reserve((in.size() / 4) * 3);
          int buffer = 0;
          int bits = 0;
          for (char c : in) {
            if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
            int v = dec(c);
            if (v < 0) continue;
            buffer = (buffer << 6) | v;
            bits += 6;
            if (bits >= 8) {
              bits -= 8;
              out.push_back(static_cast<char>((buffer >> bits) & 0xff));
            }
          }
          return out;
        };
        if (inputIsBase64 && hasStdinInput) {
          stdinInput = base64Decode(stdinInput);
        }

        // Create pipes for stdout, stderr, and optionally stdin
        int stdoutPipe[2] = {-1, -1}, stderrPipe[2] = {-1, -1}, stdinPipe[2] = {-1, -1};
        if (syncStdoutPipe) {
          if (pipe(stdoutPipe) != 0) {
            throw facebook::jsi::JSError(runtime, "Failed to create stdout pipe");
          }
        }
        if (syncStderrPipe) {
          if (pipe(stderrPipe) != 0) {
            if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            throw facebook::jsi::JSError(runtime, "Failed to create stderr pipe");
          }
        }
        if (hasStdinInput) {
          if (pipe(stdinPipe) != 0) {
            if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
            throw facebook::jsi::JSError(runtime, "Failed to create stdin pipe");
          }
        }
        int execErrPipe[2] = {-1, -1};
        if (pipe(execErrPipe) != 0) {
          if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
          if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
          if (hasStdinInput) { close(stdinPipe[0]); close(stdinPipe[1]); }
          throw facebook::jsi::JSError(runtime, "Failed to create exec error pipe");
        }
        fcntl(execErrPipe[1], F_SETFD, FD_CLOEXEC);

        pid_t pid = fork();
        if (pid < 0) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdoutPipe[0] >= 0) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
          if (stderrPipe[0] >= 0) { close(stderrPipe[0]); close(stderrPipe[1]); }
          if (hasStdinInput) { close(stdinPipe[0]); close(stdinPipe[1]); }
          throw facebook::jsi::JSError(runtime, "Failed to fork process");
        }

        if (pid == 0) {
          // Child process
          close(execErrPipe[0]);
          if (syncStdoutPipe) {
            close(stdoutPipe[0]);
            dup2(stdoutPipe[1], STDOUT_FILENO);
            close(stdoutPipe[1]);
          } else if (syncStdoutFdRedirect >= 0) {
            dup2(syncStdoutFdRedirect, STDOUT_FILENO);
          } else if (syncStdoutIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) { dup2(nullFd, STDOUT_FILENO); close(nullFd); }
          }
          // else inherit: do nothing, keep parent's stdout

          if (syncStderrPipe) {
            close(stderrPipe[0]);
            dup2(stderrPipe[1], STDERR_FILENO);
            close(stderrPipe[1]);
          } else if (syncStderrFdRedirect >= 0) {
            dup2(syncStderrFdRedirect, STDERR_FILENO);
          } else if (syncStderrIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) { dup2(nullFd, STDERR_FILENO); close(nullFd); }
          }
          // else inherit: do nothing, keep parent's stderr

          if (hasStdinInput) {
            close(stdinPipe[1]);
            dup2(stdinPipe[0], STDIN_FILENO);
            close(stdinPipe[0]);
          } else if (syncStdinFdRedirect >= 0) {
            dup2(syncStdinFdRedirect, STDIN_FILENO);
          } else if (syncStdinIgnore) {
            int nullFd = open("/dev/null", O_RDONLY);
            if (nullFd >= 0) { dup2(nullFd, STDIN_FILENO); close(nullFd); }
          }

          // Suppress runtime bundle note in child processes
          setenv("EXACT_QUIET", "1", 1);

          // Build envp array (must outlive execvp call)
          std::vector<char*> envp;
          if (!envEntries.empty()) {
            // Ensure EXACT_QUIET is included in custom env
            envEntries.push_back("EXACT_QUIET=1");
            envp.reserve(envEntries.size() + 1);
            for (auto& e : envEntries) {
              envp.push_back(const_cast<char*>(e.c_str()));
            }
            envp.push_back(nullptr);
#if defined(__APPLE__)
            *_NSGetEnviron() = envp.data();
#else
            environ = envp.data();
#endif
          }

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              int chdirErrno = errno;
              ssize_t nw = write(execErrPipe[1], &chdirErrno, sizeof(chdirErrno));
              (void)nw;
              _exit(127);
            }
          }

          // (ENG-23485) Apply options.gid/options.uid (gid first) between fork
          // and exec; failure reports through the exec error pipe so JS
          // surfaces spawn EPERM instead of silently keeping parent credentials.
          {
            int credErrno = s_applySpawnCredentials(spawnGid, spawnUid);
            if (credErrno != 0) {
              ssize_t nw = write(execErrPipe[1], &credErrno, sizeof(credErrno));
              (void)nw;
              _exit(127);
            }
          }

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            // (ENG-23032) Honor a custom `shell` binary; fall back to /bin/sh.
            const char* shBin = shellPath.empty() ? "/bin/sh" : shellPath.c_str();
            execl(shBin, shBin, "-c", fullCmd.c_str(), nullptr);
          } else {
            std::vector<char*> argv;
            // Use custom argv0 if provided, otherwise use file as argv[0]
            std::string argv0Str = argv0.empty() ? file : argv0;
            argv.push_back(const_cast<char*>(argv0Str.c_str()));
            for (auto& a : spawnArgs) {
              argv.push_back(const_cast<char*>(a.c_str()));
            }
            argv.push_back(nullptr);
            execvp(file.c_str(), argv.data());
          }
          {
            int execErrno = errno;
            ssize_t nw = write(execErrPipe[1], &execErrno, sizeof(execErrno));
            (void)nw;
          }
          _exit(127);
        }

        // Parent process
        close(execErrPipe[1]);
        {
          int childErrno = 0;
          ssize_t n = read(execErrPipe[0], &childErrno, sizeof(childErrno));
          close(execErrPipe[0]);
          if (n > 0) {
            // (ENG-23023) On exec failure close BOTH ends of the stdout/stderr
            // pipes. The success path closes the write ends at :799-800, but this
            // early-return branch previously closed only the read ends, leaking
            // stdoutPipe[1]/stderrPipe[1] on every failed spawnSync (e.g. ENOENT).
            if (syncStdoutPipe) { close(stdoutPipe[0]); close(stdoutPipe[1]); }
            if (syncStderrPipe) { close(stderrPipe[0]); close(stderrPipe[1]); }
            if (hasStdinInput) {
              close(stdinPipe[0]);
              close(stdinPipe[1]);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            std::string errorStr = "Command not found: " + file;
            if (childErrno == EACCES || childErrno == EPERM) {
              errorStr = "Permission denied: " + file;
            } else if (childErrno != ENOENT) {
              errorStr = std::string("exec failed: ") + std::strerror(childErrno);
            }
            // (ENG-23485) Precise code so JS reports EPERM for setuid/setgid
            // failures (previously "Permission denied" was remapped to EACCES).
            std::string errCode;
            if (childErrno == EPERM) errCode = "EPERM";
            else if (childErrno == EACCES) errCode = "EACCES";
            else if (childErrno == ENOENT) errCode = "ENOENT";
            std::string codeField;
            if (!errCode.empty()) {
              codeField = ",\"code\":\"" + errCode + "\",\"errno\":"
                  + std::to_string(-childErrno);
            }
            std::string resultJson = "{\"stdout\":\"\",\"stderr\":\"\",\"stdioEncoding\":\"base64\",\"status\":127,\"pid\":"
                + std::to_string(static_cast<int>(pid))
                + ",\"error\":\"" + jsonEscape(errorStr) + "\"" + codeField + "}";
            return facebook::jsi::Value(
                facebook::jsi::String::createFromUtf8(runtime, resultJson));
          }
        }
        if (syncStdoutPipe) close(stdoutPipe[1]);
        if (syncStderrPipe) close(stderrPipe[1]);

        std::string stdoutStr, stderrStr;
        char buf[4096];
        // ENG-23113 — cancellable, self-joining timeout watchdog (see
        // SyncTimeoutWatchdog). The worker fires SIGKILL only while the child is
        // still alive; once the child is reaped the main path cancels + joins it,
        // so it can never wake after this frame returns and SIGKILL a recycled PID
        // (or read/write the freed stack `childExited`/`timedOut`).
        SyncTimeoutWatchdog watchdog;

        if (timeout_ms > 0) {
          watchdog.worker = std::thread([&watchdog, timeout_ms, pid]() {
            std::unique_lock<std::mutex> lk(watchdog.mtx);
            if (!watchdog.cv.wait_for(
                    lk, std::chrono::milliseconds(timeout_ms),
                    [&] { return watchdog.finished; })) {
              // Not cancelled -> a real timeout. The childExited guard closes the
              // window where the child was reaped between wait_for waking and this
              // check: no reap has happened yet unless childExited is set, so pid
              // is not recycled.
              if (!watchdog.childExited.load() && kill(pid, SIGKILL) == 0) {
                watchdog.timedOut.store(true);
              }
            }
          });
        }

        // (ENG-23008) Enforce maxBuffer by BYTES on each stream. When cumulative
        // bytes exceed the limit, truncate the captured output to maxBuffer and
        // KILL the child with killSignal (matching Node), instead of buffering up
        // to 256MB and never terminating the child.
        bool maxBufferExceeded = false;

        // (ENG-23025) Multiplex stdin-write / stdout-read / stderr-read with
        // poll() on non-blocking fds. The previous path wrote all of stdin, then
        // drained stdout to EOF, then stderr to EOF, each with fully-blocking
        // I/O. A child that filled the ~64KB kernel buffer of a pipe the parent
        // was not currently draining (e.g. >64KB to stderr while the parent
        // blocked in the stdout read loop, or >64KB of stdin while the child
        // blocked writing stdout the parent hadn't begun reading) deadlocked
        // forever — there is no default timeout and typical output is under the
        // 1MB maxBuffer, so neither guard fired. Node/libuv multiplex; so do we.
        int stdinWriteFd = -1;
        const char* stdinData = nullptr;
        size_t stdinRemaining = 0;
        if (hasStdinInput) {
          close(stdinPipe[0]); // parent only writes to the child's stdin
          stdinWriteFd = stdinPipe[1];
          stdinData = stdinInput.data();
          stdinRemaining = stdinInput.size();
          int flags = fcntl(stdinWriteFd, F_GETFL, 0);
          if (flags >= 0) fcntl(stdinWriteFd, F_SETFL, flags | O_NONBLOCK);
          if (stdinRemaining == 0) {
            close(stdinWriteFd);
            stdinWriteFd = -1;
          }
        }
        int stdoutReadFd = syncStdoutPipe ? stdoutPipe[0] : -1;
        int stderrReadFd = syncStderrPipe ? stderrPipe[0] : -1;
        if (stdoutReadFd >= 0) {
          int f = fcntl(stdoutReadFd, F_GETFL, 0);
          if (f >= 0) fcntl(stdoutReadFd, F_SETFL, f | O_NONBLOCK);
        }
        if (stderrReadFd >= 0) {
          int f = fcntl(stderrReadFd, F_GETFL, 0);
          if (f >= 0) fcntl(stderrReadFd, F_SETFL, f | O_NONBLOCK);
        }

        // Append bytes to a capture buffer enforcing maxBuffer; returns false
        // when the stream hit the limit and should stop being read.
        auto appendCapped = [&](std::string& dst, const char* data, size_t len) -> bool {
          if (max_buffer_unlimited) {
            dst.append(data, len);
            return true;
          }
          if (dst.size() + len > max_buffer) {
            size_t room = max_buffer > dst.size() ? max_buffer - dst.size() : 0;
            dst.append(data, room);
            maxBufferExceeded = true;
            if (!watchdog.childExited.load()) kill(pid, kill_signal);
            return false;
          }
          dst.append(data, len);
          return true;
        };

        // Drain a readable fd until EAGAIN/EOF. On EOF or a hard error, closes
        // the fd and sets *fdSlot to -1 so it drops out of the poll set.
        auto drainReadable = [&](int* fdSlot, std::string& dst) {
          int fd = *fdSlot;
          while (true) {
            ssize_t br = read(fd, buf, sizeof(buf));
            if (br > 0) {
              if (!appendCapped(dst, buf, static_cast<size_t>(br))) {
                close(fd);
                *fdSlot = -1;
                return;
              }
            } else if (br == 0) {
              close(fd); // EOF
              *fdSlot = -1;
              return;
            } else {
              if (errno == EAGAIN || errno == EWOULDBLOCK) return; // drained
              if (errno == EINTR) continue;
              close(fd);
              *fdSlot = -1;
              return;
            }
          }
        };

        while (stdinWriteFd >= 0 || stdoutReadFd >= 0 || stderrReadFd >= 0) {
          struct pollfd pfds[3];
          int idxStdin = -1, idxStdout = -1, idxStderr = -1;
          nfds_t nfds = 0;
          if (stdinWriteFd >= 0) {
            pfds[nfds].fd = stdinWriteFd;
            pfds[nfds].events = POLLOUT;
            pfds[nfds].revents = 0;
            idxStdin = static_cast<int>(nfds++);
          }
          if (stdoutReadFd >= 0) {
            pfds[nfds].fd = stdoutReadFd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            idxStdout = static_cast<int>(nfds++);
          }
          if (stderrReadFd >= 0) {
            pfds[nfds].fd = stderrReadFd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            idxStderr = static_cast<int>(nfds++);
          }

          // 100ms tick so the watchdog thread's SIGKILL (timeout_ms) is observed
          // even when every fd is quiet; on timeout the child's write ends close
          // and the reads below see EOF, ending the loop.
          int pr = poll(pfds, nfds, 100);
          if (pr < 0) {
            if (errno == EINTR) continue;
            break; // unexpected poll failure: stop draining
          }
          if (pr == 0) {
            continue; // tick with no readiness
          }

          if (idxStdin >= 0) {
            short re = pfds[idxStdin].revents;
            if (re & (POLLERR | POLLHUP | POLLNVAL)) {
              // Reader is gone (child closed stdin or exited); stop writing.
              close(stdinWriteFd);
              stdinWriteFd = -1;
            } else if (re & POLLOUT) {
              ssize_t w = write(stdinWriteFd, stdinData, stdinRemaining);
              if (w > 0) {
                stdinData += w;
                stdinRemaining -= static_cast<size_t>(w);
                if (stdinRemaining == 0) {
                  close(stdinWriteFd);
                  stdinWriteFd = -1;
                }
              } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                         errno != EINTR) {
                close(stdinWriteFd);
                stdinWriteFd = -1;
              }
            }
          }
          if (idxStdout >= 0 && (pfds[idxStdout].revents &
                                 (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            drainReadable(&stdoutReadFd, stdoutStr);
          }
          if (idxStderr >= 0 && (pfds[idxStderr].revents &
                                 (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            drainReadable(&stderrReadFd, stderrStr);
          }
        }

        // Wait for child
        int status = 0;
        waitpid(pid, &status, 0);
        watchdog.childExited.store(true);
        // Child reaped: cancel + join the watchdog before this frame can return
        // (or throw building the result JSON), so it can never wake late and
        // SIGKILL a recycled PID. ENG-23113
        watchdog.cancelAndJoin();
        int exitStatus = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (WIFSIGNALED(status)) {
          exitStatus = -WTERMSIG(status);
        }

        std::string errorStr;
        if (watchdog.timedOut.load()) {
          errorStr = "Command timed out";
        } else if (exitStatus == 127) {
          errorStr = "Command not found: " + file;
        }

        // (ENG-23009) stdout/stderr are emitted base64 so binary output round-
        // trips exactly; JS decodes back to a Buffer.
        std::string resultJson = "{\"stdout\":\"" + base64Encode(stdoutStr)
            + "\",\"stderr\":\"" + base64Encode(stderrStr)
            + "\",\"stdioEncoding\":\"base64\",\"status\":" + std::to_string(exitStatus)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid))
            + ",\"maxBufferExceeded\":" + (maxBufferExceeded ? "true" : "false");
        if (!errorStr.empty()) {
          resultJson += ",\"error\":\"" + jsonEscape(errorStr) + "\"";
        }
        resultJson += "}";

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawnSync", std::move(spawnSyncFn));

  // --- Async spawn support ---
  // SpawnedProcess stores pipe fds and pid for async child processes.
  struct SpawnedProcess {
    uint64_t owner;
    std::string capability;
    pid_t pid;
    int stdinFd;   // parent writes to child's stdin
    int stdoutFd;  // parent reads from child's stdout
    int stderrFd;  // parent reads from child's stderr
    int ipcFd;     // IPC channel fd (optional)
    std::vector<int> extraFds; // parent-side fds for stdio indices 4+
    bool exited;
    int exitCode;
    int exitSignal; // 0 if exited normally, >0 if signaled
  };
  static std::unordered_map<int, SpawnedProcess> s_spawnedProcesses;
  static int s_nextSpawnHandle = 1;
  static std::mutex s_spawnMutex;

  auto requireSpawnHandle =
      [](facebook::jsi::Runtime& runtime, int handle, const char* syscall) {
        uint64_t owner = 0;
        std::string capability;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            throw facebook::jsi::JSError(runtime, std::string(syscall) + ": invalid handle");
          }
          owner = it->second.owner;
          capability = it->second.capability;
        }
        if (!isAllowAll()) {
          if (owner != currentPrincipalId()) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          if (!capability.empty() && !checkCapability(capability)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }
      };

  auto trySpawnHandle =
      [requireSpawnHandle](facebook::jsi::Runtime& runtime, int handle, const char* syscall) {
        try {
          requireSpawnHandle(runtime, handle, syscall);
          return true;
        } catch (const facebook::jsi::JSError&) {
          return false;
        }
      };

  // __exactSpawn(file, argsJSON, optionsJSON) -> JSON string {"handle":N,"pid":N} or {"error":"..."}
  auto spawnFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawn"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: process:spawn capability required");
        }
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSpawn: file path required");
        }
        auto file = args[0].toString(runtime).utf8(runtime);

        // Parse args array from JSON
        std::vector<std::string> spawnArgs;
        if (count > 1 && args[1].isString()) {
          auto argsJson = args[1].toString(runtime).utf8(runtime);
          if (argsJson.size() > 2 && argsJson[0] == '[') {
            size_t pos = 1;
            while (pos < argsJson.size()) {
              while (pos < argsJson.size() && (argsJson[pos] == ' ' || argsJson[pos] == ',' || argsJson[pos] == '\n')) pos++;
              if (pos >= argsJson.size() || argsJson[pos] == ']') break;
              if (argsJson[pos] == '"') {
                pos++;
                std::string arg;
                while (pos < argsJson.size() && argsJson[pos] != '"') {
                  if (argsJson[pos] == '\\' && pos + 1 < argsJson.size()) {
                    pos++;
                    if (argsJson[pos] == 'n') arg += '\n';
                    else if (argsJson[pos] == 't') arg += '\t';
                    else if (argsJson[pos] == 'r') arg += '\r';
                    else arg += argsJson[pos];
                  } else {
                    arg += argsJson[pos];
                  }
                  pos++;
                }
                if (pos < argsJson.size()) pos++;
                spawnArgs.push_back(arg);
              } else {
                while (pos < argsJson.size() && argsJson[pos] != ',' && argsJson[pos] != ']') pos++;
              }
            }
          }
        }

        // Parse options
        std::string cwd;
        bool useShell = false;
        std::string shellPath; // (ENG-23032) custom shell binary; empty -> /bin/sh
        bool detached = false; // (ENG-23032) start child in a new session/pgroup
        // (ENG-23485) options.uid/options.gid for the child; -1 = not set.
        long spawnUid = -1;
        long spawnGid = -1;
        std::vector<std::string> stdioModes = {"pipe", "pipe", "pipe", "pipe"};
        std::vector<std::string> envEntries;

        auto skipJsonWhitespace = [](const std::string& value, size_t& pos) {
          while (pos < value.size()) {
            char ch = value[pos];
            if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') break;
            pos++;
          }
        };

        auto parseJsonString = [](const std::string& value, size_t& pos) {
          std::string out;
          if (pos >= value.size() || value[pos] != '"') return out;
          ++pos;
          while (pos < value.size()) {
            char ch = value[pos++];
            if (ch == '\\' && pos < value.size()) {
              char escaped = value[pos++];
              if (escaped == 'n') out.push_back('\n');
              else if (escaped == 't') out.push_back('\t');
              else if (escaped == 'r') out.push_back('\r');
              else if (escaped == '"') out.push_back('"');
              else if (escaped == '\\') out.push_back('\\');
              else out.push_back(escaped);
              continue;
            }
            if (ch == '"') break;
            out.push_back(ch);
          }
          return out;
        };

        auto normalizeStdioMode = [](const std::string& value) {
          if (value == "ignore") return std::string("ignore");
          if (value == "inherit") return std::string("inherit");
          if (value == "pipe") return std::string("pipe");
          if (value == "overlapped") return std::string("pipe");
          if (value == "ipc") return std::string("ipc");
          // fd:N - redirect to existing file descriptor
          if (value.size() > 3 && value.substr(0, 3) == "fd:") return value;
          return std::string("pipe");
        };

        if (count > 2 && args[2].isString()) {
          auto optsJson = args[2].toString(runtime).utf8(runtime);
          auto cwdPos = optsJson.find("\"cwd\":\"");
          if (cwdPos != std::string::npos) {
            auto start = cwdPos + 7;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              cwd = optsJson.substr(start, end - start);
            }
          }
          if (optsJson.find("\"shell\":true") != std::string::npos) {
            useShell = true;
          }
          auto shellPos = optsJson.find("\"shell\":\"");
          if (shellPos != std::string::npos) {
            useShell = true;
            // (ENG-23032) Extract the requested shell binary; the async JS path
            // forwards options.shell verbatim, so honor a custom shell string
            // here instead of always exec'ing /bin/sh.
            auto sstart = shellPos + 9;
            auto send = optsJson.find("\"", sstart);
            if (send != std::string::npos) {
              shellPath = optsJson.substr(sstart, send - sstart);
            }
          }
          // (ENG-23032) `detached` was never parsed, so JS honored it only via
          // child.unref(): the child stayed in the parent's process group and
          // session, so process.kill(-pid) missed it and terminal SIGINT still
          // reached it. Plumb it through and setsid() in the child below.
          if (optsJson.find("\"detached\":true") != std::string::npos) {
            detached = true;
          }
          s_parseSpawnCredentials(optsJson, spawnUid, spawnGid);

          auto stdioPos = optsJson.find("\"stdio\":");
          if (stdioPos != std::string::npos) {
            size_t modePos = stdioPos + 8;
            skipJsonWhitespace(optsJson, modePos);
            if (modePos < optsJson.size()) {
              if (optsJson[modePos] == '"') {
                auto parsed = parseJsonString(optsJson, modePos);
                auto normalized = normalizeStdioMode(parsed);
                stdioModes[0] = normalized;
                stdioModes[1] = normalized;
                stdioModes[2] = normalized;
                stdioModes[3] = normalized;
              } else if (optsJson[modePos] == '[') {
                ++modePos;
                int slot = 0;
                while (modePos < optsJson.size()) {
                  skipJsonWhitespace(optsJson, modePos);
                  if (modePos >= optsJson.size() || optsJson[modePos] == ']') break;
                  std::string parsed;
                  if (optsJson[modePos] == '"') {
                    parsed = parseJsonString(optsJson, modePos);
                  } else {
                    if (optsJson.compare(modePos, 4, "null") == 0) {
                      modePos += 4;
                    } else {
                      while (modePos < optsJson.size() &&
                             optsJson[modePos] != ',' &&
                             optsJson[modePos] != ']') {
                        modePos++;
                      }
                    }
                  }
                  if (slot < (int)stdioModes.size()) {
                    stdioModes[slot] = normalizeStdioMode(parsed);
                  } else {
                    stdioModes.push_back(normalizeStdioMode(parsed));
                  }
                  slot++;
                  skipJsonWhitespace(optsJson, modePos);
                  if (modePos < optsJson.size() && optsJson[modePos] == ',') {
                    modePos++;
                  }
                }
              }
            }
          }
          envEntries = s_parseEnvFromOpts(optsJson);
        }

        const bool stdinPipeRequested = stdioModes[0] == "pipe";
        const bool stdoutPipeRequested = stdioModes[1] == "pipe";
        const bool stderrPipeRequested = stdioModes[2] == "pipe";
        const bool ipcRequested = stdioModes[3] == "ipc";

        // Parse fd:N modes for stdio redirection to existing file descriptors
        int stdinFdRedirect = -1, stdoutFdRedirect = -1, stderrFdRedirect = -1;
        auto parseFdMode = [](const std::string& mode) -> int {
          if (mode.substr(0, 3) == "fd:") {
            return std::atoi(mode.c_str() + 3);
          }
          return -1;
        };
        stdinFdRedirect = parseFdMode(stdioModes[0]);
        stdoutFdRedirect = parseFdMode(stdioModes[1]);
        stderrFdRedirect = parseFdMode(stdioModes[2]);
        // (ENG-23485) NOTE: the trusted JS layer resolves fd:N-equals-slot to
        // 'inherit' before it reaches this bridge (Node's stdio:[0,1,2]), so
        // every fd:N seen here is a genuinely foreign fd and is always
        // ownership-checked below (ENG-22906: spawn authority does not imply
        // raw fd authority).

        auto currentPrincipalOwnsSpawnFd = [](int fd, bool needsRead, bool needsWrite) {
          if (fd < 0) {
            return false;
          }
          auto principal = currentPrincipalId();
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          for (const auto& pair : s_spawnedProcesses) {
            const auto& proc = pair.second;
            if (!isAllowAll() && proc.owner != principal) {
              continue;
            }
            if (fd == proc.stdinFd) {
              if (needsRead) return false;
              if (needsWrite) return true;
            }
            if (fd == proc.stdoutFd || fd == proc.stderrFd) {
              if (needsWrite) return false;
              if (needsRead) return true;
            }
            if (fd == proc.ipcFd) {
              return true;
            }
            for (int extraFd : proc.extraFds) {
              if (fd == extraFd) {
                return true;
              }
            }
          }
          return false;
        };

        auto requireRedirectFd = [&](int fd, bool needsRead, bool needsWrite, const char* syscall) {
          if (fd < 0 || isAllowAll()) {
            return;
          }
          if (currentPrincipalOwnsSpawnFd(fd, needsRead, needsWrite)) {
            return;
          }
          try {
            if (needsRead) {
              exactRequireFdReadable(runtime, fd, syscall);
            }
            if (needsWrite) {
              exactRequireFdWritable(runtime, fd, syscall);
            }
          } catch (const facebook::jsi::JSError&) {
            throw facebook::jsi::JSError(
                runtime, std::string(syscall) + ": fd is not owned by this principal");
          }
        };

        // @ref LLP 0013#policy — raw fd integers are forgeable. Validate every
        // fd:N stdio redirect before fork so process:spawn cannot smuggle an
        // unowned host/internal descriptor into the child.
        requireRedirectFd(stdinFdRedirect, true, false, "__exactSpawn stdio[0]");
        requireRedirectFd(stdoutFdRedirect, false, true, "__exactSpawn stdio[1]");
        requireRedirectFd(stderrFdRedirect, false, true, "__exactSpawn stdio[2]");

        // Create pipes for stdin, stdout, stderr
        int stdinPipeFd[2] = {-1, -1};
        int stdoutPipeFd[2] = {-1, -1};
        int stderrPipeFd[2] = {-1, -1};
        int ipcPair[2] = {-1, -1};

        if (stdinPipeRequested && pipe(stdinPipeFd) != 0) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdin pipe\"}"));
        }
        if (stdoutPipeRequested && pipe(stdoutPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) {
            close(stdinPipeFd[0]);
          }
          if (stdinPipeFd[1] >= 0) {
            close(stdinPipeFd[1]);
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stdout pipe\"}"));
        }
        if (stderrPipeRequested && pipe(stderrPipeFd) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create stderr pipe\"}"));
        }
        if (ipcRequested && socketpair(AF_UNIX, SOCK_STREAM, 0, ipcPair) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create IPC socketpair\"}"));
        }

        // Set FD_CLOEXEC on parent-retained pipe fds so they don't leak
        // to subsequently spawned child processes.  Without this, piping
        // echo | grep | sed fails because sed inherits the write end of
        // grep's stdin pipe, preventing grep from seeing EOF.
        if (stdinPipeRequested && stdinPipeFd[1] >= 0)
          fcntl(stdinPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (stdoutPipeRequested && stdoutPipeFd[0] >= 0)
          fcntl(stdoutPipeFd[0], F_SETFD, FD_CLOEXEC);
        if (stderrPipeRequested && stderrPipeFd[0] >= 0)
          fcntl(stderrPipeFd[0], F_SETFD, FD_CLOEXEC);
        // ENG-23113 — the CHILD-side ends also need FD_CLOEXEC. This child
        // dup2's them onto STDIN/OUT/ERR and closes the originals before exec, so
        // CLOEXEC does not affect it; but without CLOEXEC a *concurrently* spawned
        // child (another fork racing between this fork and exec) inherits them and
        // they leak into it — the same leak the parent ends above guard against.
        if (stdinPipeRequested && stdinPipeFd[0] >= 0)
          fcntl(stdinPipeFd[0], F_SETFD, FD_CLOEXEC);
        if (stdoutPipeRequested && stdoutPipeFd[1] >= 0)
          fcntl(stdoutPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (stderrPipeRequested && stderrPipeFd[1] >= 0)
          fcntl(stderrPipeFd[1], F_SETFD, FD_CLOEXEC);
        if (ipcRequested) {
          if (ipcPair[0] >= 0) fcntl(ipcPair[0], F_SETFD, FD_CLOEXEC);
          if (ipcPair[1] >= 0) fcntl(ipcPair[1], F_SETFD, FD_CLOEXEC);
        }

        // Create pipes for extra stdio entries (index 4+)
        std::vector<std::pair<int,int>> extraPipes; // (parentFd, childFd) pairs
        for (size_t i = 4; i < stdioModes.size(); i++) {
          if (stdioModes[i] == "pipe") {
            int ep[2] = {-1, -1};
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, ep) != 0) {
              // Clean up on failure
              for (auto& p : extraPipes) { close(p.first); close(p.second); }
              if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
              if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
              if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
              if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
              if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
              if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
              if (ipcPair[0] >= 0) close(ipcPair[0]);
              if (ipcPair[1] >= 0) close(ipcPair[1]);
              return facebook::jsi::Value(
                  facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create extra stdio pipe\"}"));
            }
            fcntl(ep[0], F_SETFD, FD_CLOEXEC);
            // ENG-23113 — CLOEXEC the child end too (this child dup2's + closes
            // it before exec; keeps it from leaking into a concurrently spawned child).
            fcntl(ep[1], F_SETFD, FD_CLOEXEC);
            extraPipes.push_back({ep[0], ep[1]});
          } else {
            extraPipes.push_back({-1, -1});
          }
        }

        // Create an exec error pipe to detect ENOENT and other exec failures.
        // The write end has CLOEXEC so it auto-closes on successful exec.
        // If exec fails, the child writes errno to this pipe before _exit.
        int execErrPipe[2] = {-1, -1};
        if (pipe(execErrPipe) != 0) {
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          if (ipcPair[0] >= 0) close(ipcPair[0]);
          if (ipcPair[1] >= 0) close(ipcPair[1]);
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to create exec error pipe\"}"));
        }
        fcntl(execErrPipe[1], F_SETFD, FD_CLOEXEC);

        pid_t pid = fork();
        if (pid < 0) {
          close(execErrPipe[0]);
          close(execErrPipe[1]);
          if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
          if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
          if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
          if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          // ENG-23113 — no SpawnedProcess is stored on failure, so close every
          // fd the parent still holds. Previously ipcPair and extraPipes leaked here.
          if (ipcPair[0] >= 0) close(ipcPair[0]);
          if (ipcPair[1] >= 0) close(ipcPair[1]);
          for (auto& p : extraPipes) {
            if (p.first >= 0) close(p.first);
            if (p.second >= 0) close(p.second);
          }
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to fork process\"}"));
        }

        if (pid == 0) {
          // Child process
          close(execErrPipe[0]); // close read end in child
          // (ENG-23032) When detached, start a new session so the child becomes
          // the leader of its own process group (pgid == pid). This makes
          // process.kill(-pid) target the child's group and detaches it from the
          // controlling terminal's signal delivery (Node's detached behavior).
          // A freshly forked child is never already a group leader, so setsid()
          // succeeds; guard with setpgid as a defensive fallback.
          if (detached) {
            if (setsid() < 0) {
              setpgid(0, 0);
            }
          }
          if (stdinPipeRequested) {
            close(stdinPipeFd[1]);
            dup2(stdinPipeFd[0], STDIN_FILENO);
            close(stdinPipeFd[0]);
          } else if (stdinFdRedirect >= 0) {
            dup2(stdinFdRedirect, STDIN_FILENO);
            int stdinFlags = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (stdinFlags >= 0 && (stdinFlags & O_NONBLOCK)) {
              fcntl(STDIN_FILENO, F_SETFL, stdinFlags & ~O_NONBLOCK);
            }
          } else if (stdioModes[0] == "ignore") {
            int nullStdin = open("/dev/null", O_RDONLY);
            if (nullStdin >= 0) {
              dup2(nullStdin, STDIN_FILENO);
              close(nullStdin);
            }
          }

          if (stdoutPipeRequested) {
            close(stdoutPipeFd[0]);
            dup2(stdoutPipeFd[1], STDOUT_FILENO);
            close(stdoutPipeFd[1]);
          } else if (stdoutFdRedirect >= 0) {
            dup2(stdoutFdRedirect, STDOUT_FILENO);
            int stdoutFlags = fcntl(STDOUT_FILENO, F_GETFL, 0);
            if (stdoutFlags >= 0 && (stdoutFlags & O_NONBLOCK)) {
              fcntl(STDOUT_FILENO, F_SETFL, stdoutFlags & ~O_NONBLOCK);
            }
          } else if (stdioModes[1] == "ignore") {
            int nullStdout = open("/dev/null", O_WRONLY);
            if (nullStdout >= 0) {
              dup2(nullStdout, STDOUT_FILENO);
              close(nullStdout);
            }
          }

          if (stderrPipeRequested) {
            close(stderrPipeFd[0]);
            dup2(stderrPipeFd[1], STDERR_FILENO);
            close(stderrPipeFd[1]);
          } else if (stderrFdRedirect >= 0) {
            dup2(stderrFdRedirect, STDERR_FILENO);
            int stderrFlags = fcntl(STDERR_FILENO, F_GETFL, 0);
            if (stderrFlags >= 0 && (stderrFlags & O_NONBLOCK)) {
              fcntl(STDERR_FILENO, F_SETFL, stderrFlags & ~O_NONBLOCK);
            }
          } else if (stdioModes[2] == "ignore") {
            int nullStderr = open("/dev/null", O_WRONLY);
            if (nullStderr >= 0) {
              dup2(nullStderr, STDERR_FILENO);
              close(nullStderr);
            }
          }

          if (ipcRequested) {
            close(ipcPair[1]);
            dup2(ipcPair[0], 3);
            close(ipcPair[0]);
            // Set IPC fd to non-blocking so child's poll reads don't hang
            int ipcFlags = fcntl(3, F_GETFL, 0);
            if (ipcFlags >= 0) {
              fcntl(3, F_SETFL, ipcFlags | O_NONBLOCK);
            }
          }

          // Set up extra stdio pipes (index 4+)
          for (size_t i = 0; i < extraPipes.size(); i++) {
            if (extraPipes[i].second >= 0) {
              close(extraPipes[i].first); // close parent end in child
              int targetFd = static_cast<int>(i + 4);
              dup2(extraPipes[i].second, targetFd);
              close(extraPipes[i].second);
            }
          }

          if (!stdinPipeRequested) {
            if (stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
            if (stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
          }
          if (!stdoutPipeRequested) {
            if (stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
          }
          if (!stderrPipeRequested) {
            if (stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
          }
          if (!ipcRequested) {
            if (ipcPair[0] >= 0) close(ipcPair[0]);
            if (ipcPair[1] >= 0) close(ipcPair[1]);
          }

          // Suppress runtime bundle note in child processes
          setenv("EXACT_QUIET", "1", 1);

          // Set EXACT_IPC_FD so the child knows which fd is the IPC channel
          if (ipcRequested) {
            for (size_t si = 0; si < stdioModes.size(); si++) {
              if (stdioModes[si] == "ipc") {
                std::string ipcFdStr = std::to_string(si);
                setenv("EXACT_IPC_FD", ipcFdStr.c_str(), 1);
                break;
              }
            }
          }

          // Build envp array (must outlive execvp call)
          std::vector<char*> envp;
          if (!envEntries.empty()) {
            // Ensure EXACT_QUIET is included in custom env
            envEntries.push_back("EXACT_QUIET=1");
            // Include EXACT_IPC_FD in custom env if IPC requested
            if (ipcRequested) {
              for (size_t si = 0; si < stdioModes.size(); si++) {
                if (stdioModes[si] == "ipc") {
                  envEntries.push_back("EXACT_IPC_FD=" + std::to_string(si));
                  break;
                }
              }
            }
            envp.reserve(envEntries.size() + 1);
            for (auto& e : envEntries) {
              envp.push_back(const_cast<char*>(e.c_str()));
            }
            envp.push_back(nullptr);
#if defined(__APPLE__)
            *_NSGetEnviron() = envp.data();
#else
            environ = envp.data();
#endif
          }

          if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) {
              int chdirErrno = errno;
              ssize_t nw = write(execErrPipe[1], &chdirErrno, sizeof(chdirErrno));
              (void)nw;
              _exit(127);
            }
          }

          // (ENG-23485) Apply options.gid/options.uid (gid first) between fork
          // and exec; failure reports through the exec error pipe so JS
          // surfaces spawn EPERM instead of silently keeping parent credentials.
          {
            int credErrno = s_applySpawnCredentials(spawnGid, spawnUid);
            if (credErrno != 0) {
              ssize_t nw = write(execErrPipe[1], &credErrno, sizeof(credErrno));
              (void)nw;
              _exit(127);
            }
          }

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            // (ENG-23032) Honor a custom `shell` binary; fall back to /bin/sh.
            const char* shBin = shellPath.empty() ? "/bin/sh" : shellPath.c_str();
            execl(shBin, shBin, "-c", fullCmd.c_str(), nullptr);
          } else {
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(file.c_str()));
            for (auto& a : spawnArgs) {
              argv.push_back(const_cast<char*>(a.c_str()));
            }
            argv.push_back(nullptr);
            execvp(file.c_str(), argv.data());
          }
          // exec failed - write errno to parent via the error pipe
          {
            int execErrno = errno;
            ssize_t nw = write(execErrPipe[1], &execErrno, sizeof(execErrno));
            (void)nw;
          }
          _exit(127);
        }

        // Parent process - check if exec succeeded or failed
        close(execErrPipe[1]); // close write end in parent
        {
          int childErrno = 0;
          ssize_t n = read(execErrPipe[0], &childErrno, sizeof(childErrno));
          close(execErrPipe[0]);

          if (n > 0) {
            // Exec failed in the child - reap it and return error
            int wstatus;
            waitpid(pid, &wstatus, 0);
            // ENG-23113 — close EVERY fd the parent still holds. No
            // SpawnedProcess is stored on exec failure, so there is no
            // __exactSpawnDispose to reclaim these later. Previously only the
            // parent-retained ends below were closed; the child-side ends the
            // parent also holds (the child exited, but the parent's copies remain)
            // and every extraPipes fd leaked permanently -> EMFILE for a process
            // that probes for optional/missing binaries.
            // Parent-retained ends:
            if (stdinPipeRequested && stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
            if (stdoutPipeRequested && stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stderrPipeRequested && stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (ipcRequested && ipcPair[1] >= 0) close(ipcPair[1]);
            // Child-side ends the parent still holds (the success path closes
            // these once the child has inherited them; here the child is gone):
            if (stdinPipeRequested && stdinPipeFd[0] >= 0) close(stdinPipeFd[0]);
            if (stdoutPipeRequested && stdoutPipeFd[1] >= 0) close(stdoutPipeFd[1]);
            if (stderrPipeRequested && stderrPipeFd[1] >= 0) close(stderrPipeFd[1]);
            if (ipcRequested && ipcPair[0] >= 0) close(ipcPair[0]);
            for (auto& p : extraPipes) {
              if (p.first >= 0) close(p.first);
              if (p.second >= 0) close(p.second);
            }

            std::string errName;
            if (childErrno == ENOENT) errName = "ENOENT";
            else if (childErrno == EACCES) errName = "EACCES";
            else if (childErrno == EPERM) errName = "EPERM";
            else if (childErrno == ENOEXEC) errName = "ENOEXEC";
            else errName = "UNKNOWN";

            std::string errorJson = "{\"error\":\"" + errName
                + "\",\"errno\":" + std::to_string(childErrno)
                + ",\"path\":\"" + file + "\"}";
            return facebook::jsi::Value(
                facebook::jsi::String::createFromUtf8(runtime, errorJson));
          }
        }

        if (stdinPipeRequested) close(stdinPipeFd[0]);   // close read end of stdin pipe (child reads)
        if (stdoutPipeRequested) close(stdoutPipeFd[1]); // close write end of stdout pipe (child writes)
        if (stderrPipeRequested) close(stderrPipeFd[1]); // close write end of stderr pipe (child writes)
        if (ipcRequested) close(ipcPair[0]); // close read end in parent

        if (stdinPipeRequested) {
          int flags = fcntl(stdinPipeFd[1], F_GETFL, 0);
          if (flags >= 0) {
            fcntl(stdinPipeFd[1], F_SETFL, flags | O_NONBLOCK);
          }
        }
        if (stdoutPipeRequested) fcntl(stdoutPipeFd[0], F_SETFL, O_NONBLOCK);
        if (stderrPipeRequested) fcntl(stderrPipeFd[0], F_SETFL, O_NONBLOCK);
        if (ipcRequested) {
          int flags = fcntl(ipcPair[1], F_GETFL, 0);
          if (flags >= 0) {
            fcntl(ipcPair[1], F_SETFL, flags | O_NONBLOCK);
          }
        }

        // Store in map
        int handle;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          handle = s_nextSpawnHandle++;
          SpawnedProcess proc;
          proc.owner = currentPrincipalId();
          proc.capability = "process:spawn";
          proc.pid = pid;
          proc.stdinFd = stdinPipeRequested ? stdinPipeFd[1] : -1;
          proc.stdoutFd = stdoutPipeRequested ? stdoutPipeFd[0] : -1;
          proc.stderrFd = stderrPipeRequested ? stderrPipeFd[0] : -1;
          proc.ipcFd = ipcRequested ? ipcPair[1] : -1;
          // Store parent-side fds for extra stdio pipes and close child ends
          for (size_t i = 0; i < extraPipes.size(); i++) {
            int extraFlags = fcntl(extraPipes[i].first, F_GETFL, 0);
            if (extraFlags >= 0) {
              fcntl(extraPipes[i].first, F_SETFL, extraFlags | O_NONBLOCK);
            }
            proc.extraFds.push_back(extraPipes[i].first);
            if (extraPipes[i].second >= 0) close(extraPipes[i].second); // close child end in parent
          }
          proc.exited = false;
          proc.exitCode = -1;
          proc.exitSignal = 0;
          s_spawnedProcesses[handle] = std::move(proc);
        }

        std::string resultJson = "{\"handle\":" + std::to_string(handle)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid)) + "}";
        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, resultJson));
      });
  rt.global().setProperty(rt, "__exactSpawn", std::move(spawnFn));

  // __exactSpawnRead(handle, stream) -> Uint8Array (raw bytes read, empty if
  // nothing available). stream is "stdout", "stderr", or "ipc". Non-blocking.
  // (ENG-23009) The data channel is byte-accurate: child output is handed to JS
  // as raw bytes rather than a UTF-8 string, so bytes >= 0x80 and NULs survive
  // the native->JS boundary instead of being mangled by createFromUtf8/U+FFFD.
  // IPC callers UTF-8 decode the bytes themselves (packets are ASCII/UTF-8 JSON).
  auto spawnReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return makeUint8Array(runtime, {});
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnRead")) {
          return makeUint8Array(runtime, {});
        }
        std::string streamName;
        if (args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        } else if (args[1].isNumber()) {
          switch (static_cast<int>(args[1].asNumber())) {
            case 1:
              streamName = "stdout";
              break;
            case 2:
              streamName = "stderr";
              break;
            case 3:
              streamName = "ipc";
              break;
            default:
              return makeUint8Array(runtime, {});
          }
        } else {
          return makeUint8Array(runtime, {});
        }

        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            return makeUint8Array(runtime, {});
          }
          if (streamName == "stdout") {
            fd = it->second.stdoutFd;
          } else if (streamName == "stderr") {
            fd = it->second.stderrFd;
          } else if (streamName == "ipc") {
            fd = it->second.ipcFd;
          }
        }

        if (fd < 0) {
          if (streamName == "ipc" && startup_trace_enabled()) {
            fprintf(stderr, "[spawn_read] ipc fd=-1 for handle %d\n", handle);
          }
          return makeUint8Array(runtime, {});
        }

        // Non-blocking read
        char buf[65536];
        std::vector<uint8_t> result;
        while (true) {
          ssize_t n = read(fd, buf, sizeof(buf));
          if (n > 0) {
            result.insert(result.end(), buf, buf + n);
          } else {
            if (streamName == "ipc" && startup_trace_enabled() && n < 0) {
              fprintf(stderr, "[spawn_read] ipc fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
            }
            break;  // EAGAIN/EWOULDBLOCK or EOF
          }
        }

        if (!result.empty() && streamName == "ipc" && startup_trace_enabled()) {
          fprintf(stderr, "[spawn_read] ipc fd=%d got %zu bytes\n", fd, result.size());
        }

        return makeUint8Array(runtime, std::move(result));
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(spawnReadFn));

  // __exactSpawnGetFd(handle, streamIndex) -> raw fd or -1
  // streamIndex: 0=stdin, 1=stdout, 2=stderr, 3=ipc
  auto spawnGetFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnGetFd")) {
          return facebook::jsi::Value(-1);
        }
        int streamIndex = static_cast<int>(args[1].asNumber());
        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) return facebook::jsi::Value(-1);
        const auto& proc = it->second;
        switch (streamIndex) {
          case 0: return facebook::jsi::Value(proc.stdinFd);
          case 1: return facebook::jsi::Value(proc.stdoutFd);
          case 2: return facebook::jsi::Value(proc.stderrFd);
          case 3: return facebook::jsi::Value(proc.ipcFd);
          default: {
            int extraIdx = streamIndex - 4;
            if (extraIdx >= 0 && extraIdx < (int)proc.extraFds.size()) {
              return facebook::jsi::Value(proc.extraFds[extraIdx]);
            }
            return facebook::jsi::Value(-1);
          }
        }
      });
  rt.global().setProperty(rt, "__exactSpawnGetFd", std::move(spawnGetFdFn));

  // __exactSpawnWrite(handle, data, stream?) -> number
  // For stdio pipes this returns the number of bytes written (0 on EAGAIN).
  // IPC writes still attempt to write the full payload and return bytes written.
  // (ENG-23009) `data` may be a Uint8Array/ArrayBuffer (byte-accurate, used for
  // stdin/relay writes so bytes >= 0x80 are not UTF-8 re-encoded) or a string
  // (used by the IPC JSON packet path, which is ASCII/UTF-8 already).
  auto spawnWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnWrite")) {
          return facebook::jsi::Value(-1);
        }
        // Collect the payload as raw bytes from either a string or a byte view.
        std::string strHolder;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        if (args[1].isString()) {
          strHolder = args[1].toString(runtime).utf8(runtime);
          payload = reinterpret_cast<const uint8_t*>(strHolder.data());
          payloadLen = strHolder.size();
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (!extractArrayBufferView(runtime, obj, payload, payloadLen)) {
            return facebook::jsi::Value(-1);
          }
        } else {
          return facebook::jsi::Value(-1);
        }
        auto streamName = std::string("stdin");
        if (count > 2 && args[2].isString()) {
          streamName = args[2].toString(runtime).utf8(runtime);
        }

        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            return facebook::jsi::Value(-1);
          }
          if (streamName == "stdin") {
            fd = it->second.stdinFd;
          } else if (streamName == "ipc") {
            fd = it->second.ipcFd;
          } else if (streamName.substr(0, 6) == "extra:") {
            int extraIdx = std::atoi(streamName.c_str() + 6);
            if (extraIdx >= 0 && extraIdx < (int)it->second.extraFds.size()) {
              fd = it->second.extraFds[extraIdx];
            }
          }
        }

        if (fd < 0) {
          if (streamName == "ipc" && startup_trace_enabled()) {
            fprintf(stderr, "[spawn_write] ipc fd=-1 for handle %d\n", handle);
          }
          return facebook::jsi::Value(-1);
        }

        if (streamName == "ipc" && startup_trace_enabled()) {
          fprintf(stderr, "[spawn_write] ipc fd=%d data_len=%zu\n", fd, payloadLen);
        }

        if (streamName != "ipc") {
          while (true) {
            ssize_t n = write(fd, payload, payloadLen);
            if (n < 0) {
              if (errno == EINTR) continue;
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return facebook::jsi::Value(0);
              }
              return facebook::jsi::Value(-1);
            }
            return facebook::jsi::Value(static_cast<int>(n));
          }
        }

        size_t totalWritten = 0;
        while (totalWritten < payloadLen) {
          ssize_t n = write(fd, payload + totalWritten, payloadLen - totalWritten);
          if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              return facebook::jsi::Value(static_cast<int>(totalWritten));
            }
            if (startup_trace_enabled()) {
              fprintf(stderr, "[spawn_write] ipc write error: fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
            }
            return facebook::jsi::Value(-1);
          }
          totalWritten += static_cast<size_t>(n);
        }
        return facebook::jsi::Value(static_cast<int>(totalWritten));
      });
  rt.global().setProperty(rt, "__exactSpawnWrite", std::move(spawnWriteFn));

  // __exactSpawnSendMsg(handle, data, sendFd?) -> number
  // Sends data to the child's IPC socket using sendmsg and returns the byte
  // count the kernel accepted (0 on EAGAIN — retry later) or -1 on a hard
  // failure. `data` may be a string or a Uint8Array/ArrayBuffer view. If
  // sendFd >= 0 the descriptor rides SCM_RIGHTS on this call, so the caller
  // must attach it only to the FIRST chunk of a framed packet (ENG-23231:
  // partial sends are queued and resumed by the JS side, mirroring the
  // child-side __exactIpcSendMsg contract).
  auto spawnSendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSendMsg"),
      3,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnSendMsg")) {
          return facebook::jsi::Value(-1);
        }
        std::string strHolder;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        if (args[1].isString()) {
          strHolder = args[1].toString(runtime).utf8(runtime);
          payload = reinterpret_cast<const uint8_t*>(strHolder.data());
          payloadLen = strHolder.size();
        } else if (args[1].isObject()) {
          auto obj = args[1].asObject(runtime);
          if (!extractArrayBufferView(runtime, obj, payload, payloadLen)) {
            return facebook::jsi::Value(-1);
          }
        } else {
          return facebook::jsi::Value(-1);
        }
        int sendFd = -1;
        if (count > 2 && args[2].isNumber()) {
          sendFd = static_cast<int>(args[2].asNumber());
        }
        if (sendFd >= 0) {
          exactRequireTransferableFd(runtime, sendFd, "__exactSpawnSendMsg");
        }

        int ipcFd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) return facebook::jsi::Value(-1);
          ipcFd = it->second.ipcFd;
        }
        if (ipcFd < 0) return facebook::jsi::Value(-1);

        struct iovec iov;
        iov.iov_base = const_cast<uint8_t*>(payload);
        iov.iov_len = payloadLen;

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        union {
          char buf[CMSG_SPACE(sizeof(int))];
          struct cmsghdr align;
        } cmsgBuf;

        if (sendFd >= 0) {
          memset(&cmsgBuf, 0, sizeof(cmsgBuf));
          msg.msg_control = cmsgBuf.buf;
          msg.msg_controllen = sizeof(cmsgBuf.buf);
          struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
          cmsg->cmsg_level = SOL_SOCKET;
          cmsg->cmsg_type = SCM_RIGHTS;
          cmsg->cmsg_len = CMSG_LEN(sizeof(int));
          memcpy(CMSG_DATA(cmsg), &sendFd, sizeof(int));
        }

        while (true) {
          ssize_t sent = ::sendmsg(ipcFd, &msg, 0);
          if (sent < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
              return facebook::jsi::Value(0);
            }
            return facebook::jsi::Value(-1);
          }
          return facebook::jsi::Value(static_cast<int>(sent));
        }
      });
  rt.global().setProperty(rt, "__exactSpawnSendMsg", std::move(spawnSendMsgFn));

  // __exactSpawnRecvMsg(handle) -> {data: Uint8Array, fd: number} or null
  // Receives data from the child's IPC socket using recvmsg. Returns
  // any SCM_RIGHTS file descriptor in the fd field (-1 if none).
  // (ENG-23485) data is raw bytes; JS decodes with a streaming UTF-8 decoder.
  auto spawnRecvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRecvMsg"),
      1,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnRecvMsg")) {
          return facebook::jsi::Value::null();
        }

        int ipcFd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) return facebook::jsi::Value::null();
          ipcFd = it->second.ipcFd;
        }
        if (ipcFd < 0) return facebook::jsi::Value::null();

        char buf[65536];
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        union {
          char cbuf[CMSG_SPACE(sizeof(int))];
          struct cmsghdr align;
        } cmsgBuf;
        memset(&cmsgBuf, 0, sizeof(cmsgBuf));

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgBuf.cbuf;
        msg.msg_controllen = sizeof(cmsgBuf.cbuf);

        ssize_t bytesRead = ::recvmsg(ipcFd, &msg, 0);
        if (bytesRead <= 0) {
          return facebook::jsi::Value::null();
        }

        int recvFd = -1;
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != nullptr) {
          if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&recvFd, CMSG_DATA(cmsg), sizeof(int));
            if (recvFd >= 0) {
              fcntl(recvFd, F_SETFD, FD_CLOEXEC);
              exactRegisterReceivedFdForCurrentPrincipal(recvFd);
            }
            break;
          }
          cmsg = CMSG_NXTHDR(&msg, cmsg);
        }

        auto result = facebook::jsi::Object(runtime);
        // (ENG-23485) Hand JS the raw bytes, not a UTF-8 string: a 64KB
        // recvmsg chunk can split a multibyte UTF-8 sequence, and
        // createFromUtf8 replaced the halves with U+FFFD before JS could
        // reassemble them (the corrupted JSON line was then silently
        // dropped). JS feeds these bytes to a persistent streaming decoder,
        // same as the __exactSpawnRead byte channel (ENG-23009).
        std::vector<uint8_t> dataBytes(buf, buf + static_cast<size_t>(bytesRead));
        result.setProperty(runtime, "data", makeUint8Array(runtime, std::move(dataBytes)));
        result.setProperty(runtime, "fd", facebook::jsi::Value(recvFd));
        return result;
      });
  rt.global().setProperty(rt, "__exactSpawnRecvMsg", std::move(spawnRecvMsgFn));

  // __exactSpawnPoll(handle) -> JSON string {"exited":bool,"exitCode":N,"signal":N}
  // Uses waitpid with WNOHANG for non-blocking check.
  auto spawnPollFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnPoll"),
      1,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnPoll")) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":true,\"exitCode\":-1,\"signal\":0}"));
        }

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":true,\"exitCode\":-1,\"signal\":0}"));
        }

        auto& proc = it->second;
        if (proc.exited) {
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc.exitCode)
              + ",\"signal\":" + std::to_string(proc.exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }

        int status = 0;
        pid_t result = waitpid(proc.pid, &status, WNOHANG);
        if (result == 0) {
          // Still running
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        } else if (result > 0) {
          // Process exited
          proc.exited = true;
          if (WIFEXITED(status)) {
            proc.exitCode = WEXITSTATUS(status);
            proc.exitSignal = 0;
          } else if (WIFSIGNALED(status)) {
            proc.exitCode = -1;
            proc.exitSignal = WTERMSIG(status);
          }
          std::string json = "{\"exited\":true,\"exitCode\":" + std::to_string(proc.exitCode)
              + ",\"signal\":" + std::to_string(proc.exitSignal) + "}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        } else {
          // waitpid error
          proc.exited = true;
          proc.exitCode = -1;
          std::string json = "{\"exited\":true,\"exitCode\":-1,\"signal\":0}";
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, json));
        }
      });
  rt.global().setProperty(rt, "__exactSpawnPoll", std::move(spawnPollFn));

  // __exactSpawnKill(handle, signal) -> boolean (success)
  // signal: number (e.g. 15 for SIGTERM, 9 for SIGKILL)
  auto spawnKillFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnKill"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnKill")) {
          return facebook::jsi::Value(false);
        }
        int sig = SIGTERM; // default
        if (count > 1 && args[1].isNumber()) {
          sig = static_cast<int>(args[1].asNumber());
        }

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value(false);
        }

        auto& proc = it->second;
        if (proc.exited) {
          return facebook::jsi::Value(false);
        }

        int killResult = kill(proc.pid, sig);
        return facebook::jsi::Value(killResult == 0);
      });
  rt.global().setProperty(rt, "__exactSpawnKill", std::move(spawnKillFn));

  // __exactSpawnCloseStdin(handle) -> void
  // __exactSpawnCloseStdin(handle, stream?) -> void
  // Closes the requested stream so the child process sees EOF.
  auto spawnCloseStdinFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnCloseStdin"),
      2,
      [trySpawnHandle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
        if (!trySpawnHandle(runtime, handle, "__exactSpawnCloseStdin")) {
          return facebook::jsi::Value::undefined();
        }
        auto streamName = std::string("stdin");
        if (count > 1 && args[1].isString()) {
          streamName = args[1].toString(runtime).utf8(runtime);
        }

        std::lock_guard<std::mutex> lock(s_spawnMutex);
        auto it = s_spawnedProcesses.find(handle);
        if (it == s_spawnedProcesses.end()) {
          return facebook::jsi::Value::undefined();
        }

        auto& proc = it->second;
        if (streamName == "ipc") {
          // Only close the IPC fd, not stdin
          if (proc.ipcFd >= 0) {
            close(proc.ipcFd);
            proc.ipcFd = -1;
          }
        } else {
          // Close stdin (default behavior)
          if (proc.stdinFd >= 0) {
            close(proc.stdinFd);
            proc.stdinFd = -1;
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnCloseStdin", std::move(spawnCloseStdinFn));

  // __exactSpawnDispose(handle) -> void
  // (ENG-23023) Release every parent-side fd captured for an async child and
  // drop its s_spawnedProcesses entry. The JS `close` handler calls this once the
  // child has exited and its streams are drained. Without it, each async spawn
  // permanently leaked its stdout/stderr (and any ipc/extra) read fds plus a map
  // entry, so a repeated spawn loop or per-request exec() marched to EMFILE. The
  // JS-only stub in child-process.js merely dropped the JS bookkeeping object;
  // installing this native fn overrides that stub so the kernel fds are freed.
  auto spawnDisposeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnDispose"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());

        // Detach the entry under the lock, then close its fds outside the lock.
        SpawnedProcess proc;
        bool found = false;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it != s_spawnedProcesses.end()) {
            proc = std::move(it->second);
            s_spawnedProcesses.erase(it);
            found = true;
          }
        }
        if (!found) {
          return facebook::jsi::Value::undefined();
        }

        // The child has already been reaped by __exactSpawnPoll; here we only
        // reclaim the parent-side descriptors. Each may already be -1 if closed
        // earlier (e.g. stdin via __exactSpawnCloseStdin, ipc via disconnect).
        if (proc.stdinFd >= 0) close(proc.stdinFd);
        if (proc.stdoutFd >= 0) close(proc.stdoutFd);
        if (proc.stderrFd >= 0) close(proc.stderrFd);
        if (proc.ipcFd >= 0) close(proc.ipcFd);
        for (int extraFd : proc.extraFds) {
          if (extraFd >= 0) close(extraFd);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSpawnDispose", std::move(spawnDisposeFn));

  // __exactWhich(command) -> string path or null
  // Searches PATH for the given command, similar to the `which` utility.
  auto whichFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWhich"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          return facebook::jsi::Value::null();
        }
        if (!checkCapability("process:spawn")) {
          throw facebook::jsi::JSError(
              runtime,
              "Permission denied: process:spawn capability required");
        }
        auto command = args[0].asString(runtime).utf8(runtime);

        // If command contains a slash, check it directly
        if (command.find('/') != std::string::npos) {
          if (access(command.c_str(), X_OK) == 0) {
            return facebook::jsi::String::createFromUtf8(runtime, command);
          }
          return facebook::jsi::Value::null();
        }

        // Get PATH environment variable
        const char* pathEnv = getenv("PATH");
        if (!pathEnv) {
          return facebook::jsi::Value::null();
        }

        std::string pathStr(pathEnv);
        std::string::size_type start = 0;
        while (start < pathStr.size()) {
          auto end = pathStr.find(':', start);
          if (end == std::string::npos) end = pathStr.size();

          std::string dir = pathStr.substr(start, end - start);
          if (!dir.empty()) {
            std::string fullPath = dir + "/" + command;
            if (access(fullPath.c_str(), X_OK) == 0) {
              // Resolve to real path
              char resolved[PATH_MAX];
              if (realpath(fullPath.c_str(), resolved) != nullptr) {
                return facebook::jsi::String::createFromUtf8(runtime, std::string(resolved));
              }
              return facebook::jsi::String::createFromUtf8(runtime, fullPath);
            }
          }

          start = end + 1;
        }

        return facebook::jsi::Value::null();
      });
  rt.global().setProperty(rt, "__exactWhich", std::move(whichFn));

}
