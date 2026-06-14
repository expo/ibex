#include "hermes_runtime_internal.h"

// PATH_MAX / realpath live in <limits.h> on Linux; macOS pulls them in
// transitively. Spell it out so the realpath() path-resolution helpers build
// on Linux. @ref LLP 0177
#include <limits.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <fcntl.h>
#include <mutex>
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
          if (!checkCapability("child_process")) {
            throw facebook::jsi::JSError(
                runtime,
                "Permission denied: child_process capability required");
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
        return facebook::jsi::Value(false);
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
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
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

        // Build the actual command: optionally prepend cd
        std::string fullCommand = command;
        if (!cwd.empty()) {
          fullCommand = "cd " + cwd + " && " + command;
        }

        // Redirect stderr to a temp file so we can capture it separately
        char stderrTmpPath[] = "/tmp/ex_stderr_XXXXXX";
        int stderrFd = mkstemp(stderrTmpPath);
        if (stderrFd < 0) {
          throw facebook::jsi::JSError(runtime, "Failed to create temp file for stderr");
        }
        close(stderrFd);

        std::string shellCmd = "( " + fullCommand + " ) 2>" + stderrTmpPath;

        std::atomic<bool> timedOut{false};

        FILE* fp = popen(shellCmd.c_str(), "r");
        if (!fp) {
          unlink(stderrTmpPath);
          throw facebook::jsi::JSError(runtime, "Failed to execute command");
        }

        // Start timeout thread if needed
        if (timeout_ms > 0) {
          std::thread([timeout_ms, &timedOut]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            timedOut.store(true);
          }).detach();
        }

        // Read stdout
        std::string stdoutStr;
        char buf[4096];
        while (!timedOut.load()) {
          size_t bytesRead = fread(buf, 1, sizeof(buf), fp);
          if (bytesRead == 0) break;
          if (stdoutStr.size() + bytesRead > max_buffer) {
            stdoutStr.append(buf, max_buffer - stdoutStr.size());
            break;
          }
          stdoutStr.append(buf, bytesRead);
        }

        int pcloseResult = pclose(fp);
        int exitStatus = WIFEXITED(pcloseResult) ? WEXITSTATUS(pcloseResult) : -1;

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
        if (timedOut.load()) {
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
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
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
        uint32_t timeout_ms = 0;
        uint32_t max_buffer = 1024 * 1024;
        std::vector<std::string> envEntries;
        std::string stdinInput;
        bool hasStdinInput = false;
        std::string argv0;
        std::string syncStdioMode = "pipe"; // default: pipe stdout/stderr

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
          envEntries = s_parseEnvFromOpts(optsJson);
          // Parse stdio option (string form: "inherit", "pipe", "ignore")
          auto stdioPos = optsJson.find("\"stdio\":\"");
          if (stdioPos != std::string::npos) {
            auto start = stdioPos + 9;
            auto end = optsJson.find("\"", start);
            if (end != std::string::npos) {
              syncStdioMode = optsJson.substr(start, end - start);
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

        const bool syncStdoutPipe = (syncStdioMode == "pipe");
        const bool syncStderrPipe = (syncStdioMode == "pipe");
        const bool syncStdioIgnore = (syncStdioMode == "ignore");

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
          } else if (syncStdioIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) { dup2(nullFd, STDOUT_FILENO); close(nullFd); }
          }
          // else inherit: do nothing, keep parent's stdout

          if (syncStderrPipe) {
            close(stderrPipe[0]);
            dup2(stderrPipe[1], STDERR_FILENO);
            close(stderrPipe[1]);
          } else if (syncStdioIgnore) {
            int nullFd = open("/dev/null", O_WRONLY);
            if (nullFd >= 0) { dup2(nullFd, STDERR_FILENO); close(nullFd); }
          }
          // else inherit: do nothing, keep parent's stderr

          if (hasStdinInput) {
            close(stdinPipe[1]);
            dup2(stdinPipe[0], STDIN_FILENO);
            close(stdinPipe[0]);
          } else if (syncStdioIgnore) {
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

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            execl("/bin/sh", "sh", "-c", fullCmd.c_str(), nullptr);
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
            if (syncStdoutPipe) close(stdoutPipe[0]);
            if (syncStderrPipe) close(stderrPipe[0]);
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
            std::string resultJson = "{\"stdout\":\"\",\"stderr\":\"\",\"status\":127,\"pid\":"
                + std::to_string(static_cast<int>(pid))
                + ",\"error\":\"" + jsonEscape(errorStr) + "\"}";
            return facebook::jsi::Value(
                facebook::jsi::String::createFromUtf8(runtime, resultJson));
          }
        }
        if (syncStdoutPipe) close(stdoutPipe[1]);
        if (syncStderrPipe) close(stderrPipe[1]);
        if (hasStdinInput) {
          close(stdinPipe[0]);
          // Write input to child's stdin
          const char* data = stdinInput.c_str();
          size_t remaining = stdinInput.size();
          while (remaining > 0) {
            ssize_t written = write(stdinPipe[1], data, remaining);
            if (written <= 0) break;
            data += written;
            remaining -= written;
          }
          close(stdinPipe[1]);
        }

        std::string stdoutStr, stderrStr;
        char buf[4096];
        std::atomic<bool> timedOut{false};
        std::atomic<bool> childExited{false};

        if (timeout_ms > 0) {
          std::thread([timeout_ms, &timedOut, &childExited, pid]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
            if (!childExited.load() && kill(pid, SIGKILL) == 0) {
              timedOut.store(true);
            }
          }).detach();
        }

        // Read stdout (only if piped)
        if (syncStdoutPipe) {
          while (true) {
            ssize_t bytesRead = read(stdoutPipe[0], buf, sizeof(buf));
            if (bytesRead <= 0) break;
            if (stdoutStr.size() + static_cast<size_t>(bytesRead) > max_buffer) {
              stdoutStr.append(buf, max_buffer - stdoutStr.size());
              break;
            }
            stdoutStr.append(buf, static_cast<size_t>(bytesRead));
          }
          close(stdoutPipe[0]);
        }

        // Read stderr (only if piped)
        if (syncStderrPipe) {
          while (true) {
            ssize_t bytesRead = read(stderrPipe[0], buf, sizeof(buf));
            if (bytesRead <= 0) break;
            stderrStr.append(buf, static_cast<size_t>(bytesRead));
          }
          close(stderrPipe[0]);
        }

        // Wait for child
        int status = 0;
        waitpid(pid, &status, 0);
        childExited.store(true);
        int exitStatus = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (WIFSIGNALED(status)) {
          exitStatus = -WTERMSIG(status);
        }

        std::string errorStr;
        if (timedOut.load()) {
          errorStr = "Command timed out";
        } else if (exitStatus == 127) {
          errorStr = "Command not found: " + file;
        }

        std::string resultJson = "{\"stdout\":\"" + jsonEscape(stdoutStr)
            + "\",\"stderr\":\"" + jsonEscape(stderrStr)
            + "\",\"status\":" + std::to_string(exitStatus)
            + ",\"pid\":" + std::to_string(static_cast<int>(pid));
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

  // __exactSpawn(file, argsJSON, optionsJSON) -> JSON string {"handle":N,"pid":N} or {"error":"..."}
  auto spawnFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawn"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (!checkCapability("child_process")) {
          throw facebook::jsi::JSError(runtime, "Permission denied: child_process capability required");
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
          }

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
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"error\":\"Failed to fork process\"}"));
        }

        if (pid == 0) {
          // Child process
          close(execErrPipe[0]); // close read end in child
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

          if (useShell) {
            std::string fullCmd = file;
            for (auto& a : spawnArgs) {
              fullCmd += " " + a;
            }
            execl("/bin/sh", "sh", "-c", fullCmd.c_str(), nullptr);
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
            // Clean up all pipe fds
            if (stdinPipeRequested && stdinPipeFd[1] >= 0) close(stdinPipeFd[1]);
            if (stdoutPipeRequested && stdoutPipeFd[0] >= 0) close(stdoutPipeFd[0]);
            if (stderrPipeRequested && stderrPipeFd[0] >= 0) close(stderrPipeFd[0]);
            if (ipcRequested && ipcPair[1] >= 0) close(ipcPair[1]);

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

  // __exactSpawnRead(handle, stream) -> string (data read, empty if nothing available)
  // stream is "stdout", "stderr", or "ipc". Non-blocking read.
  auto spawnReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRead"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
        }
        int handle = static_cast<int>(args[0].asNumber());
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
              return facebook::jsi::Value(
                  facebook::jsi::String::createFromUtf8(runtime, ""));
          }
        } else {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, ""));
        }

        int fd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) {
            return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
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
          return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, ""));
        }

        // Non-blocking read
        char buf[65536];
        std::string result;
        while (true) {
          ssize_t n = read(fd, buf, sizeof(buf));
          if (n > 0) {
            result.append(buf, static_cast<size_t>(n));
          } else {
            if (streamName == "ipc" && startup_trace_enabled() && n < 0) {
              fprintf(stderr, "[spawn_read] ipc fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
            }
            break;  // EAGAIN/EWOULDBLOCK or EOF
          }
        }

        if (!result.empty() && streamName == "ipc" && startup_trace_enabled()) {
          fprintf(stderr, "[spawn_read] ipc fd=%d got %zu bytes: %.80s\n", fd, result.size(), result.c_str());
        }

        return facebook::jsi::Value(
            facebook::jsi::String::createFromUtf8(runtime, result));
      });
  rt.global().setProperty(rt, "__exactSpawnRead", std::move(spawnReadFn));

  // __exactSpawnGetFd(handle, streamIndex) -> raw fd or -1
  // streamIndex: 0=stdin, 1=stdout, 2=stderr, 3=ipc
  auto spawnGetFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnGetFd"),
      2,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
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
  auto spawnWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnWrite"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value(-1);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto data = args[1].toString(runtime).utf8(runtime);
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
          fprintf(stderr, "[spawn_write] ipc fd=%d data_len=%zu: %.80s\n", fd, data.size(), data.c_str());
        }

        if (streamName != "ipc") {
          while (true) {
            ssize_t n = write(fd, data.c_str(), data.size());
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
        while (totalWritten < data.size()) {
          ssize_t n = write(fd, data.c_str() + totalWritten, data.size() - totalWritten);
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

  // __exactSpawnSendMsg(handle, data, sendFd?) -> boolean
  // Sends data to the child's IPC socket using sendmsg. If sendFd >= 0,
  // passes the file descriptor via SCM_RIGHTS.
  auto spawnSendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnSendMsg"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isString()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
        auto data = args[1].toString(runtime).utf8(runtime);
        int sendFd = -1;
        if (count > 2 && args[2].isNumber()) {
          sendFd = static_cast<int>(args[2].asNumber());
        }

        int ipcFd = -1;
        {
          std::lock_guard<std::mutex> lock(s_spawnMutex);
          auto it = s_spawnedProcesses.find(handle);
          if (it == s_spawnedProcesses.end()) return facebook::jsi::Value(false);
          ipcFd = it->second.ipcFd;
        }
        if (ipcFd < 0) return facebook::jsi::Value(false);

        struct iovec iov;
        iov.iov_base = const_cast<char*>(data.c_str());
        iov.iov_len = data.size();

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

        ssize_t sent = ::sendmsg(ipcFd, &msg, 0);
        return facebook::jsi::Value(sent > 0);
      });
  rt.global().setProperty(rt, "__exactSpawnSendMsg", std::move(spawnSendMsgFn));

  // __exactSpawnRecvMsg(handle) -> {data: string, fd: number} or null
  // Receives data from the child's IPC socket using recvmsg. Returns
  // any SCM_RIGHTS file descriptor in the fd field (-1 if none).
  auto spawnRecvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactSpawnRecvMsg"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::null();
        }
        int handle = static_cast<int>(args[0].asNumber());

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
            if (recvFd >= 0) fcntl(recvFd, F_SETFD, FD_CLOEXEC);
            break;
          }
          cmsg = CMSG_NXTHDR(&msg, cmsg);
        }

        auto result = facebook::jsi::Object(runtime);
        result.setProperty(runtime, "data",
            facebook::jsi::String::createFromUtf8(runtime, std::string(buf, static_cast<size_t>(bytesRead))));
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "{\"exited\":false,\"exitCode\":-1,\"signal\":0}"));
        }
        int handle = static_cast<int>(args[0].asNumber());

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
      [](facebook::jsi::Runtime& /*runtime*/,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int handle = static_cast<int>(args[0].asNumber());
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value::undefined();
        }
        int handle = static_cast<int>(args[0].asNumber());
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
