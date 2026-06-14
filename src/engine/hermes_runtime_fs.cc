#include "hermes_runtime_internal.h"

// PATH_MAX / realpath live in <limits.h> on Linux; macOS pulls them in
// transitively. Spell it out so the realpath() path-resolution helpers build
// on Linux. @ref LLP 0177
#include <limits.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#if defined(__linux__) && !defined(EXACT_PLATFORM_ANDROID)
#include <sys/statfs.h>
#endif
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

extern "C" void* ex_host_fs_open(const char* path, uint32_t flags);
extern "C" int32_t ex_host_fs_read(void* file, uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_write(void* file, const uint8_t* buf, uint32_t len);
extern "C" void ex_host_fs_close(void* file);
extern "C" uint8_t* ex_host_fs_read_file(const char* path,
                                         uint32_t* out_len,
                                         int32_t* out_errno);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint32_t len);
extern "C" char* ex_host_fs_stat(const char* path);
extern "C" char* ex_host_fs_lstat(const char* path);
extern "C" char* ex_host_fs_readdir(const char* path);
extern "C" int32_t ex_host_fs_mkdir(const char* path, int32_t recursive);
extern "C" int32_t ex_host_fs_rmdir(const char* path);
extern "C" int32_t ex_host_fs_unlink(const char* path);
extern "C" int32_t ex_host_fs_rename(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy(const char* from, const char* to);
extern "C" char* ex_host_fs_realpath(const char* path);
extern "C" int32_t ex_host_fs_access(const char* path, int32_t mode);
extern "C" int32_t ex_host_fs_chmod(const char* path, uint32_t mode);
extern "C" char* ex_host_fs_mkdtemp(const char* prefix);
extern "C" int32_t ex_host_fs_append(const char* path, const uint8_t* data, uint32_t len);
extern "C" void ex_host_free_string(char* value);

constexpr uint32_t EXACT_FS_WRITE = 1u << 1;
constexpr uint32_t EXACT_FS_CREATE = 1u << 2;
constexpr uint32_t EXACT_FS_TRUNCATE = 1u << 3;

struct IoVecMetadata {
  bool isArrayBuffer;
  size_t byteOffset;
  size_t byteLength;
};

static bool parseIoVecArguments(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value,
    std::vector<std::vector<uint8_t>>& buffers,
    std::vector<struct iovec>& iovecs,
    std::vector<IoVecMetadata>* metadata) {
  if (!value.isObject()) {
    return false;
  }
  auto listObj = value.asObject(runtime);
  if (!listObj.isArray(runtime)) {
    return false;
  }
  auto lengthValue = listObj.getProperty(runtime, "length");
  if (!lengthValue.isNumber()) {
    return false;
  }
  auto length = static_cast<size_t>(lengthValue.asNumber());
  buffers.reserve(length);
  iovecs.reserve(length);
  if (metadata) {
    metadata->reserve(length);
  }
  for (size_t i = 0; i < length; i++) {
    std::string index = std::to_string(i);
    auto entry = listObj.getProperty(runtime, facebook::jsi::PropNameID::forAscii(runtime, index));
    if (!entry.isObject()) {
      return false;
    }
    auto entryObj = entry.asObject(runtime);
    size_t byteOffset = 0;
    size_t byteLength = 0;
    const uint8_t* source = nullptr;
    bool isArrayBuffer = false;
    if (entryObj.isArrayBuffer(runtime)) {
      auto ab = entryObj.getArrayBuffer(runtime);
      source = ab.data(runtime);
      byteLength = ab.size(runtime);
      isArrayBuffer = true;
    } else if (entryObj.hasProperty(runtime, "buffer")) {
      auto bufferValue = entryObj.getProperty(runtime, "buffer");
      if (!bufferValue.isObject()) {
        return false;
      }
      auto bufferObj = bufferValue.asObject(runtime);
      if (!bufferObj.isArrayBuffer(runtime)) {
        return false;
      }
      auto ab = bufferObj.getArrayBuffer(runtime);
      size_t available = ab.size(runtime);
      byteOffset = entryObj.hasProperty(runtime, "byteOffset")
          ? static_cast<size_t>(entryObj.getProperty(runtime, "byteOffset").asNumber())
          : 0;
      byteLength = entryObj.hasProperty(runtime, "byteLength")
          ? static_cast<size_t>(entryObj.getProperty(runtime, "byteLength").asNumber())
          : (available - byteOffset);
      if (byteOffset > available) {
        return false;
      }
      if (byteOffset + byteLength > available) {
        byteLength = available - byteOffset;
      }
      source = ab.data(runtime) + byteOffset;
    } else {
      return false;
    }
    if (byteLength > 0 && !source) {
      return false;
    }
    auto bytes = source ? std::vector<uint8_t>(source, source + byteLength) : std::vector<uint8_t>();
    buffers.push_back(std::move(bytes));
    auto& bytesRef = buffers.back();
    struct iovec iov {
      .iov_base = bytesRef.empty() ? nullptr : bytesRef.data(),
      .iov_len = bytesRef.size()
    };
    iovecs.push_back(iov);
    if (metadata) {
      metadata->push_back({isArrayBuffer, byteOffset, byteLength});
    }
  }
  return true;
}

static std::string fsErrorMessage(
    int errn,
    const char* syscall,
    const std::string& path,
    const std::string& dest = "") {
  const char* code = "UNKNOWN";
  const char* description = "unknown error";
  switch (errn) {
    case EACCES: code = "EACCES"; description = "permission denied"; break;
    case EBADF: code = "EBADF"; description = "bad file descriptor"; break;
    case EBUSY: code = "EBUSY"; description = "resource busy or locked"; break;
    case EEXIST: code = "EEXIST"; description = "file already exists"; break;
    case EINVAL: code = "EINVAL"; description = "invalid argument"; break;
    case EIO: code = "EIO"; description = "i/o error"; break;
    case EISDIR: code = "EISDIR"; description = "illegal operation on a directory"; break;
    case ELOOP: code = "ELOOP"; description = "too many symbolic links encountered"; break;
    case EMFILE: code = "EMFILE"; description = "too many open files"; break;
    case ENAMETOOLONG: code = "ENAMETOOLONG"; description = "name too long"; break;
    case ENOENT: code = "ENOENT"; description = "no such file or directory"; break;
    case ENOMEM: code = "ENOMEM"; description = "not enough memory"; break;
    case ENOSPC: code = "ENOSPC"; description = "no space left on device"; break;
    case ENOSYS: code = "ENOSYS"; description = "function not implemented"; break;
    case ENOTDIR: code = "ENOTDIR"; description = "not a directory"; break;
    case ENOTEMPTY: code = "ENOTEMPTY"; description = "directory not empty"; break;
    case EPERM: code = "EPERM"; description = "operation not permitted"; break;
    case EROFS: code = "EROFS"; description = "read-only file system"; break;
    case ESPIPE: code = "ESPIPE"; description = "invalid seek"; break;
    case EXDEV: code = "EXDEV"; description = "cross-device link not permitted"; break;
    case ETXTBSY: code = "ETXTBSY"; description = "text file is busy"; break;
#ifdef ENOTSUP
    case ENOTSUP: code = "ENOTSUP"; description = "operation not supported"; break;
#endif
    default: break;
  }
  std::string msg = std::string(code) + ": " + description + ", " + syscall;
  if (!path.empty()) {
    msg += " '" + path + "'";
  }
  if (!dest.empty()) {
    msg += " -> '" + dest + "'";
  }
  return msg;
}

static void throwFsError(
    facebook::jsi::Runtime& runtime,
    const char* syscall,
    const std::string& path = "",
    const std::string& dest = "") {
  int errn = errno;
  throw facebook::jsi::JSError(runtime, fsErrorMessage(errn, syscall, path, dest));
}

static void normalizeWriteErrno(int fd) {
#ifdef RLIMIT_FSIZE
  struct rlimit limit = {};
  if (getrlimit(RLIMIT_FSIZE, &limit) != 0 || limit.rlim_cur == RLIM_INFINITY) {
    return;
  }
  struct stat st = {};
  if (fstat(fd, &st) != 0 || st.st_size < 0) {
    return;
  }
  if (static_cast<rlim_t>(st.st_size) >= limit.rlim_cur) {
    errno = EFBIG;
  }
#endif
}

void installFsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto readFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactReadFile"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          return facebook::jsi::Value::undefined();
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }

        // Single FFI call: read entire file at once
        uint32_t len = 0;
        int32_t read_errno = 0;
        uint8_t* buf = ex_host_fs_read_file(path.c_str(), &len, &read_errno);
        if (!buf) {
          if (read_errno != 0) {
            errno = read_errno;
          }
          throwFsError(runtime, "open", path);
        }

        // Move data into a vector and free the Rust buffer
        std::vector<uint8_t> data(buf, buf + len);
        ex_host_free_buffer(buf, len);
        return makeUint8Array(runtime, std::move(data));
      });
  rt.global().setProperty(rt, "__exactReadFile", std::move(readFileFn));

  // __exactWriteFile(path, data: Uint8Array) -> void (throws on error)
  auto writeFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWriteFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactWriteFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        // Extract bytes from Uint8Array
        auto obj = args[1].asObject(runtime);
        size_t length = 0;
        const uint8_t* dataPtr = nullptr;
        std::vector<uint8_t> dataCopy;

        if (obj.hasProperty(runtime, "buffer")) {
          auto bufVal = obj.getProperty(runtime, "buffer");
          if (bufVal.isObject()) {
            auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
            auto offset = obj.hasProperty(runtime, "byteOffset")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteOffset").asNumber())
                : 0;
            length = obj.hasProperty(runtime, "byteLength")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteLength").asNumber())
                : buf.size(runtime) - offset;
            dataCopy.assign(buf.data(runtime) + offset, buf.data(runtime) + offset + length);
            dataPtr = dataCopy.data();
          }
        }

        void* handle = ex_host_fs_open(path.c_str(), EXACT_FS_WRITE | EXACT_FS_CREATE | EXACT_FS_TRUNCATE);
        if (!handle) {
          throw facebook::jsi::JSError(runtime, "Failed to open file for writing");
        }
        if (length > 0 && dataPtr) {
          int32_t written = ex_host_fs_write(handle, dataPtr, static_cast<uint32_t>(length));
          if (written < 0) {
            ex_host_fs_close(handle);
            throw facebook::jsi::JSError(runtime, "Failed to write file");
          }
        }
        ex_host_fs_close(handle);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWriteFile", std::move(writeFileFn));

  // __exactAppendFile(path, data: Uint8Array) -> void
  auto appendFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAppendFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactAppendFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        auto obj = args[1].asObject(runtime);
        size_t length = 0;
        const uint8_t* dataPtr = nullptr;
        std::vector<uint8_t> dataCopy;

        if (obj.hasProperty(runtime, "buffer")) {
          auto bufVal = obj.getProperty(runtime, "buffer");
          if (bufVal.isObject()) {
            auto buf = bufVal.asObject(runtime).getArrayBuffer(runtime);
            auto offset = obj.hasProperty(runtime, "byteOffset")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteOffset").asNumber())
                : 0;
            length = obj.hasProperty(runtime, "byteLength")
                ? static_cast<size_t>(obj.getProperty(runtime, "byteLength").asNumber())
                : buf.size(runtime) - offset;
            dataCopy.assign(buf.data(runtime) + offset, buf.data(runtime) + offset + length);
            dataPtr = dataCopy.data();
          }
        }

        if (length > 0 && dataPtr) {
          int32_t written = ex_host_fs_append(path.c_str(), dataPtr, static_cast<uint32_t>(length));
          if (written < 0) {
            throw facebook::jsi::JSError(runtime, "Failed to append to file");
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAppendFile", std::move(appendFileFn));

  // __exactStat(path) -> object {size, mtime_ms, is_dir, is_file, mode}
  auto statFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStat"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactStat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_stat(path.c_str());
        if (!json) {
          throwFsError(runtime, "stat", path);
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactStat", std::move(statFn));

  // __exactLstat(path) -> JSON string
  auto lstatFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactLstat"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactLstat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_lstat(path.c_str());
        if (!json) {
          throwFsError(runtime, "lstat", path);
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactLstat", std::move(lstatFn));

  // __exactReaddir(path) -> JSON string (array of names)
  auto readdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactReaddir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactReaddir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* json = ex_host_fs_readdir(path.c_str());
        if (!json) {
          throwFsError(runtime, "scandir", path);
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, json);
        ex_host_free_string(json);
        return result;
      });
  rt.global().setProperty(rt, "__exactReaddir", std::move(readdirFn));

  // __exactMkdir(path, recursive) -> void
  auto mkdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdir"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactMkdir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        int32_t recursive = 0;
        if (count > 1 && args[1].isBool()) {
          recursive = args[1].getBool() ? 1 : 0;
        } else if (count > 1 && args[1].isNumber()) {
          recursive = args[1].asNumber() != 0 ? 1 : 0;
        }
        if (ex_host_fs_mkdir(path.c_str(), recursive) != 0) {
          throwFsError(runtime, "mkdir", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactMkdir", std::move(mkdirFn));

  // __exactRmdir(path) -> void
  auto rmdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRmdir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRmdir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_rmdir(path.c_str()) != 0) {
          throwFsError(runtime, "rmdir", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactRmdir", std::move(rmdirFn));

  // __exactUnlink(path) -> void
  auto unlinkFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactUnlink"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactUnlink: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_unlink(path.c_str()) != 0) {
          throwFsError(runtime, "unlink", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactUnlink", std::move(unlinkFn));

  // __exactRename(from, to) -> void
  auto renameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRename"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRename: from and to paths required");
        }
        auto from = args[0].toString(runtime).utf8(runtime);
        auto to = args[1].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + from;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_rename(from.c_str(), to.c_str()) != 0) {
          throwFsError(runtime, "rename", from, to);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactRename", std::move(renameFn));

  // __exactCopyFile(from, to) -> void
  auto copyFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactCopyFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactCopyFile: src and dest required");
        }
        auto from = args[0].toString(runtime).utf8(runtime);
        auto to = args[1].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + from;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        std::string wcap = "fs:write:" + to;
        if (!checkCapability(wcap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (ex_host_fs_copy(from.c_str(), to.c_str()) != 0) {
          throwFsError(runtime, "copyfile", from, to);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactCopyFile", std::move(copyFileFn));

  // __exactRealpath(path) -> string
  auto realpathFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRealpath"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRealpath: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* resolved = ex_host_fs_realpath(path.c_str());
        if (!resolved) {
          throwFsError(runtime, "realpath", path);
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, resolved);
        ex_host_free_string(resolved);
        return result;
      });
  rt.global().setProperty(rt, "__exactRealpath", std::move(realpathFn));

  // __exactAccess(path, mode) -> void (throws if not accessible)
  auto accessFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAccess"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactAccess: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:read:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        int32_t mode = 0;
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int32_t>(args[1].asNumber());
        }
        if (ex_host_fs_access(path.c_str(), mode) != 0) {
          throwFsError(runtime, "access", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAccess", std::move(accessFn));

  // __exactChmod(path, mode) -> void
  auto chmodFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactChmod"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactChmod: path and mode required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        uint32_t mode = static_cast<uint32_t>(args[1].asNumber());
        if (ex_host_fs_chmod(path.c_str(), mode) != 0) {
          throwFsError(runtime, "chmod", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactChmod", std::move(chmodFn));

  // __exactMkdtemp(prefix) -> string (path of created temp directory)
  auto mkdtempFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdtemp"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        std::string prefix = "tmp";
        if (count > 0 && args[0].isString()) {
          prefix = args[0].toString(runtime).utf8(runtime);
        }
        std::string cap = "fs:write:" + prefix;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        char* path = ex_host_fs_mkdtemp(prefix.c_str());
        if (!path) {
          throw facebook::jsi::JSError(runtime, "Failed to create temporary directory");
        }
        auto result = facebook::jsi::String::createFromUtf8(runtime, path);
        ex_host_free_string(path);
        return result;
      });
  rt.global().setProperty(rt, "__exactMkdtemp", std::move(mkdtempFn));

  // __exactFsOpen(path, flags, mode) -> integer fd
  auto fsOpenFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsOpen"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsOpen: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            std::string wcap = "fs:write:" + path;
            if (!checkCapability(wcap)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          }
        }

        // Parse flags string to POSIX flags
        int posixFlags = O_RDONLY;
        if (count > 1 && args[1].isString()) {
          auto flagStr = args[1].toString(runtime).utf8(runtime);
          bool hasPlus = flagStr.find('+') != std::string::npos;
          bool hasSync = false;
          bool hasExclusive = false;
          char modeChar = 0;
          if (hasPlus && flagStr.find('+') != flagStr.rfind('+')) {
            throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
          }
          auto flagChars = hasPlus ? flagStr.substr(0, flagStr.size() - 1) : flagStr;
          if (hasPlus && !flagChars.empty() && flagStr.back() != '+') {
            throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
          }
          for (char ch : flagChars) {
            if (ch == 's') {
              if (hasSync) {
                throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
              }
              hasSync = true;
            } else if (ch == 'x') {
              if (hasExclusive) {
                throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
              }
              hasExclusive = true;
            } else if (ch == 'r' || ch == 'w' || ch == 'a') {
              if (modeChar) {
                throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
              }
              modeChar = ch;
            } else {
              throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
            }
          }
          if (!modeChar || (modeChar == 'r' && hasExclusive)) {
            throw facebook::jsi::JSError(runtime, "ERR_INVALID_ARG_VALUE: flags");
          }
          if (modeChar == 'r') {
            posixFlags = O_RDONLY;
          } else if (modeChar == 'w') {
            posixFlags = O_WRONLY | O_CREAT | O_TRUNC;
          } else {
            posixFlags = O_WRONLY | O_CREAT | O_APPEND;
          }
          if (hasPlus) {
            posixFlags = (posixFlags & ~O_WRONLY) | O_RDWR;
          }
          if (hasSync) {
            posixFlags |= O_SYNC;
          }
          if (hasExclusive) {
            posixFlags |= O_EXCL;
          }
        } else if (count > 1 && args[1].isNumber()) {
          posixFlags = static_cast<int>(args[1].asNumber());
        }

        int mode = 0666;
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        int fd = ::open(path.c_str(), posixFlags, mode);
        if (fd < 0) {
          throwFsError(runtime, "open", path);
        }
        return facebook::jsi::Value(fd);
      });
  rt.global().setProperty(rt, "__exactFsOpen", std::move(fsOpenFn));

  // __exactFsClose(fd) -> void
  auto fsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsClose: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        if (::close(fd) < 0) {
          throwFsError(runtime, "close", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsClose", std::move(fsCloseFn));

  // __exactFsRead(fd, length, position) -> Uint8Array (bytes read)
  // position = -1 means use current position
  auto fsReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsRead"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsRead: fd and length required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        size_t length = static_cast<size_t>(args[1].asNumber());

        // If position is provided and not -1 / null / undefined, seek first
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            if (::lseek(fd, static_cast<off_t>(pos), SEEK_SET) < 0) {
              throwFsError(runtime, "read");
            }
          }
        }

        std::vector<uint8_t> data(length);
        ssize_t bytesRead = ::read(fd, data.data(), length);
        if (bytesRead < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Non-blocking fd with no data available — return empty array
            return makeUint8Array(runtime, std::vector<uint8_t>());
          }
          if (startup_trace_enabled()) {
            fprintf(stderr, "[fsRead] fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
          }
          throwFsError(runtime, "read");
        }
        if (bytesRead > 0 && fd == 3 && startup_trace_enabled()) {
          fprintf(stderr, "[fsRead] fd=3 got %zd bytes\n", bytesRead);
        }
        data.resize(static_cast<size_t>(bytesRead));
        return makeUint8Array(runtime, std::move(data));
      });
  rt.global().setProperty(rt, "__exactFsRead", std::move(fsReadFn));

  // __exactFdPollHup(fd) -> boolean
  // Returns true if the file descriptor has received a hangup (pipe closed).
  // Uses poll() with zero timeout for non-blocking check.
  auto fdPollHupFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFdPollHup"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int fd = static_cast<int>(args[0].asNumber());
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int ret = ::poll(&pfd, 1, 0);
        if (ret > 0 && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
          return facebook::jsi::Value(true);
        }
        return facebook::jsi::Value(false);
      });
  rt.global().setProperty(rt, "__exactFdPollHup", std::move(fdPollHupFn));

  // __exactIpcSendMsg(socketFd, data, sendFd?) -> number (bytes sent)
  // Sends data over a Unix domain socket. If sendFd >= 0, passes it via
  // SCM_RIGHTS ancillary data (file descriptor passing).
  auto ipcSendMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactIpcSendMsg"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactIpcSendMsg: socketFd and data required");
        }
        int sockFd = static_cast<int>(args[0].asNumber());
        auto dataBytes = extractBytes(runtime, args[1]);
        int sendFd = -1;
        if (count > 2 && args[2].isNumber()) {
          sendFd = static_cast<int>(args[2].asNumber());
        }

        struct iovec iov;
        iov.iov_base = const_cast<uint8_t*>(dataBytes.data());
        iov.iov_len = dataBytes.size();

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Ancillary data buffer for SCM_RIGHTS
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

        ssize_t sent = ::sendmsg(sockFd, &msg, 0);
        if (sent < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return facebook::jsi::Value(0);
          }
          throw facebook::jsi::JSError(runtime, std::string("sendmsg failed: ") + strerror(errno));
        }
        return facebook::jsi::Value(static_cast<int>(sent));
      });
  rt.global().setProperty(rt, "__exactIpcSendMsg", std::move(ipcSendMsgFn));

  // __exactIpcRecvMsg(socketFd, bufSize) -> {data: Uint8Array, fd: number}
  // Receives data from a Unix domain socket using recvmsg. If a file
  // descriptor was passed via SCM_RIGHTS, it is returned in the fd field
  // (otherwise fd is -1).
  auto ipcRecvMsgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactIpcRecvMsg"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactIpcRecvMsg: socketFd and bufSize required");
        }
        int sockFd = static_cast<int>(args[0].asNumber());
        int bufSize = static_cast<int>(args[1].asNumber());
        if (bufSize <= 0) bufSize = 65536;

        std::vector<uint8_t> buf(static_cast<size_t>(bufSize));

        struct iovec iov;
        iov.iov_base = buf.data();
        iov.iov_len = buf.size();

        // Ancillary data buffer for receiving SCM_RIGHTS
        union {
          char buf[CMSG_SPACE(sizeof(int))];
          struct cmsghdr align;
        } cmsgBuf;
        memset(&cmsgBuf, 0, sizeof(cmsgBuf));

        struct msghdr msg = {};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgBuf.buf;
        msg.msg_controllen = sizeof(cmsgBuf.buf);

        ssize_t bytesRead = ::recvmsg(sockFd, &msg, 0);
        if (bytesRead < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Return empty result with no fd
            auto result = facebook::jsi::Object(runtime);
            result.setProperty(runtime, "data", makeUint8Array(runtime, {}));
            result.setProperty(runtime, "fd", facebook::jsi::Value(-1));
            return result;
          }
          throw facebook::jsi::JSError(runtime, std::string("recvmsg failed: ") + strerror(errno));
        }

        // Check for received file descriptor
        int recvFd = -1;
        struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
        while (cmsg != nullptr) {
          if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            memcpy(&recvFd, CMSG_DATA(cmsg), sizeof(int));
            // Set CLOEXEC on received fd
            if (recvFd >= 0) {
              fcntl(recvFd, F_SETFD, FD_CLOEXEC);
            }
            break;
          }
          cmsg = CMSG_NXTHDR(&msg, cmsg);
        }

        buf.resize(static_cast<size_t>(bytesRead));
        auto result = facebook::jsi::Object(runtime);
        result.setProperty(runtime, "data", makeUint8Array(runtime, std::move(buf)));
        result.setProperty(runtime, "fd", facebook::jsi::Value(recvFd));
        return result;
      });
  rt.global().setProperty(rt, "__exactIpcRecvMsg", std::move(ipcRecvMsgFn));

  // __exactFsWrite(fd, data, position) -> number (bytes written)
  // data can be a string or Uint8Array; position = -1 means use current position
  auto fsWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWrite"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsWrite: fd and data required");
        }
        int fd = static_cast<int>(args[0].asNumber());

        // Extract data bytes
        auto dataBytes = extractBytes(runtime, args[1]);

        // If position is provided and not -1 / null / undefined, seek first
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            if (::lseek(fd, static_cast<off_t>(pos), SEEK_SET) < 0) {
              throwFsError(runtime, "write");
            }
          }
        }

        ssize_t bytesWritten = ::write(fd, dataBytes.data(), dataBytes.size());
        if (bytesWritten < 0) {
          normalizeWriteErrno(fd);
          throwFsError(runtime, "write");
        }
        return facebook::jsi::Value(static_cast<int>(bytesWritten));
      });
  rt.global().setProperty(rt, "__exactFsWrite", std::move(fsWriteFn));

  // __exactFsReadv(fd, buffers, position, callback?)
  auto fsReadvFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadv"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadv: fd and buffers required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        std::vector<IoVecMetadata> targetMetadata;
        if (!parseIoVecArguments(runtime, args[1], buffers, iovecs, &targetMetadata)) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadv: buffers must be Uint8Array-like objects");
        }
        auto listObj = args[1].asObject(runtime);
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            if (::lseek(fd, static_cast<off_t>(pos), SEEK_SET) < 0) {
              throwFsError(runtime, "readv");
            }
          }
        }
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 3 && args[3].isObject() && args[3].asObject(runtime).isFunction(runtime)) {
          callback = args[3].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 3) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadv: callback must be a function");
        }

        ssize_t bytesRead = ::readv(fd, iovecs.data(), static_cast<int>(iovecs.size()));
        if (bytesRead < 0) {
          auto errorMessage = fsErrorMessage(errno, "readv", "", "");
          if (hasCallback) {
            callback->call(runtime, facebook::jsi::String::createFromUtf8(runtime, errorMessage));
            return facebook::jsi::Value::undefined();
          }
          throw facebook::jsi::JSError(runtime, errorMessage.c_str());
        }

        size_t copied = 0;
        size_t remaining = static_cast<size_t>(bytesRead);
        for (size_t i = 0; i < targetMetadata.size() && remaining > 0; i++) {
          auto entry = listObj.getProperty(
              runtime, facebook::jsi::PropNameID::forAscii(runtime, std::to_string(i)));
          if (!entry.isObject()) {
            throw facebook::jsi::JSError(runtime, "__exactFsReadv: buffer entry invalid");
          }
          auto target = entry.asObject(runtime);
          auto& info = targetMetadata[i];
          size_t copyLen = info.byteLength;
          if (copyLen > remaining) copyLen = remaining;
          size_t byteOffset = info.byteOffset;
          if (target.isArrayBuffer(runtime)) {
            auto ab = target.getArrayBuffer(runtime);
            size_t available = ab.size(runtime);
            if (byteOffset + copyLen > available) {
              throw facebook::jsi::JSError(runtime, "__exactFsReadv: buffer length insufficient");
            }
            std::copy(buffers[i].data(), buffers[i].data() + copyLen, ab.data(runtime) + byteOffset);
          } else if (target.hasProperty(runtime, "buffer")) {
            auto bufferValue = target.getProperty(runtime, "buffer");
            if (bufferValue.isObject() && bufferValue.asObject(runtime).isArrayBuffer(runtime)) {
              auto ab = bufferValue.asObject(runtime).getArrayBuffer(runtime);
              size_t available = ab.size(runtime);
              if (byteOffset + copyLen > available) {
                throw facebook::jsi::JSError(runtime, "__exactFsReadv: buffer length insufficient");
              }
              std::copy(buffers[i].data(), buffers[i].data() + copyLen, ab.data(runtime) + byteOffset);
            }
          }
          remaining -= copyLen;
          copied += copyLen;
          (void)copied;
        }
        auto result = static_cast<int>(copied);
        if (hasCallback) {
          callback->call(runtime,
                        facebook::jsi::Value::undefined(),
                        facebook::jsi::Value(result),
                        args[1]);
          return facebook::jsi::Value::undefined();
        }
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactFsReadv", std::move(fsReadvFn));

  // __exactFsWritev(fd, buffers, position, callback?)
  auto fsWritevFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWritev"),
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritev: fd and buffers required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        if (!parseIoVecArguments(runtime, args[1], buffers, iovecs, nullptr)) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritev: buffers must be Uint8Array-like objects");
        }
        if (count > 2 && args[2].isNumber()) {
          double pos = args[2].asNumber();
          if (pos >= 0) {
            if (::lseek(fd, static_cast<off_t>(pos), SEEK_SET) < 0) {
              throwFsError(runtime, "writev");
            }
          }
        }
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 3 && args[3].isObject() && args[3].asObject(runtime).isFunction(runtime)) {
          callback = args[3].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 3) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritev: callback must be a function");
        }
        ssize_t bytesWritten = ::writev(fd, iovecs.data(), static_cast<int>(iovecs.size()));
        if (bytesWritten < 0) {
          normalizeWriteErrno(fd);
          auto errorMessage = fsErrorMessage(errno, "writev", "", "");
          if (hasCallback) {
            callback->call(runtime, facebook::jsi::String::createFromUtf8(runtime, errorMessage));
            return facebook::jsi::Value::undefined();
          }
          throw facebook::jsi::JSError(runtime, errorMessage.c_str());
        }
        auto result = static_cast<int>(bytesWritten);
        if (hasCallback) {
          callback->call(runtime,
                        facebook::jsi::Value::undefined(),
                        facebook::jsi::Value(result),
                        args[1]);
          return facebook::jsi::Value::undefined();
        }
        return facebook::jsi::Value(result);
      });
  rt.global().setProperty(rt, "__exactFsWritev", std::move(fsWritevFn));

  // __exactOpendir(path) -> JSON string of child names
  auto opendirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactOpendir"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactOpendir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }
        DIR* dir = ::opendir(path.c_str());
        if (!dir) {
          throwFsError(runtime, "opendir", path);
        }
        std::ostringstream entriesJson;
        entriesJson << "[";
        bool first = true;
        while (auto entry = ::readdir(dir)) {
          std::string name = entry->d_name;
          if (name == "." || name == "..") {
            continue;
          }
          if (!first) {
            entriesJson << ",";
          }
          first = false;
          entriesJson << "\""
                     << name << "\"";
        }
        ::closedir(dir);
        entriesJson << "]";
        return facebook::jsi::String::createFromUtf8(runtime, entriesJson.str());
      });
  rt.global().setProperty(rt, "__exactOpendir", std::move(opendirFn));

  // __exactSymlink(target, path) -> void
  auto symlinkFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactSymlink"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactSymlink: target and path required");
        }
        auto target = args[0].toString(runtime).utf8(runtime);
        auto path = args[1].toString(runtime).utf8(runtime);
        if (::symlink(target.c_str(), path.c_str()) != 0) {
          throwFsError(runtime, "symlink", target, path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactSymlink", std::move(symlinkFn));

  // __exactLink(existingPath, newPath) -> void
  auto linkFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLink"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactLink: existingPath and newPath required");
        }
        auto existing = args[0].toString(runtime).utf8(runtime);
        auto newp = args[1].toString(runtime).utf8(runtime);
        if (::link(existing.c_str(), newp.c_str()) != 0) {
          throwFsError(runtime, "link", existing, newp);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactLink", std::move(linkFn));

  // __exactReadlink(path) -> string
  auto readlinkFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactReadlink"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactReadlink: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        char buf[PATH_MAX];
        ssize_t len = ::readlink(path.c_str(), buf, sizeof(buf) - 1);
        if (len < 0) {
          throwFsError(runtime, "readlink", path);
        }
        buf[len] = '\0';
        return facebook::jsi::String::createFromUtf8(runtime, buf);
      });
  rt.global().setProperty(rt, "__exactReadlink", std::move(readlinkFn));

  // __exactTruncate(path, len) -> void
  auto truncateFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTruncate"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactTruncate: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        off_t len = 0;
        if (count > 1 && args[1].isNumber()) len = static_cast<off_t>(args[1].asNumber());
        if (::truncate(path.c_str(), len) != 0) {
          throwFsError(runtime, "truncate", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTruncate", std::move(truncateFn));

  // __exactChown(path, uid, gid) -> void
  auto chownFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactChown"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactChown: path, uid, gid required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        uid_t uid = static_cast<uid_t>(args[1].asNumber());
        gid_t gid = static_cast<gid_t>(args[2].asNumber());
        if (::chown(path.c_str(), uid, gid) != 0) {
          throwFsError(runtime, "chown", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactChown", std::move(chownFn));

  // __exactLchown(path, uid, gid) -> void
  auto lchownFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLchown"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactLchown: path, uid, gid required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        uid_t uid = static_cast<uid_t>(args[1].asNumber());
        gid_t gid = static_cast<gid_t>(args[2].asNumber());
        if (::lchown(path.c_str(), uid, gid) != 0) {
          throwFsError(runtime, "lchown", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactLchown", std::move(lchownFn));

  // __exactUtimes(path, atime, mtime) -> void
  auto utimesFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUtimes"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactUtimes: path, atime, mtime required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        double atimeVal = args[1].asNumber();
        double mtimeVal = args[2].asNumber();
        // Convert seconds or Date ms to timeval
        struct timeval times[2];
        if (atimeVal > 1e12) { // likely milliseconds from Date
          times[0].tv_sec = static_cast<time_t>(atimeVal / 1000.0);
          times[0].tv_usec = static_cast<suseconds_t>((static_cast<long long>(atimeVal) % 1000) * 1000);
        } else {
          times[0].tv_sec = static_cast<time_t>(atimeVal);
          times[0].tv_usec = static_cast<suseconds_t>((atimeVal - times[0].tv_sec) * 1e6);
        }
        if (mtimeVal > 1e12) {
          times[1].tv_sec = static_cast<time_t>(mtimeVal / 1000.0);
          times[1].tv_usec = static_cast<suseconds_t>((static_cast<long long>(mtimeVal) % 1000) * 1000);
        } else {
          times[1].tv_sec = static_cast<time_t>(mtimeVal);
          times[1].tv_usec = static_cast<suseconds_t>((mtimeVal - times[1].tv_sec) * 1e6);
        }
        if (::utimes(path.c_str(), times) != 0) {
          throwFsError(runtime, "utime", path);
        }
        return facebook::jsi::Value::undefined();
  });
  rt.global().setProperty(rt, "__exactUtimes", std::move(utimesFn));

  // __exactStatfs(path) -> JSON string
  auto statfsFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactStatfs"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactStatfs: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
#if defined(__linux__) && !defined(EXACT_PLATFORM_ANDROID)
        // @ref LLP 0008#filesystem — Linux statfs(2) exposes f_type; statvfs(3) does not.
        struct statfs buf;
        if (::statfs(path.c_str(), &buf) != 0) {
          throwFsError(runtime, "statfs", path);
        }
        uint64_t type = static_cast<uint64_t>(buf.f_type);
#else
        struct statvfs buf;
        if (::statvfs(path.c_str(), &buf) != 0) {
          throwFsError(runtime, "statfs", path);
        }
        uint64_t type = 0;
#endif
        std::ostringstream oss;
        oss << "{"
            << "\"type\":" << type << ","
            << "\"bsize\":" << buf.f_bsize << ","
            << "\"blocks\":" << static_cast<uint64_t>(buf.f_blocks) << ","
            << "\"bfree\":" << static_cast<uint64_t>(buf.f_bfree) << ","
            << "\"bavail\":" << static_cast<uint64_t>(buf.f_bavail) << ","
            << "\"files\":" << static_cast<uint64_t>(buf.f_files) << ","
            << "\"ffree\":" << static_cast<uint64_t>(buf.f_ffree) << "}";
        return facebook::jsi::String::createFromUtf8(runtime, oss.str());
      });
  rt.global().setProperty(rt, "__exactStatfs", std::move(statfsFn));

  auto parseTimeFromDouble = [](double value) -> struct timespec {
    struct timespec ts;
    if (value > 1e12) {
      ts.tv_sec = static_cast<time_t>(value / 1000.0);
      ts.tv_nsec = static_cast<long>((static_cast<long long>(value) % 1000) * 1000000);
    } else {
      ts.tv_sec = static_cast<time_t>(value);
      ts.tv_nsec = static_cast<long>((value - ts.tv_sec) * 1e9);
    }
    if (ts.tv_nsec < 0) ts.tv_nsec = 0;
    return ts;
  };

  // __exactLutimes(path, atime, mtime) -> void (does not follow symlinks)
  auto lUtimesBody = [parseTimeFromDouble](facebook::jsi::Runtime& runtime,
      const facebook::jsi::Value* args, size_t count) -> void {
    if (count < 3 || !args[0].isString()) {
      throw facebook::jsi::JSError(runtime, "__exactLutimes: path, atime, mtime required");
    }
    auto path = args[0].toString(runtime).utf8(runtime);
    double atimeVal = args[1].asNumber();
    double mtimeVal = args[2].asNumber();
    struct timespec times[2];
    times[0] = parseTimeFromDouble(atimeVal);
    times[1] = parseTimeFromDouble(mtimeVal);

#if defined(__APPLE__)
    struct timeval tv[2];
    tv[0].tv_sec = times[0].tv_sec;
    tv[0].tv_usec = times[0].tv_nsec / 1000;
    tv[1].tv_sec = times[1].tv_sec;
    tv[1].tv_usec = times[1].tv_nsec / 1000;
    if (::lutimes(path.c_str(), tv) != 0) {
      throwFsError(runtime, "lutimes", path);
    }
#else
    if (::utimensat(AT_FDCWD, path.c_str(), times, AT_SYMLINK_NOFOLLOW) != 0) {
      throwFsError(runtime, "lutimes", path);
    }
#endif
  };

  auto lutimesFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLutimes"), 3,
      [lUtimesBody](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                    const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        lUtimesBody(runtime, args, count);
        return facebook::jsi::Value::undefined();
      });
  auto lUtimesSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLutimesSync"), 3,
      [lUtimesBody](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                    const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        lUtimesBody(runtime, args, count);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactLutimes", std::move(lutimesFn));
  rt.global().setProperty(rt, "__exactLutimesSync", std::move(lUtimesSyncFn));

  // __exactLchmod(path, mode) -> void
  auto lchmodBody = [](facebook::jsi::Runtime& runtime,
                       const facebook::jsi::Value* args, size_t count) -> void {
    if (count < 2 || !args[0].isString()) {
      throw facebook::jsi::JSError(runtime, "__exactLchmod: path and mode required");
    }
    auto path = args[0].toString(runtime).utf8(runtime);
    mode_t mode = static_cast<mode_t>(args[1].asNumber());
#if defined(__APPLE__)
    if (::lchmod(path.c_str(), mode) != 0) {
      throwFsError(runtime, "lchmod", path);
    }
#else
    errno = ENOSYS;
    throwFsError(runtime, "lchmod", path);
#endif
  };

  auto lchmodFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLchmod"), 2,
      [lchmodBody](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                   const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        lchmodBody(runtime, args, count);
        return facebook::jsi::Value::undefined();
      });
  auto lchmodSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactLchmodSync"), 2,
      [lchmodBody](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                   const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        lchmodBody(runtime, args, count);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactLchmod", std::move(lchmodFn));
  rt.global().setProperty(rt, "__exactLchmodSync", std::move(lchmodSyncFn));

  // __exactFsFtruncateSync(fd, len) -> void
  auto ftruncateSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFtruncateSync"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFtruncateSync: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        off_t len = 0;
        if (count > 1 && args[1].isNumber()) len = static_cast<off_t>(args[1].asNumber());
        if (::ftruncate(fd, len) != 0) {
          throwFsError(runtime, "ftruncate", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFtruncateSync", std::move(ftruncateSyncFn));

  // __exactFsFstatSync(fd) -> JSON string (same format as __exactStat)
  auto fstatSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFstatSync"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFstatSync: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        struct stat sb;
        if (::fstat(fd, &sb) != 0) {
          throwFsError(runtime, "fstat", "");
        }
        std::ostringstream oss;
        oss << "{\"size\":" << sb.st_size
            << ",\"mode\":" << sb.st_mode
            << ",\"dev\":" << sb.st_dev
            << ",\"ino\":" << sb.st_ino
            << ",\"nlink\":" << sb.st_nlink
            << ",\"uid\":" << sb.st_uid
            << ",\"gid\":" << sb.st_gid
            << ",\"rdev\":" << sb.st_rdev
            << ",\"blksize\":" << sb.st_blksize
            << ",\"blocks\":" << sb.st_blocks
            << ",\"is_file\":" << (S_ISREG(sb.st_mode) ? "true" : "false")
            << ",\"is_dir\":" << (S_ISDIR(sb.st_mode) ? "true" : "false")
            << ",\"is_symlink\":" << (S_ISLNK(sb.st_mode) ? "true" : "false")
            << ",\"is_char_device\":" << (S_ISCHR(sb.st_mode) ? "true" : "false")
            << ",\"is_block_device\":" << (S_ISBLK(sb.st_mode) ? "true" : "false")
            << ",\"is_fifo\":" << (S_ISFIFO(sb.st_mode) ? "true" : "false")
            << ",\"is_socket\":" << (S_ISSOCK(sb.st_mode) ? "true" : "false");
#if defined(__APPLE__)
        double mtime_ms = sb.st_mtimespec.tv_sec * 1000.0 + sb.st_mtimespec.tv_nsec / 1e6;
        double atime_ms = sb.st_atimespec.tv_sec * 1000.0 + sb.st_atimespec.tv_nsec / 1e6;
        double ctime_ms = sb.st_ctimespec.tv_sec * 1000.0 + sb.st_ctimespec.tv_nsec / 1e6;
        double birthtime_ms = sb.st_birthtimespec.tv_sec * 1000.0 + sb.st_birthtimespec.tv_nsec / 1e6;
        long long atime_ns = sb.st_atimespec.tv_sec * 1000000000LL + sb.st_atimespec.tv_nsec;
        long long mtime_ns = sb.st_mtimespec.tv_sec * 1000000000LL + sb.st_mtimespec.tv_nsec;
        long long ctime_ns = sb.st_ctimespec.tv_sec * 1000000000LL + sb.st_ctimespec.tv_nsec;
        long long birthtime_ns = sb.st_birthtimespec.tv_sec * 1000000000LL + sb.st_birthtimespec.tv_nsec;
#else
        double mtime_ms = sb.st_mtim.tv_sec * 1000.0 + sb.st_mtim.tv_nsec / 1e6;
        double atime_ms = sb.st_atim.tv_sec * 1000.0 + sb.st_atim.tv_nsec / 1e6;
        double ctime_ms = sb.st_ctim.tv_sec * 1000.0 + sb.st_ctim.tv_nsec / 1e6;
        double birthtime_ms = ctime_ms;
        long long atime_ns = sb.st_atim.tv_sec * 1000000000LL + sb.st_atim.tv_nsec;
        long long mtime_ns = sb.st_mtim.tv_sec * 1000000000LL + sb.st_mtim.tv_nsec;
        long long ctime_ns = sb.st_ctim.tv_sec * 1000000000LL + sb.st_ctim.tv_nsec;
        long long birthtime_ns = ctime_ns;
#endif
        oss << ",\"mtime_ms\":" << std::fixed << std::setprecision(3) << mtime_ms
            << ",\"atime_ms\":" << std::fixed << std::setprecision(3) << atime_ms
            << ",\"ctime_ms\":" << std::fixed << std::setprecision(3) << ctime_ms
            << ",\"birthtime_ms\":" << std::fixed << std::setprecision(3) << birthtime_ms
            << ",\"atime_ns\":" << atime_ns
            << ",\"mtime_ns\":" << mtime_ns
            << ",\"ctime_ns\":" << ctime_ns
            << ",\"birthtime_ns\":" << birthtime_ns
            << "}";
        return facebook::jsi::String::createFromUtf8(runtime, oss.str());
      });
  rt.global().setProperty(rt, "__exactFsFstatSync", std::move(fstatSyncFn));

  // __exactFsFsyncSync(fd) -> void
  auto fsyncSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFsyncSync"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFsyncSync: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        if (::fsync(fd) != 0) {
          throwFsError(runtime, "fsync", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFsyncSync", std::move(fsyncSyncFn));

  // __exactFsFdatasyncSync(fd) -> void
  auto fdatasyncSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFdatasyncSync"), 1,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFdatasyncSync: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
#if defined(__APPLE__)
        // macOS doesn't have fdatasync, use fsync instead
        if (::fsync(fd) != 0) {
#else
        if (::fdatasync(fd) != 0) {
#endif
          throwFsError(runtime, "fdatasync", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFdatasyncSync", std::move(fdatasyncSyncFn));

  // __exactFsFchmod(fd, mode, callback?)
  auto fchmodFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFchmod"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchmod: fd and mode required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        mode_t mode = static_cast<mode_t>(args[1].asNumber());
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 2 && args[2].isObject() && args[2].asObject(runtime).isFunction(runtime)) {
          callback = args[2].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 2) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchmod: callback must be a function");
        }
        if (::fchmod(fd, mode) != 0) {
          auto errorMessage = fsErrorMessage(errno, "fchmod", "");
          if (hasCallback) {
            callback->call(runtime, facebook::jsi::String::createFromUtf8(runtime, errorMessage));
            return facebook::jsi::Value::undefined();
          }
          throwFsError(runtime, "fchmod", "");
        }
        if (hasCallback) {
          callback->call(runtime, facebook::jsi::Value::undefined());
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFchmod", std::move(fchmodFn));

  // __exactFsFchown(fd, uid, gid, callback?)
  auto fchownFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFchown"), 4,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchown: fd, uid, gid required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        uid_t uid = static_cast<uid_t>(args[1].asNumber());
        gid_t gid = static_cast<gid_t>(args[2].asNumber());
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 3 && args[3].isObject() && args[3].asObject(runtime).isFunction(runtime)) {
          callback = args[3].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 3) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchown: callback must be a function");
        }
        if (::fchown(fd, uid, gid) != 0) {
          auto errorMessage = fsErrorMessage(errno, "fchown", "");
          if (hasCallback) {
            callback->call(runtime, facebook::jsi::String::createFromUtf8(runtime, errorMessage));
            return facebook::jsi::Value::undefined();
          }
          throwFsError(runtime, "fchown", "");
        }
        if (hasCallback) {
          callback->call(runtime, facebook::jsi::Value::undefined());
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFchown", std::move(fchownFn));

  // __exactFsFchmodSync(fd, mode) -> void
  auto fchmodSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFchmodSync"), 2,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchmodSync: fd and mode required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        mode_t mode = static_cast<mode_t>(args[1].asNumber());
        if (::fchmod(fd, mode) != 0) {
          throwFsError(runtime, "fchmod", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFchmodSync", std::move(fchmodSyncFn));

  // __exactFsFchownSync(fd, uid, gid) -> void
  auto fchownSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFchownSync"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFchownSync: fd, uid, gid required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        uid_t uid = static_cast<uid_t>(args[1].asNumber());
        gid_t gid = static_cast<gid_t>(args[2].asNumber());
        if (::fchown(fd, uid, gid) != 0) {
          throwFsError(runtime, "fchown", "");
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFchownSync", std::move(fchownSyncFn));

  // __exactFsFutimesSync(fd, atime, mtime) -> void
  auto futimesSyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFutimesSync"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFutimesSync: fd, atime, mtime required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        double atimeVal = args[1].asNumber();
        double mtimeVal = args[2].asNumber();
        struct timeval times[2];
        if (atimeVal > 1e12) {
          times[0].tv_sec = static_cast<time_t>(atimeVal / 1000.0);
          times[0].tv_usec = static_cast<suseconds_t>((static_cast<long long>(atimeVal) % 1000) * 1000);
        } else {
          times[0].tv_sec = static_cast<time_t>(atimeVal);
          times[0].tv_usec = static_cast<suseconds_t>((atimeVal - times[0].tv_sec) * 1e6);
        }
        if (mtimeVal > 1e12) {
          times[1].tv_sec = static_cast<time_t>(mtimeVal / 1000.0);
          times[1].tv_usec = static_cast<suseconds_t>((static_cast<long long>(mtimeVal) % 1000) * 1000);
        } else {
          times[1].tv_sec = static_cast<time_t>(mtimeVal);
          times[1].tv_usec = static_cast<suseconds_t>((mtimeVal - times[1].tv_sec) * 1e6);
        }
#if defined(EXACT_PLATFORM_ANDROID)
        struct timespec ts[2] = {
            {times[0].tv_sec, static_cast<long>(times[0].tv_usec) * 1000},
            {times[1].tv_sec, static_cast<long>(times[1].tv_usec) * 1000},
        };
        if (::futimens(fd, ts) != 0) {
          throwFsError(runtime, "futimens", "");
        }
#else
        if (::futimes(fd, times) != 0) {
          throwFsError(runtime, "futimes", "");
        }
#endif
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFutimesSync", std::move(futimesSyncFn));

}
