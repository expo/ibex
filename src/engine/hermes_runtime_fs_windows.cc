#include "hermes_runtime_internal.h"

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint32_t EXACT_FS_READ = 1;
constexpr uint32_t EXACT_FS_WRITE = 2;
constexpr uint32_t EXACT_FS_CREATE = 4;
constexpr uint32_t EXACT_FS_TRUNCATE = 8;
constexpr uint32_t EXACT_FS_APPEND = 16;

constexpr int NODE_O_WRONLY = 1;
constexpr int NODE_O_RDWR = 2;
constexpr int NODE_O_APPEND = 8;
constexpr int NODE_O_CREAT = 512;
constexpr int NODE_O_TRUNC = 1024;

extern "C" void ex_host_fs_close(void* file);
extern "C" int32_t ex_host_fs_last_error();

struct WindowsFileHandle {
  explicit WindowsFileHandle(void* file) : handle(file) {}
  ~WindowsFileHandle() {
    if (handle) {
      ex_host_fs_close(handle);
    }
  }
  WindowsFileHandle(const WindowsFileHandle&) = delete;
  WindowsFileHandle& operator=(const WindowsFileHandle&) = delete;
  void* handle = nullptr;
  std::mutex ioMutex;
};

struct FileEntry {
  std::shared_ptr<WindowsFileHandle> file;
  std::string path;
  bool append = false;
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
  bool canRead = false;
  bool canWrite = false;
};

// g_files_mutex only guards the fd -> FileEntry lookup/insert/erase below. Each
// WindowsFileHandle carries its own I/O mutex because the async fs bridge can
// now use the same fd from worker threads while sync calls still run on the JS
// thread. The Rust-backed pread/pwrite shims are save-cursor/seek/op/restore
// sequences on one opaque handle, so same-fd I/O must be serialized to preserve
// Node's cursor semantics. (ENG-23042 finding 2, ENG-23541)
std::mutex g_files_mutex;
std::unordered_map<int, FileEntry> g_files;
int g_next_fd = 3;
thread_local const std::vector<uint64_t>* g_typed_principal_stack = nullptr;

extern "C" void* ex_host_fs_open(const char* path, uint32_t flags);
extern "C" int32_t ex_host_fs_read(void* file, uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_write(void* file, const uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_seek(void* file, uint64_t position);
// Positional read/write that do NOT move the handle's cursor (pread/pwrite
// equivalents; ENG-22993, porting the POSIX fix in ENG-22982). Node's
// readSync/writeSync leave the fd offset unchanged when `position` is a number.
extern "C" int32_t ex_host_fs_pread(void* file, uint8_t* buf, uint32_t len, uint64_t offset);
extern "C" int32_t ex_host_fs_pwrite(void* file, const uint8_t* buf, uint32_t len, uint64_t offset);
extern "C" int32_t ex_host_fs_sync(void* file, int32_t dataOnly);
extern "C" char* ex_host_fs_fstat(void* file);
extern "C" uint8_t* ex_host_fs_read_file(const char* path, uint64_t* out_len, int32_t* out_errno);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint64_t len);
extern "C" char* ex_host_fs_stat(const char* path);
extern "C" char* ex_host_fs_lstat(const char* path);
extern "C" char* ex_host_fs_readdir(const char* path);
extern "C" int32_t ex_host_fs_mkdir(const char* path, int32_t recursive);
extern "C" char* ex_host_fs_mkdir_recursive_result(const char* path);
extern "C" int32_t ex_host_fs_rmdir(const char* path);
extern "C" int32_t ex_host_fs_unlink(const char* path);
extern "C" int32_t ex_host_fs_rename(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy_exclusive(const char* from, const char* to);
extern "C" int32_t ex_host_fs_truncate(const char* path, uint64_t len);
extern "C" int32_t ex_host_fs_utimes(const char* path, double atime, double mtime);
extern "C" char* ex_host_fs_statfs(const char* path);
extern "C" char* ex_host_fs_realpath(const char* path);
extern "C" int32_t ex_host_fs_access(const char* path, int32_t mode);
extern "C" int32_t ex_host_fs_chmod(const char* path, uint32_t mode);
extern "C" char* ex_host_fs_mkdtemp(const char* prefix, uint64_t module_id);
extern "C" void ex_host_free_string(char* value);

std::string pathArg(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value) {
  return value.toString(runtime).utf8(runtime);
}

const char* fsErrorCode(int32_t error) {
  switch (error) {
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case EEXIST: return "EEXIST";
    case EINVAL: return "EINVAL";
    case EBADF: return "EBADF";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case ENOTEMPTY: return "ENOTEMPTY";
    case ENOSPC: return "ENOSPC";
    case EXDEV: return "EXDEV";
    case EMFILE: return "EMFILE";
    case EROFS: return "EROFS";
    case EBUSY: return "EBUSY";
    case ENOSYS: return "ENOSYS";
    default: return "EIO";
  }
}

const char* fsErrorDescription(int32_t error) {
  switch (error) {
    case ENOENT: return "no such file or directory";
    case EACCES: return "permission denied";
    case EEXIST: return "file already exists";
    case EINVAL: return "invalid argument";
    case EBADF: return "bad file descriptor";
    case ENOTDIR: return "not a directory";
    case EISDIR: return "illegal operation on a directory";
    case ENOTEMPTY: return "directory not empty";
    case ENOSPC: return "no space left on device";
    case EXDEV: return "cross-device link not permitted";
    case EMFILE: return "too many open files";
    case EROFS: return "read-only file system";
    case EBUSY: return "resource busy or locked";
    case ENOSYS: return "function not implemented";
    default: return "I/O error";
  }
}

std::string fsErrorMessage(
    const std::string& syscall,
    const std::string& path,
    int32_t error = 0) {
  if (error == 0) {
    error = ex_host_fs_last_error();
  }
  std::string message = std::string(fsErrorCode(error)) + ": " +
      fsErrorDescription(error) + ", " + syscall;
  if (!path.empty()) {
    message += " '" + path + "'";
  }
  return message;
}

void throwFs(facebook::jsi::Runtime& runtime, const std::string& syscall, const std::string& path) {
  throw facebook::jsi::JSError(runtime, fsErrorMessage(syscall, path));
}

void requireCapability(
    facebook::jsi::Runtime& runtime,
    const char* capability,
    const std::string& path) {
  if (isAllowAll()) {
    return;
  }
  std::string cap = std::string(capability) + ":" + path;
  if (!checkCapability(cap)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

void requireReadCapability(facebook::jsi::Runtime& runtime, const std::string& path) {
  requireCapability(runtime, "fs:read", path);
}

void requireWriteCapability(facebook::jsi::Runtime& runtime, const std::string& path) {
  requireCapability(runtime, "fs:write", path);
}

uint32_t hostFlagsFromNodeFlags(int flags) {
  uint32_t host_flags = 0;
  if ((flags & NODE_O_RDWR) == NODE_O_RDWR) {
    host_flags |= EXACT_FS_READ | EXACT_FS_WRITE;
  } else if ((flags & NODE_O_WRONLY) == NODE_O_WRONLY) {
    host_flags |= EXACT_FS_WRITE;
  } else {
    host_flags |= EXACT_FS_READ;
  }
  if ((flags & NODE_O_CREAT) == NODE_O_CREAT) {
    host_flags |= EXACT_FS_CREATE;
  }
  if ((flags & NODE_O_TRUNC) == NODE_O_TRUNC) {
    host_flags |= EXACT_FS_TRUNCATE;
  }
  if ((flags & NODE_O_APPEND) == NODE_O_APPEND) {
    host_flags |= EXACT_FS_APPEND;
  }
  return host_flags;
}

int fdFromValue(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, "file descriptor must be a number");
  }
  return static_cast<int>(value.asNumber());
}

void* fileHandle(const FileEntry& entry) {
  return entry.file ? entry.file->handle : nullptr;
}

FileEntry getFileEntry(facebook::jsi::Runtime& runtime, int fd) {
  std::lock_guard<std::mutex> lock(g_files_mutex);
  auto it = g_files.find(fd);
  if (it == g_files.end() || !fileHandle(it->second)) {
    throw facebook::jsi::JSError(runtime, "bad file descriptor");
  }
  if (it->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      (!isAllowAll() && it->second.owner != currentPrincipalId())) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  return it->second;
}

void requireFileEntryRead(facebook::jsi::Runtime& runtime, const FileEntry& entry) {
  if (isAllowAll()) {
    return;
  }
  if (!entry.canRead) {
    throw facebook::jsi::JSError(runtime, "fd not opened for reading");
  }
  requireReadCapability(runtime, entry.path);
}

void requireFileEntryWrite(facebook::jsi::Runtime& runtime, const FileEntry& entry) {
  if (isAllowAll()) {
    return;
  }
  if (!entry.canWrite) {
    throw facebook::jsi::JSError(runtime, "fd not opened for writing");
  }
  requireWriteCapability(runtime, entry.path);
}

facebook::jsi::Value jsonStringResult(
    facebook::jsi::Runtime& runtime,
    char* value,
    const std::string& syscall,
    const std::string& path) {
  if (!value) {
    throwFs(runtime, syscall, path);
  }
  auto result = facebook::jsi::String::createFromUtf8(runtime, value);
  ex_host_free_string(value);
  return result;
}

facebook::jsi::Function unaryPathJsonFunction(
    facebook::jsi::Runtime& rt,
    const char* name,
    const char* syscall,
    char* (*host_fn)(const char*)) {
  return facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, name),
      1,
      [name, syscall, host_fn](
          facebook::jsi::Runtime& runtime,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, std::string(name) + ": path required");
        }
        auto path = pathArg(runtime, args[0]);
        requireReadCapability(runtime, path);
        return jsonStringResult(runtime, host_fn(path.c_str()), syscall, path);
      });
}

struct FsAsyncResult {
  enum class Kind { Undefined, Bytes, Json, Number };
  bool ok = false;
  Kind kind = Kind::Undefined;
  std::vector<uint8_t> bytes;
  std::string json;
  double number = 0;
  std::string code;
  std::string message;
  std::string syscall;
  std::string path;
  bool tooLarge = false;
  double tooLargeSize = 0;
};

constexpr double kMaxReadFileBytes = 2147483647.0;
constexpr uint32_t kMaxHostIoChunk = 0x7FFFFFFFu;

FsAsyncResult fsAsyncOk(FsAsyncResult::Kind kind = FsAsyncResult::Kind::Undefined) {
  FsAsyncResult result;
  result.ok = true;
  result.kind = kind;
  return result;
}

FsAsyncResult fsAsyncError(
    std::string code,
    std::string message,
    std::string syscall,
    std::string path = "") {
  FsAsyncResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  result.syscall = std::move(syscall);
  result.path = std::move(path);
  return result;
}

FsAsyncResult fsAsyncSyscallError(
    const std::string& syscall,
    const std::string& path = "",
    int32_t error = 0) {
  if (error == 0) {
    error = ex_host_fs_last_error();
  }
  return fsAsyncError(
      fsErrorCode(error), fsErrorMessage(syscall, path, error), syscall, path);
}

FsAsyncResult fsAsyncBadFd(const std::string& syscall) {
  return fsAsyncError("EBADF", "EBADF: bad file descriptor, " + syscall, syscall);
}

FsAsyncResult fsAsyncUnsupported(const std::string& syscall, const std::string& path = "") {
  return fsAsyncError(
      "ENOSYS",
      "ENOSYS: function not implemented, " + syscall + (path.empty() ? "" : " '" + path + "'"),
      syscall,
      path);
}

class FsWorkerPool {
 public:
  static FsWorkerPool& instance() {
    static FsWorkerPool* pool = new FsWorkerPool();
    return *pool;
  }

  bool enqueue(std::function<void()> job, std::string& error) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (queue_.size() >= kMaxQueue) {
        error = "FS worker queue full";
        return false;
      }
      spawnWorkerIfNeededLocked();
      queue_.push_back(std::move(job));
    }
    cv_.notify_one();
    return true;
  }

 private:
  static constexpr size_t kMaxWorkers = 8;
  static constexpr size_t kMaxQueue = 1024;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  size_t idle_ = 0;
  size_t total_ = 0;

  void spawnWorkerIfNeededLocked() {
    if (idle_ > 0 || total_ >= kMaxWorkers) {
      return;
    }
    total_ += 1;
    std::thread([this]() {
      for (;;) {
        std::function<void()> job;
        {
          std::unique_lock<std::mutex> lock(mutex_);
          idle_ += 1;
          cv_.wait(lock, [this] { return !queue_.empty(); });
          idle_ -= 1;
          job = std::move(queue_.front());
          queue_.pop_front();
        }
        job();
      }
    }).detach();
  }
};

facebook::jsi::Value makeFsAsyncErrorValue(
    facebook::jsi::Runtime& rt,
    const FsAsyncResult& result) {
  if (result.tooLarge) {
    std::ostringstream oss;
    oss << "File size (" << static_cast<long long>(result.tooLargeSize)
        << ") is greater than 2 GiB";
    facebook::jsi::JSError jsError(rt, oss.str());
    facebook::jsi::Value err(rt, jsError.value());
    auto obj = err.asObject(rt);
    obj.setProperty(
        rt, "code", facebook::jsi::String::createFromUtf8(rt, "ERR_FS_FILE_TOO_LARGE"));
    obj.setProperty(rt, "size", facebook::jsi::Value(result.tooLargeSize));
    return err;
  }
  facebook::jsi::JSError jsError(rt, result.message.empty() ? "fs async failed" : result.message);
  facebook::jsi::Value err(rt, jsError.value());
  auto obj = err.asObject(rt);
  if (!result.code.empty()) {
    obj.setProperty(rt, "code", facebook::jsi::String::createFromUtf8(rt, result.code));
  }
  if (!result.syscall.empty()) {
    obj.setProperty(rt, "syscall", facebook::jsi::String::createFromUtf8(rt, result.syscall));
  }
  if (!result.path.empty()) {
    obj.setProperty(rt, "path", facebook::jsi::String::createFromUtf8(rt, result.path));
  }
  return err;
}

facebook::jsi::Value startFsAsync(
    ExactHermesRuntime* handle,
    facebook::jsi::Runtime& runtime,
    std::function<FsAsyncResult()> work) {
  uint64_t principal = currentPrincipalId();
  auto principalStack =
      std::make_shared<std::vector<uint64_t>>(exactCollectTypedPrincipalStack());
  auto workPtr = std::make_shared<std::function<FsAsyncResult()>>(std::move(work));
  auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
  auto executor = facebook::jsi::Function::createFromHostFunction(
      runtime,
      facebook::jsi::PropNameID::forAscii(runtime, "executor"),
      2,
      [handle, principal, principalStack, workPtr](
          facebook::jsi::Runtime& rt,
          const facebook::jsi::Value&,
          const facebook::jsi::Value* args,
          size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isObject() || !args[1].isObject()) {
          throw facebook::jsi::JSError(rt, "FS async: malformed executor invocation");
        }
        auto resolve =
            std::make_shared<facebook::jsi::Function>(args[0].asObject(rt).asFunction(rt));
        auto reject =
            std::make_shared<facebook::jsi::Function>(args[1].asObject(rt).asFunction(rt));
        handle->pending_fs_ops.fetch_add(1, std::memory_order_relaxed);

        std::string enqueueError;
        bool queued = FsWorkerPool::instance().enqueue(
            [handle, principal, principalStack, workPtr, resolve, reject]() mutable {
              ScopedRuntimeSecurityContext securityContext(handle);
              ScopedTypedPrincipalStack typedStack(*principalStack);
              std::shared_ptr<FsAsyncResult> resultPtr;
              try {
                resultPtr = std::make_shared<FsAsyncResult>((*workPtr)());
              } catch (const std::exception& error) {
                resultPtr = std::make_shared<FsAsyncResult>(fsAsyncError(
                    "EIO", std::string("filesystem worker failed: ") + error.what(), "fs"));
              } catch (...) {
                resultPtr = std::make_shared<FsAsyncResult>(
                    fsAsyncError("EIO", "filesystem worker failed", "fs"));
              }
              *workPtr = {};
              auto runtimeResolve = std::move(resolve);
              auto runtimeReject = std::move(reject);
              pushRuntimeCallback(
                  handle,
                  [handle, principal, resolve = std::move(runtimeResolve),
                   reject = std::move(runtimeReject), resultPtr](
                      facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    handle->pending_fs_ops.fetch_sub(1, std::memory_order_relaxed);
                    try {
                      if (resultPtr->ok) {
                        switch (resultPtr->kind) {
                          case FsAsyncResult::Kind::Bytes:
                            resolve->call(rt, makeUint8Array(rt, std::move(resultPtr->bytes)));
                            break;
                          case FsAsyncResult::Kind::Json:
                            resolve->call(
                                rt,
                                facebook::jsi::String::createFromUtf8(rt, resultPtr->json));
                            break;
                          case FsAsyncResult::Kind::Number:
                            resolve->call(rt, facebook::jsi::Value(resultPtr->number));
                            break;
                          default:
                            resolve->call(rt, facebook::jsi::Value::undefined());
                            break;
                        }
                      } else {
                        reject->call(rt, makeFsAsyncErrorValue(rt, *resultPtr));
                      }
                    } catch (const facebook::jsi::JSError& deliveryError) {
                      try {
                        reject->call(rt, deliveryError.value());
                      } catch (const facebook::jsi::JSError& rejectionError) {
                        disposeAsyncCallbackError(handle, rejectionError);
                      }
                    } catch (const std::exception& deliveryError) {
                      try {
                        facebook::jsi::JSError jsError(rt, deliveryError.what());
                        reject->call(rt, jsError.value());
                      } catch (const facebook::jsi::JSError& rejectionError) {
                        disposeAsyncCallbackError(handle, rejectionError);
                      }
                    } catch (...) {
                      try {
                        facebook::jsi::JSError jsError(
                            rt, "filesystem result delivery failed");
                        reject->call(rt, jsError.value());
                      } catch (const facebook::jsi::JSError& rejectionError) {
                        disposeAsyncCallbackError(handle, rejectionError);
                      }
                    }
                  });
            },
            enqueueError);
        if (!queued) {
          handle->pending_fs_ops.fetch_sub(1, std::memory_order_relaxed);
          // A rejected Promise can retain its executor. Clear the unqueued
          // callable so any owned native resources are released immediately.
          *workPtr = {};
          auto queueError = fsAsyncError(
              "ERR_FS_WORKER_QUEUE_FULL", enqueueError, "fs");
          reject->call(rt, makeFsAsyncErrorValue(rt, queueError));
        }
        return facebook::jsi::Value::undefined();
      });
  return promiseCtor.callAsConstructor(runtime, executor);
}

FsAsyncResult fsReadWholeHandleWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& pathForError) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("read");
  }
  std::vector<uint8_t> data;
  uint8_t buf[65536];
  for (;;) {
    int32_t bytesRead;
    {
      std::lock_guard<std::mutex> ioLock(file->ioMutex);
      bytesRead = ex_host_fs_read(file->handle, buf, sizeof(buf));
    }
    if (bytesRead < 0) {
      return fsAsyncSyscallError("read", pathForError);
    }
    if (bytesRead == 0) {
      break;
    }
    data.insert(data.end(), buf, buf + bytesRead);
    if (static_cast<double>(data.size()) > kMaxReadFileBytes) {
      FsAsyncResult result;
      result.tooLarge = true;
      result.tooLargeSize = static_cast<double>(data.size());
      return result;
    }
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(data);
  return result;
}

FsAsyncResult fsReadFilePathWork(const std::string& path) {
  uint64_t len = 0;
  int32_t readErrno = 0;
  uint8_t* data = ex_host_fs_read_file(path.c_str(), &len, &readErrno);
  if (!data) {
    return fsAsyncSyscallError("open", path, readErrno);
  }
  if (static_cast<double>(len) > kMaxReadFileBytes) {
    ex_host_free_buffer(data, len);
    FsAsyncResult result;
    result.tooLarge = true;
    result.tooLargeSize = static_cast<double>(len);
    return result;
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes.assign(data, data + len);
  ex_host_free_buffer(data, len);
  return result;
}

FsAsyncResult fsWriteAllHandleWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& path,
    const std::vector<uint8_t>& bytes,
    bool flush) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("write");
  }
  size_t totalWritten = 0;
  while (totalWritten < bytes.size()) {
    size_t remaining = bytes.size() - totalWritten;
    uint32_t chunk = remaining > kMaxHostIoChunk
        ? kMaxHostIoChunk
        : static_cast<uint32_t>(remaining);
    // Append is an open-handle property (EXACT_FS_APPEND), so the same call
    // preserves fd identity across rename/unlink and lets the OS serialize
    // concurrent appenders atomically. Reopening by path here violated both.
    int32_t written;
    {
      std::lock_guard<std::mutex> ioLock(file->ioMutex);
      written = ex_host_fs_write(
          file->handle, bytes.data() + totalWritten, chunk);
    }
    if (written <= 0) {
      return fsAsyncSyscallError("write", path);
    }
    totalWritten += static_cast<size_t>(written);
  }
  if (flush) {
    int32_t syncResult;
    {
      std::lock_guard<std::mutex> ioLock(file->ioMutex);
      syncResult = ex_host_fs_sync(file->handle, 0);
    }
    if (syncResult != 0) {
      return fsAsyncSyscallError("fsync", path);
    }
  }
  return fsAsyncOk();
}

FsAsyncResult fsWriteFilePathWork(
    const std::string& path,
    const std::vector<uint8_t>& bytes,
    int nodeFlags,
    bool flush) {
  void* rawFile = ex_host_fs_open(path.c_str(), hostFlagsFromNodeFlags(nodeFlags));
  if (!rawFile) {
    return fsAsyncSyscallError("open", path);
  }
  auto file = std::make_shared<WindowsFileHandle>(rawFile);
  return fsWriteAllHandleWork(file, path, bytes, flush);
}

FsAsyncResult fsReadChunkWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& path,
    size_t length,
    bool positioned,
    int64_t position) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("read");
  }
  if (length == 0) {
    return fsAsyncOk(FsAsyncResult::Kind::Bytes);
  }
  std::lock_guard<std::mutex> ioLock(file->ioMutex);
  std::vector<uint8_t> data(length);
  int32_t bytesRead = positioned
      ? ex_host_fs_pread(
            file->handle, data.data(), static_cast<uint32_t>(length),
            static_cast<uint64_t>(position))
      : ex_host_fs_read(file->handle, data.data(), static_cast<uint32_t>(length));
  if (bytesRead < 0) {
    return fsAsyncSyscallError("read", path);
  }
  data.resize(static_cast<size_t>(bytesRead));
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(data);
  return result;
}

FsAsyncResult fsWriteChunkWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& path,
    bool append,
    const std::vector<uint8_t>& bytes,
    bool positioned,
    int64_t position) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("write");
  }
  if (bytes.empty()) {
    auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
    result.number = 0;
    return result;
  }
  std::lock_guard<std::mutex> ioLock(file->ioMutex);
  int32_t written = append
      ? ex_host_fs_write(file->handle, bytes.data(), static_cast<uint32_t>(bytes.size()))
      : (positioned
             ? ex_host_fs_pwrite(
                   file->handle, bytes.data(), static_cast<uint32_t>(bytes.size()),
                   static_cast<uint64_t>(position))
             : ex_host_fs_write(file->handle, bytes.data(), static_cast<uint32_t>(bytes.size())));
  if (written < 0) {
    return fsAsyncSyscallError("write", path);
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = static_cast<double>(written);
  return result;
}

FsAsyncResult fsReadvWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& path,
    std::vector<std::vector<uint8_t>>& buffers,
    bool positioned,
    int64_t position) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("readv");
  }
  std::lock_guard<std::mutex> ioLock(file->ioMutex);
  std::vector<uint8_t> out;
  size_t bytesReadTotal = 0;
  for (auto& buffer : buffers) {
    if (buffer.empty()) {
      continue;
    }
    int64_t currentPosition = positioned ? position + static_cast<int64_t>(bytesReadTotal) : -1;
    int32_t bytesRead = currentPosition >= 0
        ? ex_host_fs_pread(
              file->handle, buffer.data(), static_cast<uint32_t>(buffer.size()),
              static_cast<uint64_t>(currentPosition))
        : ex_host_fs_read(file->handle, buffer.data(), static_cast<uint32_t>(buffer.size()));
    if (bytesRead < 0) {
      return fsAsyncSyscallError("readv", path);
    }
    if (bytesRead == 0) {
      break;
    }
    out.insert(out.end(), buffer.begin(), buffer.begin() + bytesRead);
    bytesReadTotal += static_cast<size_t>(bytesRead);
    if (static_cast<size_t>(bytesRead) < buffer.size()) {
      break;
    }
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(out);
  return result;
}

FsAsyncResult fsWritevWork(
    std::shared_ptr<WindowsFileHandle> file,
    const std::string& path,
    bool append,
    std::vector<std::vector<uint8_t>>& buffers,
    bool positioned,
    int64_t position) {
  if (!file || !file->handle) {
    return fsAsyncBadFd("writev");
  }
  std::lock_guard<std::mutex> ioLock(file->ioMutex);
  size_t bytesWrittenTotal = 0;
  for (auto& buffer : buffers) {
    if (buffer.empty()) {
      continue;
    }
    int64_t currentPosition =
        positioned ? position + static_cast<int64_t>(bytesWrittenTotal) : -1;
    int32_t written = append
        ? ex_host_fs_write(file->handle, buffer.data(), static_cast<uint32_t>(buffer.size()))
        : (currentPosition >= 0
               ? ex_host_fs_pwrite(
                     file->handle, buffer.data(), static_cast<uint32_t>(buffer.size()),
                     static_cast<uint64_t>(currentPosition))
               : ex_host_fs_write(
                     file->handle, buffer.data(), static_cast<uint32_t>(buffer.size())));
    if (written < 0) {
      return fsAsyncSyscallError("writev", path);
    }
    bytesWrittenTotal += static_cast<size_t>(written);
    if (static_cast<size_t>(written) < buffer.size()) {
      break;
    }
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = static_cast<double>(bytesWrittenTotal);
  return result;
}

FsAsyncResult fsStatPathWork(const std::string& path, bool isLstat) {
  char* json = isLstat ? ex_host_fs_lstat(path.c_str()) : ex_host_fs_stat(path.c_str());
  if (!json) {
    return fsAsyncSyscallError(isLstat ? "lstat" : "stat", path);
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = json;
  ex_host_free_string(json);
  return result;
}

FsAsyncResult fsFstatWork(const FileEntry& entry) {
  if (!entry.file || !entry.file->handle) {
    return fsAsyncBadFd("fstat");
  }
  std::lock_guard<std::mutex> ioLock(entry.file->ioMutex);
  char* json = ex_host_fs_fstat(entry.file->handle);
  if (!json) {
    return fsAsyncSyscallError("fstat", entry.path);
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = json;
  ex_host_free_string(json);
  return result;
}

FsAsyncResult fsAsyncString(std::string value) {
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = std::move(value);
  return result;
}

FsAsyncResult fsPathOpWork(
    const std::string& op,
    const std::string& a,
    const std::string& b,
    double x,
    double y,
    uint64_t principal) {
  if (op == "readdir") {
    char* json = ex_host_fs_readdir(a.c_str());
    if (!json) {
      return fsAsyncSyscallError("scandir", a);
    }
    std::string out(json);
    ex_host_free_string(json);
    return fsAsyncString(std::move(out));
  }
  if (op == "mkdir") {
    if (x != 0) {
      char* firstCreated = ex_host_fs_mkdir_recursive_result(a.c_str());
      if (!firstCreated) return fsAsyncSyscallError("mkdir", a);
      std::string result(firstCreated);
      ex_host_free_string(firstCreated);
      return result.empty() ? fsAsyncOk() : fsAsyncString(std::move(result));
    }
    if (ex_host_fs_mkdir(a.c_str(), x != 0 ? 1 : 0) != 0) {
      return fsAsyncSyscallError("mkdir", a);
    }
    return fsAsyncOk();
  }
  if (op == "rmdir") {
    if (ex_host_fs_rmdir(a.c_str()) != 0) {
      return fsAsyncSyscallError("rmdir", a);
    }
    return fsAsyncOk();
  }
  if (op == "unlink") {
    if (ex_host_fs_unlink(a.c_str()) != 0) {
      return fsAsyncSyscallError("unlink", a);
    }
    return fsAsyncOk();
  }
  if (op == "rename") {
    if (ex_host_fs_rename(a.c_str(), b.c_str()) != 0) {
      return fsAsyncSyscallError("rename", a);
    }
    return fsAsyncOk();
  }
  if (op == "copyfile") {
    if (ex_host_fs_copy(a.c_str(), b.c_str()) != 0) {
      return fsAsyncSyscallError("copyfile", a);
    }
    return fsAsyncOk();
  }
  if (op == "copyfile_excl") {
    if (ex_host_fs_copy_exclusive(a.c_str(), b.c_str()) != 0) {
      return fsAsyncSyscallError("copyfile", a);
    }
    return fsAsyncOk();
  }
  if (op == "realpath") {
    char* resolved = ex_host_fs_realpath(a.c_str());
    if (!resolved) {
      return fsAsyncSyscallError("realpath", a);
    }
    std::string out(resolved);
    ex_host_free_string(resolved);
    return fsAsyncString(std::move(out));
  }
  if (op == "access") {
    if (ex_host_fs_access(a.c_str(), static_cast<int32_t>(x)) != 0) {
      return fsAsyncSyscallError("access", a);
    }
    return fsAsyncOk();
  }
  if (op == "chmod") {
    if (ex_host_fs_chmod(a.c_str(), static_cast<uint32_t>(x)) != 0) {
      return fsAsyncSyscallError("chmod", a);
    }
    return fsAsyncOk();
  }
  if (op == "truncate") {
    if (x < 0 || ex_host_fs_truncate(a.c_str(), static_cast<uint64_t>(x)) != 0) {
      return fsAsyncSyscallError("truncate", a, x < 0 ? EINVAL : 0);
    }
    return fsAsyncOk();
  }
  if (op == "utime") {
    if (ex_host_fs_utimes(a.c_str(), x, y) != 0) {
      return fsAsyncSyscallError("utime", a);
    }
    return fsAsyncOk();
  }
  if (op == "statfs") {
    char* json = ex_host_fs_statfs(a.c_str());
    if (!json) return fsAsyncSyscallError("statfs", a);
    std::string result(json);
    ex_host_free_string(json);
    return fsAsyncString(std::move(result));
  }
  if (op == "mkdtemp") {
    char* path = ex_host_fs_mkdtemp(a.c_str(), principal);
    if (!path) {
      return fsAsyncSyscallError("mkdtemp", a);
    }
    std::string out(path);
    ex_host_free_string(path);
    return fsAsyncString(std::move(out));
  }
  return fsAsyncUnsupported(op, a);
}

bool parseWindowsIoVecArguments(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value,
    std::vector<std::vector<uint8_t>>& buffers,
    bool copyInput = true) {
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
  for (size_t i = 0; i < length; i++) {
    std::string index = std::to_string(i);
    auto entry = listObj.getProperty(runtime, facebook::jsi::PropNameID::forAscii(runtime, index));
    if (!entry.isObject()) {
      return false;
    }
    auto entryObj = entry.asObject(runtime);
    size_t byteLength = 0;
    const uint8_t* source = nullptr;
    if (!extractArrayBufferView(runtime, entryObj, source, byteLength, nullptr)) {
      return false;
    }
    std::vector<uint8_t> bytes(byteLength);
    if (copyInput && source && byteLength > 0) {
      std::copy(source, source + byteLength, bytes.begin());
    }
    buffers.push_back(std::move(bytes));
  }
  return true;
}

} // namespace

std::vector<uint64_t> exactCollectTypedPrincipalStack() {
  std::vector<uint64_t> principals;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  if (g_vm_runtime != nullptr) {
    auto frames = g_vm_runtime->getStackTrace(
        facebook::hermes::HermesRuntime::StackTraceKind::NoSourceLocation);
    for (auto& frame : frames) {
      auto domain = frame.getDomain();
      if (domain && *domain != kRuntimePrincipalId &&
          *domain != kNoUserPrincipalId &&
          std::find(principals.begin(), principals.end(), *domain) == principals.end()) {
        principals.push_back(*domain);
      }
    }
  }
#endif
  if (g_typed_principal_stack) {
    for (auto id : *g_typed_principal_stack) {
      if (std::find(principals.begin(), principals.end(), id) == principals.end()) {
        principals.push_back(id);
      }
    }
  }
  auto scheduler = g_native_callback_principal_id;
  if (scheduler != kNoNativePrincipalOverride
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
      && scheduler != static_cast<uint64_t>(kRuntimePrincipalId)
      && scheduler != static_cast<uint64_t>(kNoUserPrincipalId)
#endif
      && std::find(principals.begin(), principals.end(), scheduler) == principals.end()) {
    principals.push_back(scheduler);
  }
  if (principals.empty()) principals.push_back(currentPrincipalId());
  return principals;
}

ScopedTypedPrincipalStack::ScopedTypedPrincipalStack(
    const std::vector<uint64_t>& principals)
    : principals_(principals), previous_(g_typed_principal_stack) {
  g_typed_principal_stack = &principals_;
}

ScopedTypedPrincipalStack::~ScopedTypedPrincipalStack() {
  g_typed_principal_stack = previous_;
}

void exactCleanupRuntimeFileDescriptors(uint64_t runtimeNonce) {
  std::vector<std::shared_ptr<WindowsFileHandle>> files;
  {
    std::lock_guard<std::mutex> lock(g_files_mutex);
    for (auto it = g_files.begin(); it != g_files.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        files.push_back(std::move(it->second.file));
        it = g_files.erase(it);
      } else {
        ++it;
      }
    }
  }
  files.clear();
}

// The POSIX build implements this in hermes_runtime_fs.cc, where it records
// the SCM_RIGHTS process-IPC fd in the fd ownership registry so raw integers
// don't become ambient authority (ENG-22883). Windows has no SCM_RIGHTS fd
// passing and this file keeps no raw-fd registry (file access goes through
// HANDLE-backed FileEntry records), so the platform-neutral call site in
// hermes_runtime.cc (EXACT_IPC_FD bootstrap) links against this no-op.
void exactRegisterProcessIpcFd(int fd) {
  (void)fd;
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
          throw facebook::jsi::JSError(runtime, "__exactReadFile: path required");
        }
        auto path = pathArg(runtime, args[0]);
        requireReadCapability(runtime, path);
        uint64_t len = 0;
        int32_t read_errno = 0;
        uint8_t* data = ex_host_fs_read_file(path.c_str(), &len, &read_errno);
        if (!data) {
          (void)read_errno;
          throwFs(runtime, "open", path);
        }
        std::vector<uint8_t> bytes(data, data + len);
        ex_host_free_buffer(data, len);
        return makeUint8Array(runtime, std::move(bytes));
      });
  rt.global().setProperty(rt, "__exactReadFile", std::move(readFileFn));

  auto writeFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactWriteFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactWriteFile: path and data required");
        }
        auto path = pathArg(runtime, args[0]);
        requireWriteCapability(runtime, path);
        auto bytes = extractBytes(runtime, args[1]);
        void* file = ex_host_fs_open(
            path.c_str(), EXACT_FS_WRITE | EXACT_FS_CREATE | EXACT_FS_TRUNCATE);
        if (!file) {
          throwFs(runtime, "open", path);
        }
        // ex_host_fs_write is a single std::io::Write::write, which may write
        // FEWER bytes than requested (nearly-full disk, RLIMIT_FSIZE, a large
        // buffer). A single call that ignores the returned count silently
        // truncates the file while reporting success, so loop until every byte
        // is written. Mirrors the POSIX bridge fix in ENG-22982 / the fd-based
        // _writeAllSync path in fs.js.
        size_t totalWritten = 0;
        const size_t total = bytes.size();
        while (totalWritten < total) {
          size_t remaining = total - totalWritten;
          uint32_t chunk = remaining > 0xFFFFFFFFu
              ? 0xFFFFFFFFu
              : static_cast<uint32_t>(remaining);
          int32_t written = ex_host_fs_write(file, bytes.data() + totalWritten, chunk);
          if (written < 0) {
            // Unlike the POSIX bridge, there is nothing safe to retry here: a
            // blocking (non-overlapped) Win32 WriteFile is not interruptible
            // the way a POSIX write(2) is aborted by an asynchronous signal
            // (no EINTR-equivalent), and the Rust ABI does not propagate a
            // Windows error code across this FFI boundary for the C++ side to
            // inspect, so a negative return is treated as a real,
            // non-retryable error. (ENG-23042, residual of the ENG-22982/22993
            // short-write fixes — see the POSIX EINTR retry in
            // hermes_runtime_fs.cc's __exactWriteFile.)
            ex_host_fs_close(file);
            throwFs(runtime, "write", path);
          }
          if (written == 0) {
            // No progress and no error: refuse to spin forever.
            ex_host_fs_close(file);
            throwFs(runtime, "write", path);
          }
          totalWritten += static_cast<size_t>(written);
        }
        ex_host_fs_close(file);
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactWriteFile", std::move(writeFileFn));

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
        auto path = pathArg(runtime, args[0]);
        int flags = 0;
        if (count > 1 && args[1].isNumber()) {
          flags = static_cast<int>(args[1].asNumber());
        }
        auto host_flags = hostFlagsFromNodeFlags(flags);
        if ((host_flags & EXACT_FS_READ) == EXACT_FS_READ) {
          requireReadCapability(runtime, path);
        }
        if ((host_flags & EXACT_FS_WRITE) == EXACT_FS_WRITE) {
          requireWriteCapability(runtime, path);
        }
        void* rawFile = ex_host_fs_open(path.c_str(), host_flags);
        if (!rawFile) {
          throwFs(runtime, "open", path);
        }
        auto file = std::make_shared<WindowsFileHandle>(rawFile);
        std::lock_guard<std::mutex> lock(g_files_mutex);
        int fd = g_next_fd++;
        g_files[fd] = FileEntry{
            file,
            path,
            (flags & NODE_O_APPEND) == NODE_O_APPEND,
            exactCurrentRuntimeNonce(),
            currentPrincipalId(),
            (host_flags & EXACT_FS_READ) == EXACT_FS_READ,
            (host_flags & EXACT_FS_WRITE) == EXACT_FS_WRITE};
        return facebook::jsi::Value(static_cast<double>(fd));
      });
  rt.global().setProperty(rt, "__exactFsOpen", std::move(fsOpenFn));

  auto fsCloseFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsClose"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactFsClose: fd required");
        }
        auto fd = fdFromValue(runtime, args[0]);
        FileEntry entry;
        {
          std::lock_guard<std::mutex> lock(g_files_mutex);
          auto it = g_files.find(fd);
          if (it == g_files.end()) {
            throw facebook::jsi::JSError(runtime, "bad file descriptor");
          }
          if (it->second.runtimeNonce != exactCurrentRuntimeNonce() ||
              (!isAllowAll() && it->second.owner != currentPrincipalId())) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          entry = it->second;
          g_files.erase(it);
        }
        entry.file.reset();
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsClose", std::move(fsCloseFn));

  auto fsReadFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsRead"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactFsRead: fd and length required");
        }
        auto fd = fdFromValue(runtime, args[0]);
        auto length = static_cast<uint32_t>(args[1].asNumber());
        std::vector<uint8_t> bytes(length);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryRead(runtime, entry);
        // A numeric position is a *positional* read: Node's readSync leaves the
        // handle's current file offset unchanged when `position` is a number. The
        // old ex_host_fs_seek + ex_host_fs_read permanently moved the cursor
        // (corrupting a header-at-fixed-offset-then-stream read pattern), so use
        // ex_host_fs_pread, which reads at the offset and restores the cursor.
        // position < 0 / null / undefined means "read at the current position"
        // and keeps the plain read path. Mirrors the POSIX pread fix in ENG-22982.
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        auto file = entry.file;
        std::lock_guard<std::mutex> ioLock(file->ioMutex);
        auto nread = positioned
            ? ex_host_fs_pread(
                  file->handle, bytes.data(), length,
                  static_cast<uint64_t>(args[2].asNumber()))
            : ex_host_fs_read(file->handle, bytes.data(), length);
        if (nread < 0) {
          throwFs(runtime, "read", entry.path);
        }
        bytes.resize(static_cast<size_t>(nread));
        return makeUint8Array(runtime, std::move(bytes));
      });
  rt.global().setProperty(rt, "__exactFsRead", std::move(fsReadFn));

  auto fsWriteFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWrite"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactFsWrite: fd and data required");
        }
        auto fd = fdFromValue(runtime, args[0]);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryWrite(runtime, entry);
        auto bytes = extractBytes(runtime, args[1]);
        if (bytes.empty()) {
          return facebook::jsi::Value(0.0);
        }
        // A numeric position is a *positional* write: Node's writeSync leaves the
        // handle's current offset unchanged when `position` is a number. The old
        // ex_host_fs_seek + ex_host_fs_write permanently moved the cursor, so use
        // ex_host_fs_pwrite (writes at the offset, restores the cursor). position
        // < 0 / null / undefined means "write at the current position". An append
        // fd always appends and ignores the offset (matching Node). Mirrors the
        // POSIX pwrite fix in ENG-22982. The returned short-write count is the JS
        // caller's responsibility to loop on, same as the POSIX fd write path.
        bool positioned =
            !entry.append && count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        auto file = entry.file;
        std::lock_guard<std::mutex> ioLock(file->ioMutex);
        auto written = entry.append
            ? ex_host_fs_write(
                  file->handle, bytes.data(), static_cast<uint32_t>(bytes.size()))
            : (positioned
                   ? ex_host_fs_pwrite(
                         file->handle, bytes.data(), static_cast<uint32_t>(bytes.size()),
                         static_cast<uint64_t>(args[2].asNumber()))
                   : ex_host_fs_write(
                         file->handle, bytes.data(), static_cast<uint32_t>(bytes.size())));
        if (written < 0) {
          throwFs(runtime, "write", entry.path);
        }
        return facebook::jsi::Value(static_cast<double>(written));
      });
  rt.global().setProperty(rt, "__exactFsWrite", std::move(fsWriteFn));

  auto fsFstatFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsFstatSync"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          throw facebook::jsi::JSError(runtime, "__exactFsFstatSync: fd required");
        }
        auto entry = getFileEntry(runtime, fdFromValue(runtime, args[0]));
        requireFileEntryRead(runtime, entry);
        auto file = entry.file;
        std::lock_guard<std::mutex> ioLock(file->ioMutex);
        return jsonStringResult(runtime, ex_host_fs_fstat(file->handle), "fstat", entry.path);
      });
  rt.global().setProperty(rt, "__exactFsFstatSync", std::move(fsFstatFn));

  rt.global().setProperty(
      rt, "__exactStat", unaryPathJsonFunction(rt, "__exactStat", "stat", ex_host_fs_stat));
  rt.global().setProperty(
      rt, "__exactLstat", unaryPathJsonFunction(rt, "__exactLstat", "lstat", ex_host_fs_lstat));
  rt.global().setProperty(
      rt,
      "__exactReaddir",
      unaryPathJsonFunction(rt, "__exactReaddir", "scandir", ex_host_fs_readdir));

  auto mkdirFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdir"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        auto path = count > 0 ? pathArg(runtime, args[0]) : std::string();
        int32_t recursive = count > 1 && args[1].isBool() && args[1].getBool() ? 1 : 0;
        requireWriteCapability(runtime, path);
        if (path.empty() || ex_host_fs_mkdir(path.c_str(), recursive) != 0) {
          throwFs(runtime, "mkdir", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactMkdir", std::move(mkdirFn));

  auto unaryVoid = [&rt](const char* name, const char* syscall, int32_t (*host_fn)(const char*)) {
    return facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, name),
        1,
        [syscall, host_fn](
            facebook::jsi::Runtime& runtime,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          auto path = count > 0 ? pathArg(runtime, args[0]) : std::string();
          requireWriteCapability(runtime, path);
          if (path.empty() || host_fn(path.c_str()) != 0) {
            throwFs(runtime, syscall, path);
          }
          return facebook::jsi::Value::undefined();
        });
  };
  rt.global().setProperty(rt, "__exactRmdir", unaryVoid("__exactRmdir", "rmdir", ex_host_fs_rmdir));
  rt.global().setProperty(rt, "__exactUnlink", unaryVoid("__exactUnlink", "unlink", ex_host_fs_unlink));

  auto renameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRename"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactRename: from and to required");
        }
        auto from = pathArg(runtime, args[0]);
        auto to = pathArg(runtime, args[1]);
        requireWriteCapability(runtime, from);
        requireWriteCapability(runtime, to);
        if (ex_host_fs_rename(from.c_str(), to.c_str()) != 0) {
          throwFs(runtime, "rename", from);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactRename", std::move(renameFn));

  auto copyFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactCopyFile"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2) {
          throw facebook::jsi::JSError(runtime, "__exactCopyFile: from and to required");
        }
        auto from = pathArg(runtime, args[0]);
        auto to = pathArg(runtime, args[1]);
        requireReadCapability(runtime, from);
        requireWriteCapability(runtime, to);
        bool exclusive = count > 2 && args[2].isNumber() &&
            (static_cast<int>(args[2].asNumber()) & 1) != 0;
        auto copy = exclusive ? ex_host_fs_copy_exclusive : ex_host_fs_copy;
        if (copy(from.c_str(), to.c_str()) != 0) {
          throwFs(runtime, "copyfile", from);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactCopyFile", std::move(copyFn));

  rt.global().setProperty(
      rt,
      "__exactRealpath",
      unaryPathJsonFunction(rt, "__exactRealpath", "realpath", ex_host_fs_realpath));

  auto accessFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAccess"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        auto path = count > 0 ? pathArg(runtime, args[0]) : std::string();
        int32_t mode = count > 1 && args[1].isNumber() ? static_cast<int32_t>(args[1].asNumber()) : 0;
        if ((mode & 2) == 2) {
          requireWriteCapability(runtime, path);
        } else {
          requireReadCapability(runtime, path);
        }
        if (path.empty() || ex_host_fs_access(path.c_str(), mode) != 0) {
          throwFs(runtime, "access", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAccess", std::move(accessFn));

  auto chmodFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactChmod"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        auto path = count > 0 ? pathArg(runtime, args[0]) : std::string();
        auto mode = count > 1 && args[1].isNumber() ? static_cast<uint32_t>(args[1].asNumber()) : 0;
        requireWriteCapability(runtime, path);
        if (path.empty() || ex_host_fs_chmod(path.c_str(), mode) != 0) {
          throwFs(runtime, "chmod", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactChmod", std::move(chmodFn));

  auto truncateFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactTruncate"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactTruncate: path and length required");
        }
        auto path = pathArg(runtime, args[0]);
        auto length = args[1].asNumber();
        requireWriteCapability(runtime, path);
        if (length < 0 || ex_host_fs_truncate(path.c_str(), static_cast<uint64_t>(length)) != 0) {
          throwFs(runtime, "truncate", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactTruncate", std::move(truncateFn));

  auto utimesFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactUtimes"),
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 3 || !args[1].isNumber() || !args[2].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactUtimes: path, atime, and mtime required");
        }
        auto path = pathArg(runtime, args[0]);
        requireWriteCapability(runtime, path);
        if (ex_host_fs_utimes(
                path.c_str(), args[1].asNumber(), args[2].asNumber()) != 0) {
          throwFs(runtime, "utime", path);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactUtimes", std::move(utimesFn));

  auto statfsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStatfs"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1) {
          throw facebook::jsi::JSError(runtime, "__exactStatfs: path required");
        }
        auto path = pathArg(runtime, args[0]);
        requireReadCapability(runtime, path);
        return jsonStringResult(
            runtime, ex_host_fs_statfs(path.c_str()), "statfs", path);
      });
  rt.global().setProperty(rt, "__exactStatfs", std::move(statfsFn));

  auto mkdtempFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactMkdtemp"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        auto prefix = count > 0 ? pathArg(runtime, args[0]) : std::string("tmp");
        return jsonStringResult(
            runtime,
            ex_host_fs_mkdtemp(prefix.c_str(), currentPrincipalId()),
            "mkdtemp",
            prefix);
      });
  rt.global().setProperty(rt, "__exactMkdtemp", std::move(mkdtempFn));

  auto readFileAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadFileAsync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || (!args[0].isString() && !args[0].isNumber())) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadFileAsync: path or fd required");
        }
        if (args[0].isNumber()) {
          int fd = fdFromValue(runtime, args[0]);
          auto entry = getFileEntry(runtime, fd);
          requireFileEntryRead(runtime, entry);
          auto file = entry.file;
          auto path = entry.path;
          return startFsAsync(handle, runtime, [file, path]() -> FsAsyncResult {
            return fsReadWholeHandleWork(file, path);
          });
        }
        auto path = pathArg(runtime, args[0]);
        requireReadCapability(runtime, path);
        return startFsAsync(handle, runtime, [path]() -> FsAsyncResult {
          return fsReadFilePathWork(path);
        });
      });
  rt.global().setProperty(rt, "__exactFsReadFileAsync", std::move(readFileAsyncFn));

  auto writeFileAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWriteFileAsync"),
      5,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || (!args[0].isString() && !args[0].isNumber())) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWriteFileAsync: path/fd and data required");
        }
        auto dataBytes =
            std::make_shared<std::vector<uint8_t>>(extractBytes(runtime, args[1]));
        bool flush = count > 4 && args[4].isBool() && args[4].getBool();
        if (args[0].isNumber()) {
          int fd = fdFromValue(runtime, args[0]);
          auto entry = getFileEntry(runtime, fd);
          requireFileEntryWrite(runtime, entry);
          auto file = entry.file;
          auto path = entry.path;
          return startFsAsync(
              handle, runtime, [file, path, dataBytes, flush]() -> FsAsyncResult {
                return fsWriteAllHandleWork(file, path, *dataBytes, flush);
              });
        }
        auto path = pathArg(runtime, args[0]);
        requireWriteCapability(runtime, path);
        int nodeFlags = count > 2 && args[2].isNumber()
            ? static_cast<int>(args[2].asNumber())
            : (NODE_O_CREAT | NODE_O_TRUNC | NODE_O_WRONLY);
        return startFsAsync(
            handle, runtime, [path, dataBytes, nodeFlags, flush]() -> FsAsyncResult {
              return fsWriteFilePathWork(path, *dataBytes, nodeFlags, flush);
            });
      });
  rt.global().setProperty(rt, "__exactFsWriteFileAsync", std::move(writeFileAsyncFn));

  auto fsReadAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadAsync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadAsync: fd and length required");
        }
        int fd = fdFromValue(runtime, args[0]);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryRead(runtime, entry);
        auto length = std::min(
            static_cast<size_t>(args[1].asNumber()),
            static_cast<size_t>(kMaxHostIoChunk));
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto file = entry.file;
        auto path = entry.path;
        return startFsAsync(
            handle, runtime, [file, path, length, positioned, position]() -> FsAsyncResult {
              return fsReadChunkWork(file, path, length, positioned, position);
            });
      });
  rt.global().setProperty(rt, "__exactFsReadAsync", std::move(fsReadAsyncFn));

  auto fsWriteAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWriteAsync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsWriteAsync: fd and data required");
        }
        int fd = fdFromValue(runtime, args[0]);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryWrite(runtime, entry);
        auto dataBytes =
            std::make_shared<std::vector<uint8_t>>(extractBytes(runtime, args[1]));
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto file = entry.file;
        auto path = entry.path;
        bool append = entry.append;
        return startFsAsync(
            handle, runtime, [file, path, append, dataBytes, positioned, position]() -> FsAsyncResult {
              return fsWriteChunkWork(file, path, append, *dataBytes, positioned, position);
            });
      });
  rt.global().setProperty(rt, "__exactFsWriteAsync", std::move(fsWriteAsyncFn));

  auto fsReadvAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadvAsync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadvAsync: fd and buffers required");
        }
        int fd = fdFromValue(runtime, args[0]);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryRead(runtime, entry);
        std::vector<std::vector<uint8_t>> buffers;
        if (!parseWindowsIoVecArguments(runtime, args[1], buffers, false)) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadvAsync: buffers must be Uint8Array-like objects");
        }
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto buffersPtr = std::make_shared<std::vector<std::vector<uint8_t>>>(std::move(buffers));
        auto file = entry.file;
        auto path = entry.path;
        return startFsAsync(
            handle, runtime, [file, path, buffersPtr, positioned, position]() -> FsAsyncResult {
              return fsReadvWork(file, path, *buffersPtr, positioned, position);
            });
      });
  rt.global().setProperty(rt, "__exactFsReadvAsync", std::move(fsReadvAsyncFn));

  auto fsWritevAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsWritevAsync"),
      3,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritevAsync: fd and buffers required");
        }
        int fd = fdFromValue(runtime, args[0]);
        auto entry = getFileEntry(runtime, fd);
        requireFileEntryWrite(runtime, entry);
        std::vector<std::vector<uint8_t>> buffers;
        if (!parseWindowsIoVecArguments(runtime, args[1], buffers)) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWritevAsync: buffers must be Uint8Array-like objects");
        }
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto buffersPtr = std::make_shared<std::vector<std::vector<uint8_t>>>(std::move(buffers));
        auto file = entry.file;
        auto path = entry.path;
        bool append = entry.append;
        return startFsAsync(
            handle, runtime,
            [file, path, append, buffersPtr, positioned, position]() -> FsAsyncResult {
              return fsWritevWork(file, path, append, *buffersPtr, positioned, position);
            });
      });
  rt.global().setProperty(rt, "__exactFsWritevAsync", std::move(fsWritevAsyncFn));

  auto fsPathAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsPathAsync"),
      6,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsPathAsync: op and path required");
        }
        auto op = args[0].toString(runtime).utf8(runtime);
        auto a = args[1].toString(runtime).utf8(runtime);
        std::string b;
        if (count > 2 && args[2].isString()) {
          b = args[2].toString(runtime).utf8(runtime);
        }
        double x = count > 3 && args[3].isNumber() ? args[3].asNumber() : 0;
        double y = count > 4 && args[4].isNumber() ? args[4].asNumber() : 0;
        uint64_t principal = currentPrincipalId();
        if (!isAllowAll()) {
          if (op == "readdir" || op == "realpath" || op == "readlink" ||
              op == "statfs") {
            requireReadCapability(runtime, a);
          } else if (op == "rename") {
            requireWriteCapability(runtime, a);
            requireWriteCapability(runtime, b);
          } else if (op == "copyfile" || op == "copyfile_excl") {
            requireReadCapability(runtime, a);
            requireWriteCapability(runtime, b);
          } else if (op == "access") {
            if ((static_cast<int32_t>(x) & 2) != 0) {
              requireWriteCapability(runtime, a);
            } else {
              requireReadCapability(runtime, a);
            }
          } else if (op == "symlink") {
            requireWriteCapability(runtime, b);
          } else if (op == "link") {
            requireReadCapability(runtime, a);
            requireWriteCapability(runtime, a);
            requireWriteCapability(runtime, b);
          } else {
            requireWriteCapability(runtime, a);
          }
        }
        return startFsAsync(
            handle, runtime, [op, a, b, x, y, principal]() -> FsAsyncResult {
              return fsPathOpWork(op, a, b, x, y, principal);
            });
      });
  rt.global().setProperty(rt, "__exactFsPathAsync", std::move(fsPathAsyncFn));

  auto fsStatAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsStatAsync"),
      2,
      [handle](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[1].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsStatAsync: target and kind required");
        }
        auto kind = args[1].toString(runtime).utf8(runtime);
        if (kind == "fstat") {
          if (!args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactFsStatAsync: fd required");
          }
          auto entry = getFileEntry(runtime, fdFromValue(runtime, args[0]));
          requireFileEntryRead(runtime, entry);
          return startFsAsync(handle, runtime, [entry]() -> FsAsyncResult {
            return fsFstatWork(entry);
          });
        }
        if (!args[0].isString() || (kind != "stat" && kind != "lstat")) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsStatAsync: path and stat/lstat kind required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        requireReadCapability(runtime, path);
        bool isLstat = kind == "lstat";
        return startFsAsync(handle, runtime, [path, isLstat]() -> FsAsyncResult {
          return fsStatPathWork(path, isLstat);
        });
      });
  rt.global().setProperty(rt, "__exactFsStatAsync", std::move(fsStatAsyncFn));

  auto installSync = [&rt](const char* name, const char* syscall, int32_t dataOnly) {
    auto fn = facebook::jsi::Function::createFromHostFunction(
        rt,
        facebook::jsi::PropNameID::forAscii(rt, name),
        1,
        [name, syscall, dataOnly](
            facebook::jsi::Runtime& runtime,
            const facebook::jsi::Value&,
            const facebook::jsi::Value* args,
            size_t count) -> facebook::jsi::Value {
          if (count == 0 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, std::string(name) + ": fd required");
          }
          auto entry = getFileEntry(runtime, fdFromValue(runtime, args[0]));
          requireFileEntryWrite(runtime, entry);
          auto file = entry.file;
          std::lock_guard<std::mutex> ioLock(file->ioMutex);
          if (ex_host_fs_sync(file->handle, dataOnly) != 0) {
            throwFs(runtime, syscall, entry.path);
          }
          return facebook::jsi::Value::undefined();
        });
    rt.global().setProperty(rt, name, std::move(fn));
  };
  // The Rust-owned handle now exposes File::sync_all/sync_data, which map to
  // FlushFileBuffers on Windows. These must be real flushes: registering
  // no-op success here would violate Node's durability contract (ENG-22963).
  installSync("__exactFsFsyncSync", "fsync", 0);
  installSync("__exactFsFdatasyncSync", "fdatasync", 1);
}
