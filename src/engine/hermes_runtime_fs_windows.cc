#include "hermes_runtime_internal.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

constexpr uint32_t EXACT_FS_READ = 1;
constexpr uint32_t EXACT_FS_WRITE = 2;
constexpr uint32_t EXACT_FS_CREATE = 4;
constexpr uint32_t EXACT_FS_TRUNCATE = 8;

constexpr int NODE_O_WRONLY = 1;
constexpr int NODE_O_RDWR = 2;
constexpr int NODE_O_APPEND = 8;
constexpr int NODE_O_CREAT = 512;
constexpr int NODE_O_TRUNC = 1024;

struct FileEntry {
  void* handle = nullptr;
  std::string path;
  bool append = false;
  uint64_t owner = 0;
  bool canRead = false;
  bool canWrite = false;
};

std::mutex g_files_mutex;
std::unordered_map<int, FileEntry> g_files;
int g_next_fd = 3;

extern "C" void* ex_host_fs_open(const char* path, uint32_t flags);
extern "C" int32_t ex_host_fs_read(void* file, uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_write(void* file, const uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_seek(void* file, uint64_t position);
// Positional read/write that do NOT move the handle's cursor (pread/pwrite
// equivalents; ENG-22993, porting the POSIX fix in ENG-22982). Node's
// readSync/writeSync leave the fd offset unchanged when `position` is a number.
extern "C" int32_t ex_host_fs_pread(void* file, uint8_t* buf, uint32_t len, uint64_t offset);
extern "C" int32_t ex_host_fs_pwrite(void* file, const uint8_t* buf, uint32_t len, uint64_t offset);
extern "C" void ex_host_fs_close(void* file);
extern "C" uint8_t* ex_host_fs_read_file(const char* path, uint64_t* out_len, int32_t* out_errno);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint64_t len);
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
extern "C" char* ex_host_fs_mkdtemp(const char* prefix, uint64_t module_id);
extern "C" int32_t ex_host_fs_append(const char* path, const uint8_t* data, uint32_t len);
extern "C" void ex_host_free_string(char* value);

std::string pathArg(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value) {
  return value.toString(runtime).utf8(runtime);
}

std::string fsErrorMessage(const std::string& syscall, const std::string& path) {
  if (!path.empty() && ex_host_fs_access(path.c_str(), 0) != 0) {
    return "ENOENT: no such file or directory, " + syscall + " '" + path + "'";
  }
  return syscall + " failed" + (path.empty() ? "" : ": " + path);
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
  return host_flags;
}

int fdFromValue(facebook::jsi::Runtime& runtime, const facebook::jsi::Value& value) {
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, "file descriptor must be a number");
  }
  return static_cast<int>(value.asNumber());
}

FileEntry getFileEntry(facebook::jsi::Runtime& runtime, int fd) {
  std::lock_guard<std::mutex> lock(g_files_mutex);
  auto it = g_files.find(fd);
  if (it == g_files.end() || !it->second.handle) {
    throw facebook::jsi::JSError(runtime, "bad file descriptor");
  }
  if (!isAllowAll() && it->second.owner != currentPrincipalId()) {
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

} // namespace

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
          // written < 0 is an error; written == 0 with bytes remaining means no
          // progress and no error — refuse to spin forever.
          if (written <= 0) {
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
        void* file = ex_host_fs_open(path.c_str(), host_flags);
        if (!file) {
          throwFs(runtime, "open", path);
        }
        std::lock_guard<std::mutex> lock(g_files_mutex);
        int fd = g_next_fd++;
        g_files[fd] = FileEntry{
            file,
            path,
            (flags & NODE_O_APPEND) == NODE_O_APPEND,
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
          if (!isAllowAll() && it->second.owner != currentPrincipalId()) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          entry = it->second;
          g_files.erase(it);
        }
        if (entry.handle) {
          ex_host_fs_close(entry.handle);
        }
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
        auto nread = positioned
            ? ex_host_fs_pread(
                  entry.handle, bytes.data(), length,
                  static_cast<uint64_t>(args[2].asNumber()))
            : ex_host_fs_read(entry.handle, bytes.data(), length);
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
        auto written = entry.append
            ? ex_host_fs_append(
                  entry.path.c_str(), bytes.data(), static_cast<uint32_t>(bytes.size()))
            : (positioned
                   ? ex_host_fs_pwrite(
                         entry.handle, bytes.data(), static_cast<uint32_t>(bytes.size()),
                         static_cast<uint64_t>(args[2].asNumber()))
                   : ex_host_fs_write(
                         entry.handle, bytes.data(), static_cast<uint32_t>(bytes.size())));
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
        return jsonStringResult(runtime, ex_host_fs_stat(entry.path.c_str()), "fstat", entry.path);
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
      2,
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
        if (ex_host_fs_copy(from.c_str(), to.c_str()) != 0) {
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

  auto noopFdFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsFsyncSync"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFsyncSync", std::move(noopFdFn));
  auto noopFdataFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactFsFdatasyncSync"),
      1,
      [](facebook::jsi::Runtime&,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactFsFdatasyncSync", std::move(noopFdataFn));
}
