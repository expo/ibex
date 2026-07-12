#include "hermes_runtime_internal.h"

// PATH_MAX / realpath live in <limits.h> on Linux; macOS pulls them in
// transitively. Spell it out so the realpath() path-resolution helpers build
// on Linux. @ref LLP 0008#filesystem
#include <limits.h>

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <dirent.h>
#include <functional>
#include <memory>
#include <thread>
#include <fcntl.h>
#include <iomanip>
#include <mutex>
#include <new>
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
#include <unordered_map>
#include <unistd.h>

extern "C" void* ex_host_fs_open(const char* path, uint32_t flags);
extern "C" int32_t ex_host_fs_read(void* file, uint8_t* buf, uint32_t len);
extern "C" int32_t ex_host_fs_write(void* file, const uint8_t* buf, uint32_t len);
extern "C" void ex_host_fs_close(void* file);
extern "C" uint8_t* ex_host_fs_read_file(const char* path,
                                         uint64_t* out_len,
                                         int32_t* out_errno);
extern "C" void ex_host_free_buffer(uint8_t* buf, uint64_t len);
extern "C" char* ex_host_fs_stat(const char* path);
extern "C" char* ex_host_fs_lstat(const char* path);
extern "C" char* ex_host_fs_readdir(const char* path);
extern "C" int32_t ex_host_fs_mkdir(const char* path, int32_t recursive);
extern "C" int32_t ex_host_fs_rmdir(const char* path);
extern "C" int32_t ex_host_fs_unlink(const char* path);
extern "C" int32_t ex_host_fs_rename(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy(const char* from, const char* to);
extern "C" int32_t ex_host_fs_copy_exclusive(const char* from, const char* to);
extern "C" char* ex_host_fs_realpath(const char* path);
extern "C" int32_t ex_host_fs_access(const char* path, int32_t mode);
extern "C" int32_t ex_host_fs_chmod(const char* path, uint32_t mode);
extern "C" char* ex_host_fs_mkdtemp(const char* prefix, uint64_t module_id);
extern "C" int32_t ex_host_fs_append(const char* path, const uint8_t* data, uint32_t len);
extern "C" void ex_host_free_string(char* value);
extern "C" int32_t ex_host_is_armed(void);
extern "C" int32_t ex_host_typed_generations(
    uint64_t* negative,
    uint64_t* dynamic,
    uint64_t* handle);
extern "C" int32_t ex_host_authorize_typed_fs_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const char* path,
    uint32_t stage,
    uint32_t surface,
    int32_t parent_fd,
    int32_t fd,
    int32_t needs_read,
    int32_t needs_write,
    const char* presented_handle_id);

constexpr uint32_t EXACT_FS_WRITE = 1u << 1;
constexpr uint32_t EXACT_FS_CREATE = 1u << 2;
constexpr uint32_t EXACT_FS_TRUNCATE = 1u << 3;
constexpr uint32_t kMaxHostWriteChunk = 0x7FFFFFFFu;

struct IoVecMetadata {
  bool isArrayBuffer;
  size_t byteOffset;
  size_t byteLength;
};

struct FdEntry {
  uint64_t runtimeNonce;
  uint64_t owner;
  std::string path;
  bool canRead;
  bool canWrite;
  bool processIpc;
  std::string presentedHandleId;
  std::shared_ptr<int> retainedParent;
  uint64_t objectDevice = 0;
  uint64_t objectInode = 0;
  bool objectIdentityKnown = false;
};

static std::mutex g_fd_registry_mutex;
static std::unordered_map<int, FdEntry> g_fd_registry;
static std::mutex g_parent_fd_cache_mutex;
static std::unordered_map<std::string, std::weak_ptr<int>> g_parent_fd_cache;
struct TransferableFdOwner {
  uint64_t runtimeNonce;
  uint64_t principal;
  uint64_t objectDevice;
  uint64_t objectInode;
  bool objectIdentityKnown;
};
static std::unordered_map<int, TransferableFdOwner> g_transferable_fds;
static thread_local const std::vector<uint64_t>* g_typed_principal_stack = nullptr;

static std::string fsErrorMessage(
    int errn,
    const char* syscall,
    const std::string& path,
    const std::string& dest);

void exactCleanupRuntimeFileDescriptors(uint64_t runtimeNonce) {
  {
    std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
    for (auto it = g_fd_registry.begin(); it != g_fd_registry.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        if (!it->second.processIpc) {
          struct stat sb = {};
          const bool sameObject =
              it->second.objectIdentityKnown &&
              ::fstat(it->first, &sb) == 0 &&
              it->second.objectDevice == static_cast<uint64_t>(sb.st_dev) &&
              it->second.objectInode == static_cast<uint64_t>(sb.st_ino);
          // Keep the registry mutex across the final identity check and close:
          // another runtime cannot register a reused integer in the gap. A
          // descriptor closed/reused outside this registry is simply revoked,
          // never closed as though it were still the old runtime's object.
          if (sameObject) ::close(it->first);
        }
        g_transferable_fds.erase(it->first);
        it = g_fd_registry.erase(it);
      } else {
        ++it;
      }
    }
    for (auto it = g_transferable_fds.begin(); it != g_transferable_fds.end();) {
      if (it->second.runtimeNonce == runtimeNonce) {
        it = g_transferable_fds.erase(it);
      } else {
        ++it;
      }
    }
  }
  {
    std::lock_guard<std::mutex> lock(g_parent_fd_cache_mutex);
    const auto prefix = std::to_string(runtimeNonce) + ":";
    for (auto it = g_parent_fd_cache.begin(); it != g_parent_fd_cache.end();) {
      if (it->first.rfind(prefix, 0) == 0 || it->second.expired()) {
        it = g_parent_fd_cache.erase(it);
      } else {
        ++it;
      }
    }
  }
}

std::vector<uint64_t> exactCollectTypedPrincipalStack() {
  std::vector<uint64_t> principals;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  if (g_vm_runtime != nullptr) {
    constexpr size_t kMaxStack = 256;
    uint32_t ids[kMaxStack];
    size_t count = ex_hermes_vm_collect_package_ids(g_vm_runtime, ids, kMaxStack);
    principals.reserve(count + 1);
    for (size_t index = 0; index < count; ++index) {
      auto id = static_cast<uint64_t>(ids[index]);
      if (principals.empty() || principals.back() != id) principals.push_back(id);
    }
    if (count == kMaxStack) {
      principals.push_back(static_cast<uint64_t>(kNoUserPrincipalId));
    }
  }
#endif
  // A captured scheduler/owner stack is an additional constrained dimension,
  // not a replacement for live callback frames. On a worker thread
  // g_vm_runtime is null, so this safely restores only the captured stack; on
  // the runtime thread a callback authored by B and scheduled by A becomes
  // [B, A] and the Rust boundary intersects both.
  // @ref LLP 0021#decision-staging-and-principal-semantics
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
  // Scheduler records (notably repeating timers) may be erased by their own
  // callback. Keep the constrained principal set alive for the full dynamic
  // scope instead of pointing into the scheduler container.
  g_typed_principal_stack = &principals_;
}

ScopedTypedPrincipalStack::~ScopedTypedPrincipalStack() {
  g_typed_principal_stack = previous_;
}

static int32_t ex_host_authorize_typed_fs_open(
    uint64_t module_id,
    const char* path,
    uint32_t stage,
    uint32_t surface,
    int32_t parent_fd,
    int32_t fd,
    int32_t needs_read,
    int32_t needs_write,
    const char* presented_handle_id) {
  auto principals = exactCollectTypedPrincipalStack();
  return ex_host_authorize_typed_fs_stack(
      module_id, principals.data(), principals.size(), path, stage, surface,
      parent_fd, fd, needs_read, needs_write, presented_handle_id);
}

struct FsAuthorizationGenerations {
  uint64_t negative = 0;
  uint64_t dynamic = 0;
  uint64_t handle = 0;

  bool operator==(const FsAuthorizationGenerations& other) const {
    return negative == other.negative && dynamic == other.dynamic &&
        handle == other.handle;
  }
};

struct RepeatedFsAuthorizationLease {
  bool active = false;
  FsAuthorizationGenerations generations;
};

static bool readAuthorizationGenerations(FsAuthorizationGenerations& value) {
  return ex_host_typed_generations(
             &value.negative, &value.dynamic, &value.handle) == 1;
}

// A lease is local to one retained descriptor operation, so its operation,
// principal stack, gate, path, object identities, and presented handle cannot
// vary. Only the three mutable authority generations need a cheap per-chunk
// recheck. A changed generation performs a full repeat-stage decision before
// any more bytes are observed; a concurrent publication during evaluation
// fails closed rather than caching a result across generations.
// @ref LLP 0021#handles-dynamic-authority-and-generations
static int32_t authorizeRepeatedFsWithLease(
    RepeatedFsAuthorizationLease& lease,
    uint64_t moduleId,
    const char* path,
    uint32_t surface,
    uint32_t fullStage,
    int32_t parentFd,
    int32_t fd,
    int32_t needsRead,
    int32_t needsWrite,
    const char* presentedHandleId) {
  FsAuthorizationGenerations current;
  if (!readAuthorizationGenerations(current)) return 0;
  if (lease.active && current == lease.generations) return 1;

  for (size_t attempt = 0; attempt < 3; ++attempt) {
    FsAuthorizationGenerations before;
    FsAuthorizationGenerations after;
    if (!readAuthorizationGenerations(before)) return 0;
    auto decision = ex_host_authorize_typed_fs_open(
        moduleId, path, fullStage, surface, parentFd, fd, needsRead, needsWrite,
        presentedHandleId);
    if (decision != 1 || !readAuthorizationGenerations(after)) return decision;
    if (before == after) {
      lease.active = true;
      lease.generations = after;
      return 1;
    }
  }
  return 0;
}

static bool principalMayUseProcessStdio(uint64_t principal) {
  if (principal == 0) {
    return true;
  }
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  if (principal == static_cast<uint64_t>(kRuntimePrincipalId)) {
    return true;
  }
#endif
  return false;
}

static void registerFd(
    int fd,
    const std::string& path,
    bool canRead,
    bool canWrite,
    uint64_t owner,
    const std::string& presentedHandleId = "",
    std::shared_ptr<int> retainedParent = nullptr) {
  if (fd < 0) {
    return;
  }
  struct stat sb = {};
  bool identified = ::fstat(fd, &sb) == 0;
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  g_fd_registry[fd] =
      FdEntry{exactCurrentRuntimeNonce(), owner, path, canRead, canWrite, false,
              presentedHandleId, std::move(retainedParent),
              static_cast<uint64_t>(sb.st_dev),
              static_cast<uint64_t>(sb.st_ino), identified};
}

void exactRegisterProcessIpcFd(int fd) {
  if (fd < 0) {
    return;
  }
  uint64_t owner = 0;
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  owner = static_cast<uint64_t>(kRuntimePrincipalId);
#endif
  struct stat sb = {};
  bool identified = ::fstat(fd, &sb) == 0;
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  g_fd_registry[fd] =
      FdEntry{exactCurrentRuntimeNonce(), owner,
              std::string("/dev/fd/") + std::to_string(fd), true, true, true,
              "", nullptr, static_cast<uint64_t>(sb.st_dev),
              static_cast<uint64_t>(sb.st_ino), identified};
}

static void unregisterFd(int fd) {
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  g_fd_registry.erase(fd);
  g_transferable_fds.erase(fd);
}

static void restoreFdEntry(int fd, const std::optional<FdEntry>& entry) {
  if (!entry) return;
  struct stat sb = {};
  if (::fstat(fd, &sb) != 0 ||
      (entry->objectIdentityKnown &&
       (entry->objectDevice != static_cast<uint64_t>(sb.st_dev) ||
        entry->objectInode != static_cast<uint64_t>(sb.st_ino)))) {
    return;
  }
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  g_fd_registry.emplace(fd, *entry);
}

static std::optional<FdEntry> lookupFdEntry(int fd, bool* stale = nullptr) {
  if (stale) *stale = false;
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  auto it = g_fd_registry.find(fd);
  if (it == g_fd_registry.end()) {
    return std::nullopt;
  }
  struct stat sb = {};
  if (!it->second.objectIdentityKnown || ::fstat(fd, &sb) != 0 ||
      it->second.objectDevice != static_cast<uint64_t>(sb.st_dev) ||
      it->second.objectInode != static_cast<uint64_t>(sb.st_ino)) {
    g_fd_registry.erase(it);
    g_transferable_fds.erase(fd);
    if (stale) *stale = true;
    return std::nullopt;
  }
  return it->second;
}

static FdEntry requireOwnedFd(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  auto principal = currentPrincipalId();
  bool stale = false;
  auto entry = lookupFdEntry(fd, &stale);
  if (!entry) {
    if (!stale && fd >= STDIN_FILENO && fd <= STDERR_FILENO &&
        (principalMayUseProcessStdio(principal) || isAllowAll())) {
      return FdEntry{
          exactCurrentRuntimeNonce(), principal, std::string("/dev/fd/") + std::to_string(fd), true, true, false, "", nullptr};
    }
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": bad file descriptor");
  }
  if (entry->runtimeNonce != exactCurrentRuntimeNonce() ||
      (!isAllowAll() && entry->owner != principal)) {
    throw facebook::jsi::JSError(
        runtime, fsErrorMessage(EACCES, syscall, entry->path, ""));
  }
  return *entry;
}

static void requireFdRead(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  auto entry = requireOwnedFd(runtime, fd, syscall);
  if (isAllowAll()) return;
  if (!entry.canRead) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": fd not opened for reading");
  }
  // Standard streams are process-owned stdio capabilities, not path-open
  // capabilities. All other descriptors require an identity-bound registry
  // entry; do not manufacture a missing retained filesystem parent.
  if (fd >= STDIN_FILENO && fd <= STDERR_FILENO && !entry.retainedParent) return;
  if (ex_host_is_armed() == 1) {
    const char* handle = entry.presentedHandleId.empty()
        ? nullptr
        : entry.presentedHandleId.c_str();
    if (ex_host_authorize_typed_fs_open(
            entry.owner, entry.path.c_str(), 2, 0,
            entry.retainedParent ? *entry.retainedParent : -1, fd, 1, 0, handle) != 1) {
      throw facebook::jsi::JSError(
          runtime, fsErrorMessage(EACCES, syscall, entry.path, ""));
    }
  } else if (!checkCapability("fs:read:" + entry.path)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

static void requireFdWrite(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  auto entry = requireOwnedFd(runtime, fd, syscall);
  if (isAllowAll()) return;
  if (!entry.canWrite) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": fd not opened for writing");
  }
  if (fd >= STDIN_FILENO && fd <= STDERR_FILENO && !entry.retainedParent) return;
  if (ex_host_is_armed() == 1) {
    const char* handle = entry.presentedHandleId.empty()
        ? nullptr
        : entry.presentedHandleId.c_str();
    if (ex_host_authorize_typed_fs_open(
            entry.owner, entry.path.c_str(), 2, 0,
            entry.retainedParent ? *entry.retainedParent : -1, fd, 0, 1, handle) != 1) {
      throw facebook::jsi::JSError(
          runtime, fsErrorMessage(EACCES, syscall, entry.path, ""));
    }
  } else if (!checkCapability("fs:write:" + entry.path)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

static void requireFdMetadataWrite(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  requireFdWrite(runtime, fd, syscall);
}

static void requireFdList(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  auto entry = requireOwnedFd(runtime, fd, syscall);
  if (isAllowAll()) return;
  if (fd >= STDIN_FILENO && fd <= STDERR_FILENO && !entry.retainedParent) return;
  if (ex_host_is_armed() == 1) {
    const char* handle = entry.presentedHandleId.empty()
        ? nullptr
        : entry.presentedHandleId.c_str();
    if (ex_host_authorize_typed_fs_open(
            entry.owner, entry.path.c_str(), 5, 0,
            entry.retainedParent ? *entry.retainedParent : -1, fd, 0, 0, handle) != 1) {
      throw facebook::jsi::JSError(
          runtime, fsErrorMessage(EACCES, syscall, entry.path, ""));
    }
  } else if (!checkCapability("fs:list:" + entry.path)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

void exactRegisterTransferableFd(int fd, uint64_t owner) {
  if (fd < 0) {
    return;
  }
  struct stat sb = {};
  bool identified = ::fstat(fd, &sb) == 0;
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  g_transferable_fds[fd] = TransferableFdOwner{
      exactCurrentRuntimeNonce(), owner, static_cast<uint64_t>(sb.st_dev),
      static_cast<uint64_t>(sb.st_ino), identified};
}

void exactRegisterReceivedFdForCurrentPrincipal(int fd) {
  exactRegisterTransferableFd(fd, currentPrincipalId());
}

bool exactConsumeTransferableFdForCurrentPrincipal(int fd) {
  if (fd < 0) {
    return false;
  }
  auto principal = currentPrincipalId();
  std::lock_guard<std::mutex> lock(g_fd_registry_mutex);
  auto it = g_transferable_fds.find(fd);
  if (it == g_transferable_fds.end() ||
      it->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      (!isAllowAll() && it->second.principal != principal)) {
    return false;
  }
  struct stat sb = {};
  if (!it->second.objectIdentityKnown || ::fstat(fd, &sb) != 0 ||
      it->second.objectDevice != static_cast<uint64_t>(sb.st_dev) ||
      it->second.objectInode != static_cast<uint64_t>(sb.st_ino)) {
    g_transferable_fds.erase(it);
    return false;
  }
  g_transferable_fds.erase(it);
  return true;
}

void exactRequireOwnedIpcFd(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  struct stat st = {};
  if (::fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode)) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": bad file descriptor");
  }
  auto entry = lookupFdEntry(fd);
  if (!entry) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": bad file descriptor");
  }
  if (entry->runtimeNonce != exactCurrentRuntimeNonce() || !entry->processIpc) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

void exactRequireTransferableFd(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  if (!exactConsumeTransferableFdForCurrentPrincipal(fd)) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": Permission denied");
  }
}

void exactRequireFdReadable(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  requireFdRead(runtime, fd, syscall);
}

void exactRequireFdWritable(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  requireFdWrite(runtime, fd, syscall);
}

static bool parseIoVecArguments(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value,
    std::vector<std::vector<uint8_t>>& buffers,
    std::vector<struct iovec>& iovecs,
    std::vector<IoVecMetadata>* metadata,
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
    isArrayBuffer = entryObj.isArrayBuffer(runtime);
    if (!extractArrayBufferView(runtime, entryObj, source, byteLength, &byteOffset)) {
      return false;
    }
    if (byteLength > 0 && !source) {
      return false;
    }
    std::vector<uint8_t> bytes(byteLength);
    if (copyInput && source && byteLength > 0) {
      std::copy(source, source + byteLength, bytes.begin());
    }
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

static void fsErrnoCodeAndDescription(
    int errn,
    const char*& code,
    const char*& description) {
  code = "UNKNOWN";
  description = "unknown error";
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
    case ENXIO: code = "ENXIO"; description = "no such device or address"; break;
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
}

static std::string fsErrorMessage(
    int errn,
    const char* syscall,
    const std::string& path,
    const std::string& dest = "") {
  const char* code = nullptr;
  const char* description = nullptr;
  fsErrnoCodeAndDescription(errn, code, description);
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

static std::pair<std::string, std::string> splitParentAndName(
    const std::string& path) {
  // Find the separator before the final component, not a trailing separator.
  // Keep trailing separators in the name so openat preserves ENOTDIR for
  // `file/`, while directory paths remain valid. Root is represented as `.`
  // relative to a retained `/` descriptor.
  auto end = path.find_last_not_of('/');
  if (end == std::string::npos) return {"/", "."};
  auto slash = path.rfind('/', end);
  if (slash == std::string::npos) return {".", path};
  if (slash == 0) return {"/", path.substr(1)};
  return {path.substr(0, slash), path.substr(slash + 1)};
}

static std::shared_ptr<int> retainedFd(int fd) {
  return std::shared_ptr<int>(new int(fd), [](int* retained) {
    if (*retained >= 0) ::close(*retained);
    delete retained;
  });
}

static std::shared_ptr<int> retainedParentFd(int fd) {
  constexpr size_t kMaxParentFdCacheKeys = 4096;
  struct stat sb = {};
  if (fd < 0 || ::fstat(fd, &sb) != 0) return retainedFd(fd);
  std::string key = std::to_string(exactCurrentRuntimeNonce()) + ":" +
      std::to_string(static_cast<uint64_t>(sb.st_dev)) + ":" +
      std::to_string(static_cast<uint64_t>(sb.st_ino));
  std::lock_guard<std::mutex> lock(g_parent_fd_cache_mutex);
  if (auto it = g_parent_fd_cache.find(key); it != g_parent_fd_cache.end()) {
    if (auto existing = it->second.lock()) {
      ::close(fd);
      return existing;
    }
    g_parent_fd_cache.erase(it);
  }
  if (g_parent_fd_cache.size() >= kMaxParentFdCacheKeys) {
    for (auto it = g_parent_fd_cache.begin(); it != g_parent_fd_cache.end();) {
      if (it->second.expired()) {
        it = g_parent_fd_cache.erase(it);
      } else {
        ++it;
      }
    }
    // A live entry remains owned by its open child fds even if its weak lookup
    // key is evicted. Bound process-global metadata under workloads that keep
    // thousands of directories active; a later lookup simply opens another
    // retained parent for the evicted directory.
    while (g_parent_fd_cache.size() >= kMaxParentFdCacheKeys) {
      g_parent_fd_cache.erase(g_parent_fd_cache.begin());
    }
  }
  auto retained = retainedFd(fd);
  g_parent_fd_cache[key] = retained;
  return retained;
}

static std::optional<bool> targetAbsentAt(int parentFd, const std::string& name) {
  struct stat sb = {};
  if (::fstatat(parentFd, name.c_str(), &sb, AT_SYMLINK_NOFOLLOW) == 0) {
    return false;
  }
  if (errno == ENOENT) return true;
  return std::nullopt;
}

struct ArmedOpenResult {
  int fd = -1;
  bool created = false;
};

static void pauseBeforeArmedExclusiveCreateForTest() {
  const char* value = std::getenv("IBEX_TEST_ARMED_CREATE_PAUSE_MS");
  if (!value || !*value) return;
  char* end = nullptr;
  auto milliseconds = std::strtoull(value, &end, 10);
  if (end == value || *end != '\0') return;
  milliseconds = std::min<unsigned long long>(milliseconds, 5000);
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static bool denyArmedOpenCommitForTest() {
  return env_flag_enabled("IBEX_TEST_ARMED_DENY_OPEN_COMMIT");
}

// Open an already-parent-bound target without ever inferring ownership of a
// newly created name from a racy precheck. Every rollback-eligible creation is
// established by a successful O_CREAT|O_EXCL syscall. If a non-exclusive
// O_CREAT races between absent/existing states, rediscover and reauthorize the
// new state, then retry either an existing-only open or an exclusive create.
static ArmedOpenResult openArmedTargetAtomically(
    uint64_t principal,
    const std::string& path,
    const std::string& name,
    uint32_t surface,
    int parentFd,
    int flags,
    int extraFlags,
    int mode,
    bool canRead,
    bool canWrite,
    const char* presented) {
  constexpr size_t kMaxStateRaces = 64;
  const bool mayCreate = (flags & O_CREAT) != 0;
  const bool exclusive = (flags & O_EXCL) != 0;
  const int baseFlags = (flags & ~O_TRUNC) | extraFlags;
  for (size_t attempt = 0; attempt < kMaxStateRaces; ++attempt) {
    auto absent = targetAbsentAt(parentFd, name);
    if (!absent) return {};
    if (ex_host_authorize_typed_fs_open(
            principal, path.c_str(), 4, surface, parentFd, -1,
            canRead ? 1 : 0, canWrite ? 1 : 0, presented) != 1) {
      errno = EACCES;
      return {};
    }
    if (!mayCreate) {
      return ArmedOpenResult{
          ::openat(parentFd, name.c_str(), baseFlags, mode), false};
    }
    if (exclusive) {
      if (!*absent) {
        errno = EEXIST;
        return {};
      }
      int fd = ::openat(parentFd, name.c_str(), baseFlags, mode);
      return ArmedOpenResult{fd, fd >= 0};
    }
    if (*absent) {
      pauseBeforeArmedExclusiveCreateForTest();
      int fd = ::openat(
          parentFd, name.c_str(), baseFlags | O_CREAT | O_EXCL, mode);
      if (fd >= 0) return ArmedOpenResult{fd, true};
      if (errno == EEXIST) continue;
      return {};
    }
    int fd = ::openat(
        parentFd, name.c_str(), baseFlags & ~(O_CREAT | O_EXCL), mode);
    if (fd >= 0) return ArmedOpenResult{fd, false};
    if (errno != ENOENT) return {};
  }
  errno = EAGAIN;
  return {};
}

static bool sameObjectAt(int parentFd, const std::string& name, int fd) {
  struct stat opened = {};
  struct stat named = {};
  return ::fstat(fd, &opened) == 0 &&
      ::fstatat(parentFd, name.c_str(), &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      opened.st_dev == named.st_dev && opened.st_ino == named.st_ino;
}

static bool rollbackCreatedFile(int parentFd, const std::string& name, int fd) {
  if (!sameObjectAt(parentFd, name, fd)) {
    errno = EBUSY;
    return false;
  }
  return ::unlinkat(parentFd, name.c_str(), 0) == 0;
}

static bool rollbackCreatedDirectory(int parentFd, const std::string& name, int fd) {
  if (!sameObjectAt(parentFd, name, fd)) {
    errno = EBUSY;
    return false;
  }
  return ::unlinkat(parentFd, name.c_str(), AT_REMOVEDIR) == 0;
}

static int metadataOpenFlags() {
#if defined(__APPLE__)
  return O_EVTONLY | O_NONBLOCK;
#elif defined(O_PATH)
  return O_PATH | O_NONBLOCK;
#else
  return O_RDONLY | O_NONBLOCK;
#endif
}

static std::optional<std::string> resolvedPathForFd(int fd) {
#if defined(__APPLE__)
  std::array<char, PATH_MAX> path = {};
  if (::fcntl(fd, F_GETPATH, path.data()) != 0) return std::nullopt;
  return std::string(path.data());
#else
  std::array<char, PATH_MAX> path = {};
  auto link = std::string("/proc/self/fd/") + std::to_string(fd);
  ssize_t length = ::readlink(link.c_str(), path.data(), path.size() - 1);
  if (length < 0) return std::nullopt;
  path[static_cast<size_t>(length)] = '\0';
  return std::string(path.data(), static_cast<size_t>(length));
#endif
}

struct TypedPathDescriptors {
  std::shared_ptr<int> parent;
  std::shared_ptr<int> target;
};

static std::pair<std::shared_ptr<int>, std::string> prepareArmedReadTarget(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    uint32_t surface,
    const std::string& presentedHandle) {
  uint64_t principal = currentPrincipalId();
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 0, surface, -1, -1, 1, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto parentAndName = splitParentAndName(path);
  auto parentPath = std::move(parentAndName.first);
  auto name = std::move(parentAndName.second);
  int parentRaw = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parentRaw < 0) throwFsError(runtime, "open", path);
  auto parent = retainedParentFd(parentRaw);
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 3, surface, *parent, -1, 1, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  // A missing read target must reach openat so callers receive ENOENT. There
  // is no fs:read effect for an absent-create object to authorize.
  auto absent = targetAbsentAt(*parent, name);
  if (!absent) throwFsError(runtime, "open", path);
  if (!*absent &&
      ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 4, surface, *parent, -1, 1, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  return {std::move(parent), std::move(name)};
}

static TypedPathDescriptors openArmedListTarget(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    uint32_t surface,
    int targetFlags,
    const std::string& presentedHandle) {
  uint64_t principal = currentPrincipalId();
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 0, surface, -1, -1, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto parentAndName = splitParentAndName(path);
  auto parentPath = std::move(parentAndName.first);
  auto name = std::move(parentAndName.second);
  int parentRaw = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parentRaw < 0) throwFsError(runtime, "open", path);
  auto parent = retainedParentFd(parentRaw);
  if (name.empty() ||
      ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 3, surface, *parent, -1, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  int targetRaw = ::openat(
      *parent, name.c_str(), targetFlags | O_NOFOLLOW | O_CLOEXEC);
  if (targetRaw < 0) throwFsError(runtime, "open", path);
  auto target = retainedFd(targetRaw);
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 5, surface, *parent, targetRaw, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  return TypedPathDescriptors{std::move(parent), std::move(target)};
}

static TypedPathDescriptors openArmedLinkTarget(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    uint32_t surface,
    const std::string& presentedHandle) {
  uint64_t principal = currentPrincipalId();
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 0, surface, -1, -1, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto parentAndName = splitParentAndName(path);
  auto parentPath = std::move(parentAndName.first);
  auto name = std::move(parentAndName.second);
  int parentRaw = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parentRaw < 0) throwFsError(runtime, "open", path);
  auto parent = retainedParentFd(parentRaw);
  if (name.empty() ||
      ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 3, surface, *parent, -1, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
#if defined(__APPLE__)
  int targetRaw = ::openat(
      *parent, name.c_str(), O_RDONLY | O_SYMLINK | O_NONBLOCK | O_CLOEXEC);
#elif defined(O_PATH)
  int targetRaw = ::openat(*parent, name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
#else
  int targetRaw = -1;
  errno = ENOTSUP;
#endif
  if (targetRaw < 0) throwFsError(runtime, "lstat", path);
  auto target = retainedFd(targetRaw);
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 5, surface, *parent, targetRaw, 0, 0,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  return TypedPathDescriptors{std::move(parent), std::move(target)};
}

static TypedPathDescriptors openArmedWriteTarget(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    uint32_t surface,
    int targetFlags,
    int mode,
    bool authorizeList,
    const std::string& presentedHandle) {
  // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — Preauthorize creation and delay truncation until the retained target commits.
  uint64_t principal = currentPrincipalId();
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  if (authorizeList && ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 0, surface, -1, -1, 0, 1,
          presented) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto parentAndName = splitParentAndName(path);
  auto parentPath = std::move(parentAndName.first);
  auto name = std::move(parentAndName.second);
  int parentRaw = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parentRaw < 0) throwFsError(runtime, "open", path);
  auto parent = retainedParentFd(parentRaw);
  if (name.empty() ||
      (authorizeList && ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 3, surface, *parent, -1, 0, 1,
          presented) != 1)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto opened = openArmedTargetAtomically(
      principal, path, name, surface, *parent, targetFlags,
      O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, mode, false, true, presented);
  int targetRaw = opened.fd;
  const bool created = opened.created;
  if (targetRaw < 0) throwFsError(runtime, "open", path);
  auto target = retainedFd(targetRaw);
  struct stat sb = {};
  if (::fstat(targetRaw, &sb) != 0 || !S_ISREG(sb.st_mode)) {
    if (created) rollbackCreatedFile(*parent, name, targetRaw);
    errno = EACCES;
    throwFsError(runtime, "open", path);
  }
  if (denyArmedOpenCommitForTest() || ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 1, surface, *parent, targetRaw, 0, 1,
          presented) != 1) {
    if (created) rollbackCreatedFile(*parent, name, targetRaw);
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if ((targetFlags & O_TRUNC) != 0 && ::ftruncate(targetRaw, 0) != 0) {
    int saved = errno;
    if (created) rollbackCreatedFile(*parent, name, targetRaw);
    errno = saved;
    throwFsError(runtime, "open", path);
  }
  return TypedPathDescriptors{std::move(parent), std::move(target)};
}

static void writeArmedBytes(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    uint32_t surface,
    const std::string& presentedHandle,
    const TypedPathDescriptors& descriptors,
    const std::vector<uint8_t>& data) {
  size_t offset = 0;
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  while (offset < data.size()) {
    if (ex_host_authorize_typed_fs_open(
            currentPrincipalId(), path.c_str(), 2, surface,
            *descriptors.parent, *descriptors.target, 0, 1,
            presented) != 1) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    ssize_t amount;
    do {
      amount = ::write(
          *descriptors.target, data.data() + offset, data.size() - offset);
    } while (amount < 0 && errno == EINTR);
    if (amount < 0) {
      normalizeWriteErrno(*descriptors.target);
      throwFsError(runtime, "write", path);
    }
    if (amount == 0) {
      errno = EIO;
      throwFsError(runtime, "write", path);
    }
    offset += static_cast<size_t>(amount);
  }
}

static void createArmedDirectory(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    int mode) {
  // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — Directory creation is authorized against a retained parent, then commits the actual created directory identity.
  constexpr uint32_t kMkdirSurface = 12;
  uint64_t principal = currentPrincipalId();
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 0, kMkdirSurface, -1, -1, 0, 1,
          nullptr) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto parentAndName = splitParentAndName(path);
  auto parentPath = std::move(parentAndName.first);
  auto name = std::move(parentAndName.second);
  int parentRaw = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parentRaw < 0) throwFsError(runtime, "mkdir", path);
  auto parent = retainedParentFd(parentRaw);
  if (name.empty() ||
      ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 3, kMkdirSurface, *parent, -1, 0, 1,
          nullptr) != 1 ||
      ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 4, kMkdirSurface, *parent, -1, 0, 1,
          nullptr) != 1) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (::mkdirat(*parent, name.c_str(), static_cast<mode_t>(mode)) != 0) {
    throwFsError(runtime, "mkdir", path);
  }
  int directoryRaw = ::openat(
      *parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (directoryRaw < 0) {
    int saved = errno;
    ::unlinkat(*parent, name.c_str(), AT_REMOVEDIR);
    errno = saved;
    throwFsError(runtime, "mkdir", path);
  }
  auto directory = retainedFd(directoryRaw);
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 1, kMkdirSurface, *parent, directoryRaw,
          0, 1, nullptr) != 1) {
    if (!rollbackCreatedDirectory(*parent, name, directoryRaw)) {
      int saved = errno;
      throw facebook::jsi::JSError(
          runtime,
          "Permission denied; mkdir rollback failed: " +
              fsErrorMessage(saved, "rmdir", path));
    }
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
}

// Parse a Node open() flags argument (a string like "r"/"w+"/"ax", or numeric
// POSIX flags) into POSIX open(2) flags. Shared by __exactFsOpen and the async
// readFile/writeFile natives, which perform their own open on a worker thread.
static int parseOpenFlagsArg(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value* args,
    size_t count,
    size_t index) {
  int posixFlags = O_RDONLY;
  if (count > index && args[index].isString()) {
    auto flagStr = args[index].toString(runtime).utf8(runtime);
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
  } else if (count > index && args[index].isNumber()) {
    posixFlags = static_cast<int>(args[index].asNumber());
  }
  return posixFlags;
}

// @ref LLP 0013#policy — gate the open on the access the flags actually
// request: an open-for-write (w/a/r+/O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/
// O_APPEND) requires fs:write, not merely fs:read. Runs on the JS thread
// (capability checks must never move to a worker: the deputy stack that
// checkCapability consults is thread-local to the JS thread). (ENG-22639)
static void classifyOpenAccess(
    int posixFlags,
    bool& needsRead,
    bool& needsWrite) {
  int access = posixFlags & O_ACCMODE;
  needsWrite = access == O_WRONLY || access == O_RDWR ||
      (posixFlags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
  needsRead = access == O_RDONLY || access == O_RDWR;
  // An exotic/invalid access mode (O_ACCMODE == 3 on Linux, where the fd
  // still enables fstat/fchmod/existence probing) must not skip the gate.
  // Every open requires at least fs:read, so the flag math can only
  // *widen* the requirement, never eliminate it. (ENG-22639)
  if (!needsWrite && !needsRead) {
    needsRead = true;
  }
}

static void requireOpenCapability(
    facebook::jsi::Runtime& runtime,
    const std::string& path,
    int posixFlags,
    bool& needsRead,
    bool& needsWrite) {
  classifyOpenAccess(posixFlags, needsRead, needsWrite);
  if (!isAllowAll()) {
    if (needsWrite && !checkCapability("fs:write:" + path)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    if (needsRead && !checkCapability("fs:read:" + path)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
  }
}

// Serialize a struct stat as the JSON payload shape shared by __exactStat /
// __exactLstat (Rust side) and __exactFsFstatSync / __exactFsStatAsync.
static std::string statJsonFromStat(const struct stat& sb) {
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
  return oss.str();
}

// ---------------------------------------------------------------------------
// True-async fs natives (ENG-23497). The callback/promise fs API used to run
// every syscall synchronously on the JS thread and merely defer the callback,
// so a large readFile stalled timers and sockets. These natives run the
// blocking I/O on a bounded worker pool and deliver the result back on the JS
// thread via pushRuntimeCallback — the same wake-driven discipline as
// __exactDnsLookupAsync. Argument validation and capability checks stay on the
// JS thread (the capability deputy stack is JS-thread-local); the worker only
// touches plain data. @ref LLP 0003#blocking-work-worker-pools — pool
// discipline: immortal singleton, queue-don't-early-reject, keepalive
// counter, no JSI off-thread.
// ---------------------------------------------------------------------------

// Result of a blocking fs call performed off the JS thread. Plain data only —
// no JSI — so it can cross the thread boundary. errno/syscall/path are
// captured on the worker thread at failure time and rehydrated into a
// Node-shaped error (code/errno/syscall/path) on the JS thread.
struct FsAsyncResult {
  enum class Kind { Undefined, Bytes, Json, Number };
  bool ok = false;
  Kind kind = Kind::Undefined;
  std::vector<uint8_t> bytes;
  std::string json;
  double number = 0;
  // Async open publishes ownership metadata on the JS thread before the fd
  // is resolved to user code. Workers never mutate the capability registry.
  bool registerOpenedFd = false;
  std::shared_ptr<int> openedFdGuard;
  std::string openedPath;
  bool openedCanRead = false;
  bool openedCanWrite = false;
  uint64_t openedOwner = 0;
  std::string openedPresentedHandle;
  std::shared_ptr<int> openedRetainedParent;
  int errnoValue = 0;
  std::string syscall;
  std::string path;
  // fs.readFile refuses files above Node's 2 GiB I/O cap with
  // ERR_FS_FILE_TOO_LARGE (a RangeError, not an errno error).
  bool tooLarge = false;
  double tooLargeSize = 0;
};

static FsAsyncResult fsAsyncOk(FsAsyncResult::Kind kind = FsAsyncResult::Kind::Undefined) {
  FsAsyncResult result;
  result.ok = true;
  result.kind = kind;
  return result;
}

static FsAsyncResult fsAsyncError(int errn, const char* syscall, const std::string& path = "") {
  FsAsyncResult result;
  result.ok = false;
  result.errnoValue = errn;
  result.syscall = syscall;
  result.path = path;
  return result;
}

// Bounded worker pool that runs blocking fs syscalls off the JS thread. Same
// discipline as DnsWorkerPool / FetchWorkerPool: lazily spawn detached workers
// up to a cap, bound the backlog, park idle workers on a condvar.
class FsWorkerPool {
 public:
  static FsWorkerPool& instance() {
    // Intentionally leaked (immortal heap singleton): a function-local
    // `static FsWorkerPool` is destructed during exit() while workers are
    // still parked in cv_.wait(), and destroying a mutex/condvar with waiters
    // is UB that deadlocks the process inside glibc's pthread destructors
    // (Linux-only; macOS never reproduces it — see native_fetch_linux.cc's
    // FetchWorkerPool and ENG-23471/ENG-23498). Workers are detached, so
    // leaking the pool lets exit() proceed normally.
    static FsWorkerPool* pool = new FsWorkerPool();
    return *pool;
  }

  bool enqueue(std::function<void()> job, std::string& error) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (queue_.size() >= maxQueue()) {
        // Fail loudly rather than growing without bound.
        // @ref LLP 0006#degrade-diagnostics-never-the-caller
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

  static size_t maxQueue() {
    // Deterministic failure injection for native resource-safety tests. The
    // production default remains bounded at 1024.
    const char* value = std::getenv("IBEX_TEST_FS_WORKER_MAX_QUEUE");
    if (!value || !*value) return kMaxQueue;
    char* end = nullptr;
    auto parsed = std::strtoull(value, &end, 10);
    return end && *end == '\0' ? static_cast<size_t>(parsed) : kMaxQueue;
  }

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

// Rehydrate an FsAsyncResult failure into a Node-shaped Error on the JS
// thread: message matches the sync natives' fsErrorMessage format, and
// code/errno/syscall/path ride as structured properties so fs.js does not
// have to re-parse the message (the sync path derives them from the message;
// carrying them structurally keeps the shapes identical without string
// parsing).
static facebook::jsi::Value makeFsAsyncErrorValue(
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
  const char* code = nullptr;
  const char* description = nullptr;
  fsErrnoCodeAndDescription(result.errnoValue, code, description);
  auto message = fsErrorMessage(result.errnoValue, result.syscall.c_str(), result.path);
  facebook::jsi::JSError jsError(rt, message);
  facebook::jsi::Value err(rt, jsError.value());
  auto obj = err.asObject(rt);
  obj.setProperty(rt, "code", facebook::jsi::String::createFromUtf8(rt, code));
  obj.setProperty(rt, "errno", facebook::jsi::Value(result.errnoValue));
  obj.setProperty(
      rt, "syscall", facebook::jsi::String::createFromUtf8(rt, result.syscall));
  if (!result.path.empty()) {
    obj.setProperty(rt, "path", facebook::jsi::String::createFromUtf8(rt, result.path));
  }
  return err;
}

static facebook::jsi::Value makeFsWorkerQueueErrorValue(
    facebook::jsi::Runtime& rt,
    const std::string& message) {
  facebook::jsi::JSError jsError(rt, message);
  auto value = facebook::jsi::Value(rt, jsError.value());
  if (value.isObject()) {
    value.asObject(rt).setProperty(
        rt, "code",
        facebook::jsi::String::createFromUtf8(
            rt, "ERR_FS_WORKER_QUEUE_FULL"));
  }
  return value;
}

// Build a Promise whose `work` runs on an fs worker thread and whose
// resolution runs on the JS thread via pushRuntimeCallback. The caller must
// have already validated arguments and enforced capabilities on the JS
// thread. pending_fs_ops keeps the event loop alive while the op is in
// flight (same keepalive discipline as pending_dns_lookups).
static facebook::jsi::Value startFsAsync(
    ExactHermesRuntime* handle,
    facebook::jsi::Runtime& runtime,
    std::function<FsAsyncResult()> work,
    std::function<void()> onEnqueueFailure = {}) {
  // Capture the scheduling principal on the JS thread so the resolved
  // continuation is attributed to the caller, not a bare native frame.
  uint64_t principal = currentPrincipalId();
  auto principalStack =
      std::make_shared<std::vector<uint64_t>>(exactCollectTypedPrincipalStack());
  auto workPtr = std::make_shared<std::function<FsAsyncResult()>>(std::move(work));
  auto promiseCtor = runtime.global().getPropertyAsFunction(runtime, "Promise");
  auto executor = facebook::jsi::Function::createFromHostFunction(
      runtime,
      facebook::jsi::PropNameID::forAscii(runtime, "executor"),
      2,
      [handle, principal, principalStack, workPtr, onEnqueueFailure](
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

        if (!exactPinRuntimeNativeWorker(handle)) {
          throw facebook::jsi::JSError(rt, "FS async: runtime is shutting down");
        }
        // Mark the op in flight before dispatching so the event loop stays
        // alive across the worker call even with no other pending work.
        handle->pending_fs_ops.fetch_add(1, std::memory_order_relaxed);

        std::string enqueueError;
        auto resultPtr = std::make_shared<FsAsyncResult>();
        bool queued = FsWorkerPool::instance().enqueue(
            [handle, principal, principalStack, workPtr, resolve, reject,
             resultPtr]() mutable {
              auto workerPin = std::unique_ptr<ExactHermesRuntime, void (*)(ExactHermesRuntime*)>(
                  handle, exactUnpinRuntimeNativeWorker);
              // shared_ptr wrapper: std::function requires a copyable callable,
              // and a readFile result can be hundreds of MB — share it instead
              // of copying, and move the bytes into the JS heap at delivery.
              ScopedRuntimeSecurityContext securityContext(handle);
              ScopedTypedPrincipalStack typedStack(*principalStack);
              try {
                *resultPtr = (*workPtr)();
              } catch (const std::bad_alloc&) {
                *resultPtr = fsAsyncError(ENOMEM, "fs-worker");
              } catch (const std::exception&) {
                *resultPtr = fsAsyncError(EIO, "fs-worker");
              } catch (...) {
                *resultPtr = fsAsyncError(EIO, "fs-worker");
              }
              if (resultPtr->registerOpenedFd) {
                // The worker has no ambient JS principal. Carry the principal
                // captured at scheduling time with the result so delivery can
                // publish the fd under the correct owner explicitly.
                resultPtr->openedOwner = principal;
              }
              // The Promise executor host function may live until GC. Drop
              // the completed work closure now so dup'd and retained fds are
              // released at completion rather than at some later collection.
              *workPtr = {};
              auto runtimeResolve = std::move(resolve);
              auto runtimeReject = std::move(reject);
              bool delivered = false;
              pushRuntimeCallback(
                  handle,
                  [handle, principal, resolve = std::move(runtimeResolve),
                   reject = std::move(runtimeReject), resultPtr](
                      facebook::jsi::Runtime& rt) {
                    ScopedNativePrincipal nativePrincipal(principal);
                    try {
                      if (resultPtr->ok) {
                        if (resultPtr->registerOpenedFd) {
                          registerFd(
                              static_cast<int>(resultPtr->number),
                              resultPtr->openedPath,
                              resultPtr->openedCanRead, resultPtr->openedCanWrite,
                              resultPtr->openedOwner,
                              resultPtr->openedPresentedHandle,
                              std::move(resultPtr->openedRetainedParent));
                          if (resultPtr->openedFdGuard) *resultPtr->openedFdGuard = -1;
                        }
                        switch (resultPtr->kind) {
                          case FsAsyncResult::Kind::Bytes:
                            resolve->call(
                                rt, makeUint8Array(rt, std::move(resultPtr->bytes)));
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
                  }, &delivered);
              handle->pending_fs_ops.fetch_sub(1, std::memory_order_relaxed);
              if (!delivered && resultPtr->ok && resultPtr->registerOpenedFd) {
                ::close(static_cast<int>(resultPtr->number));
                if (resultPtr->openedFdGuard) *resultPtr->openedFdGuard = -1;
              }
            },
            enqueueError);
        if (!queued) {
          handle->pending_fs_ops.fetch_sub(1, std::memory_order_relaxed);
          exactUnpinRuntimeNativeWorker(handle);
          if (onEnqueueFailure) onEnqueueFailure();
          // The Promise may retain its executor (and therefore workPtr) after
          // synchronous rejection. No worker owns this callable because
          // enqueue failed, so clear it now to release RAII fd captures.
          *workPtr = {};
          reject->call(rt, makeFsWorkerQueueErrorValue(rt, enqueueError));
        }
        return facebook::jsi::Value::undefined();
      });
  return promiseCtor.callAsConstructor(runtime, executor);
}

// Node caps fs.readFile at 2 GiB (kIoMaxLength); fs.js enforces the same via
// ERR_FS_FILE_TOO_LARGE on the sync path.
static constexpr double kMaxReadFileBytes = 2147483647.0;

// Read the remainder of an already-open fd. No JSI: safe on a worker thread.
// Mirrors readFileSync: close errors after a successful read are ignored,
// fstat failures are ignored (size is only a hint / too-large guard).
static FsAsyncResult fsReadWholeFdWork(
    int fd,
    bool closeWhenDone,
    const std::string& pathForError) {
  struct stat sb = {};
  bool haveStat = ::fstat(fd, &sb) == 0;
  if (haveStat && S_ISREG(sb.st_mode) &&
      static_cast<double>(sb.st_size) > kMaxReadFileBytes) {
    FsAsyncResult result;
    result.tooLarge = true;
    result.tooLargeSize = static_cast<double>(sb.st_size);
    if (closeWhenDone) {
      ::close(fd);
    }
    return result;
  }
  std::vector<uint8_t> data;
  if (haveStat && S_ISREG(sb.st_mode) && sb.st_size > 0) {
    data.reserve(static_cast<size_t>(sb.st_size));
  }
  uint8_t buf[65536];
  for (;;) {
    ssize_t bytesRead;
    do {
      bytesRead = ::read(fd, buf, sizeof(buf));
    } while (bytesRead < 0 && errno == EINTR);
    if (bytesRead < 0) {
      auto result = fsAsyncError(errno, "read", pathForError);
      if (closeWhenDone) {
        ::close(fd);
      }
      return result;
    }
    if (bytesRead == 0) {
      break;
    }
    data.insert(data.end(), buf, buf + bytesRead);
    if (static_cast<double>(data.size()) > kMaxReadFileBytes) {
      // A file that grew past the cap mid-read (or a non-regular source).
      FsAsyncResult result;
      result.tooLarge = true;
      result.tooLargeSize = static_cast<double>(data.size());
      if (closeWhenDone) {
        ::close(fd);
      }
      return result;
    }
  }
  if (closeWhenDone) {
    ::close(fd);  // readFileSync ignores close errors after a successful read
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(data);
  return result;
}

static FsAsyncResult fsReadFilePathWork(
    const std::string& path,
    int openFlags,
    int openMode) {
  int fd;
  do {
    fd = ::open(path.c_str(), openFlags, openMode);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    return fsAsyncError(errno, "open", path);
  }
  return fsReadWholeFdWork(fd, true, path);
}

static FsAsyncResult fsReadFileArmedWork(
    uint64_t principal,
    const std::string& path,
    const std::string& presentedHandle,
    const std::shared_ptr<int>& parent,
    int fd) {
  struct stat sb = {};
  if (::fstat(fd, &sb) != 0) return fsAsyncError(errno, "fstat", path);
  if (!S_ISREG(sb.st_mode)) return fsAsyncError(EACCES, "open", path);
  if (static_cast<double>(sb.st_size) > kMaxReadFileBytes) {
    FsAsyncResult result;
    result.tooLarge = true;
    result.tooLargeSize = static_cast<double>(sb.st_size);
    return result;
  }
  std::vector<uint8_t> data;
  if (sb.st_size > 0) data.reserve(static_cast<size_t>(sb.st_size));
  std::array<uint8_t, 64 * 1024> chunk = {};
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  RepeatedFsAuthorizationLease authorizationLease;
  while (true) {
    if (authorizeRepeatedFsWithLease(
            authorizationLease, principal, path.c_str(), 2, 2, *parent, *fd, 1,
            0, presented) != 1) {
      return fsAsyncError(EACCES, "read", path);
    }
    ssize_t amount;
    do {
      amount = ::read(fd, chunk.data(), chunk.size());
    } while (amount < 0 && errno == EINTR);
    if (amount < 0) return fsAsyncError(errno, "read", path);
    if (amount == 0) break;
    data.insert(data.end(), chunk.begin(), chunk.begin() + amount);
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

// Write all bytes to an already-open fd at its current position. Mirrors
// _writeAllSync + __exactFsWrite: EINTR retries, RLIMIT_FSIZE errno
// normalization, zero-byte write treated as EIO.
static FsAsyncResult fsWriteAllFdWork(
    int fd,
    const std::vector<uint8_t>& bytes,
    bool flush,
    bool closeWhenDone,
    const std::string& pathForError) {
  size_t offset = 0;
  while (offset < bytes.size()) {
    ssize_t bytesWritten;
    do {
      bytesWritten = ::write(fd, bytes.data() + offset, bytes.size() - offset);
    } while (bytesWritten < 0 && errno == EINTR);
    if (bytesWritten < 0) {
      normalizeWriteErrno(fd);
      auto result = fsAsyncError(errno, "write", pathForError);
      if (closeWhenDone) {
        ::close(fd);
      }
      return result;
    }
    if (bytesWritten == 0) {
      auto result = fsAsyncError(EIO, "write", pathForError);
      if (closeWhenDone) {
        ::close(fd);
      }
      return result;
    }
    offset += static_cast<size_t>(bytesWritten);
  }
  if (flush) {
    int rc;
    do {
      rc = ::fsync(fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
      auto result = fsAsyncError(errno, "fsync", pathForError);
      if (closeWhenDone) {
        ::close(fd);
      }
      return result;
    }
  }
  if (closeWhenDone && ::close(fd) != 0) {
    return fsAsyncError(errno, "close", pathForError);
  }
  return fsAsyncOk();
}

static FsAsyncResult fsWriteFilePathWork(
    const std::string& path,
    const std::vector<uint8_t>& bytes,
    int openFlags,
    int openMode,
    bool flush) {
  int fd;
  do {
    fd = ::open(path.c_str(), openFlags, openMode);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    return fsAsyncError(errno, "open", path);
  }
  return fsWriteAllFdWork(fd, bytes, flush, true, path);
}

static FsAsyncResult fsWriteFileArmedWork(
    uint64_t principal,
    const std::string& path,
    const std::string& presentedHandle,
    const std::shared_ptr<int>& parent,
    const std::shared_ptr<int>& fd,
    const std::vector<uint8_t>& bytes,
    bool flush) {
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  size_t offset = 0;
  while (offset < bytes.size()) {
    if (ex_host_authorize_typed_fs_open(
            principal, path.c_str(), 2, 7, *parent, *fd, 0, 1,
            presented) != 1) {
      return fsAsyncError(EACCES, "write", path);
    }
    ssize_t amount;
    do {
      amount = ::write(*fd, bytes.data() + offset, bytes.size() - offset);
    } while (amount < 0 && errno == EINTR);
    if (amount < 0) {
      normalizeWriteErrno(*fd);
      return fsAsyncError(errno, "write", path);
    }
    if (amount == 0) return fsAsyncError(EIO, "write", path);
    offset += static_cast<size_t>(amount);
  }
  if (flush) {
    if (ex_host_authorize_typed_fs_open(
            principal, path.c_str(), 2, 7, *parent, *fd, 0, 1,
            presented) != 1) {
      return fsAsyncError(EACCES, "fsync", path);
    }
    int rc;
    do {
      rc = ::fsync(*fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) return fsAsyncError(errno, "fsync", path);
  }
  return fsAsyncOk();
}

// Single chunk read, mirroring __exactFsRead: positional reads use pread (fd
// cursor unchanged), EINTR retries, EAGAIN/EWOULDBLOCK resolves empty.
static FsAsyncResult fsReadChunkWork(
    int fd,
    size_t length,
    bool positioned,
    int64_t position) {
  std::vector<uint8_t> data(length);
  ssize_t bytesRead;
  do {
    bytesRead = positioned
        ? ::pread(fd, data.data(), length, static_cast<off_t>(position))
        : ::read(fd, data.data(), length);
  } while (bytesRead < 0 && errno == EINTR);
  if (bytesRead < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return fsAsyncOk(FsAsyncResult::Kind::Bytes);
    }
    return fsAsyncError(errno, "read");
  }
  data.resize(static_cast<size_t>(bytesRead));
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(data);
  return result;
}

// Single chunk write, mirroring __exactFsWrite: pwrite when positioned, EINTR
// retries, RLIMIT_FSIZE errno normalization. Partial writes surface as the
// returned count (same as writeSync).
static FsAsyncResult fsWriteChunkWork(
    int fd,
    const std::vector<uint8_t>& bytes,
    bool positioned,
    int64_t position) {
  ssize_t bytesWritten;
  do {
    bytesWritten = positioned
        ? ::pwrite(fd, bytes.data(), bytes.size(), static_cast<off_t>(position))
        : ::write(fd, bytes.data(), bytes.size());
  } while (bytesWritten < 0 && errno == EINTR);
  if (bytesWritten < 0) {
    normalizeWriteErrno(fd);
    return fsAsyncError(errno, "write");
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = static_cast<double>(bytesWritten);
  return result;
}

static std::vector<struct iovec> ioVecsForBuffers(std::vector<std::vector<uint8_t>>& buffers) {
  std::vector<struct iovec> iovecs;
  iovecs.reserve(buffers.size());
  for (auto& buffer : buffers) {
    struct iovec iov {
      .iov_base = buffer.empty() ? nullptr : buffer.data(),
      .iov_len = buffer.size()
    };
    iovecs.push_back(iov);
  }
  return iovecs;
}

static FsAsyncResult fsReadvWork(
    int fd,
    std::vector<std::vector<uint8_t>>& buffers,
    bool positioned,
    int64_t position) {
  if (buffers.empty()) {
    return fsAsyncOk(FsAsyncResult::Kind::Bytes);
  }
  auto iovecs = ioVecsForBuffers(buffers);
  ssize_t bytesRead;
  do {
    bytesRead = positioned
        ? ::preadv(fd, iovecs.data(), static_cast<int>(iovecs.size()),
                   static_cast<off_t>(position))
        : ::readv(fd, iovecs.data(), static_cast<int>(iovecs.size()));
  } while (bytesRead < 0 && errno == EINTR);
  if (bytesRead < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return fsAsyncOk(FsAsyncResult::Kind::Bytes);
    }
    return fsAsyncError(errno, "readv");
  }

  std::vector<uint8_t> data;
  data.reserve(static_cast<size_t>(bytesRead));
  size_t remaining = static_cast<size_t>(bytesRead);
  for (auto& buffer : buffers) {
    if (remaining == 0) {
      break;
    }
    size_t copyLen = std::min(buffer.size(), remaining);
    data.insert(data.end(), buffer.begin(), buffer.begin() + copyLen);
    remaining -= copyLen;
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Bytes);
  result.bytes = std::move(data);
  return result;
}

static FsAsyncResult fsWritevWork(
    int fd,
    std::vector<std::vector<uint8_t>>& buffers,
    bool positioned,
    int64_t position) {
  if (buffers.empty()) {
    auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
    result.number = 0;
    return result;
  }
  auto iovecs = ioVecsForBuffers(buffers);
  ssize_t bytesWritten;
  do {
    bytesWritten = positioned
        ? ::pwritev(fd, iovecs.data(), static_cast<int>(iovecs.size()),
                    static_cast<off_t>(position))
        : ::writev(fd, iovecs.data(), static_cast<int>(iovecs.size()));
  } while (bytesWritten < 0 && errno == EINTR);
  if (bytesWritten < 0) {
    normalizeWriteErrno(fd);
    return fsAsyncError(errno, "writev");
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = static_cast<double>(bytesWritten);
  return result;
}

static FsAsyncResult fsAsyncString(std::string value) {
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = std::move(value);
  return result;
}

static struct timeval fsTimevalFromDouble(double value) {
  struct timeval tv;
  if (value > 1e12) {
    tv.tv_sec = static_cast<time_t>(value / 1000.0);
    tv.tv_usec =
        static_cast<suseconds_t>((static_cast<long long>(value) % 1000) * 1000);
  } else {
    tv.tv_sec = static_cast<time_t>(value);
    tv.tv_usec = static_cast<suseconds_t>((value - tv.tv_sec) * 1e6);
  }
  return tv;
}

static FsAsyncResult fsStatfsPathWork(const std::string& path) {
#if defined(__linux__) && !defined(EXACT_PLATFORM_ANDROID)
  struct statfs buf;
  if (::statfs(path.c_str(), &buf) != 0) {
    return fsAsyncError(errno, "statfs", path);
  }
  uint64_t type = static_cast<uint64_t>(buf.f_type);
#else
  struct statvfs buf;
  if (::statvfs(path.c_str(), &buf) != 0) {
    return fsAsyncError(errno, "statfs", path);
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
  return fsAsyncString(oss.str());
}

static FsAsyncResult fsPathOpWork(
    const std::string& op,
    const std::string& a,
    const std::string& b,
    double x,
    double y,
    double z,
    uint64_t principal) {
  (void)z;
  if (op == "readdir") {
    char* json = ex_host_fs_readdir(a.c_str());
    if (!json) {
      return fsAsyncError(errno, "scandir", a);
    }
    std::string out(json);
    ex_host_free_string(json);
    return fsAsyncString(std::move(out));
  }
  if (op == "mkdir") {
    if (ex_host_is_armed() == 1) {
      constexpr uint32_t kMkdirSurface = 12;
      if (x != 0) {
        return fsAsyncError(ENOTSUP, "mkdir", a);
      }
      if (ex_host_authorize_typed_fs_open(
              principal, a.c_str(), 0, kMkdirSurface, -1, -1, 0, 1,
              nullptr) != 1) {
        return fsAsyncError(EACCES, "mkdir", a);
      }
      auto parentAndName = splitParentAndName(a);
      const auto& parentPath = parentAndName.first;
      const auto& name = parentAndName.second;
      int parentRaw = ::open(
          parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
      if (parentRaw < 0) return fsAsyncError(errno, "mkdir", a);
      auto parent = retainedParentFd(parentRaw);
      if (name.empty() ||
          ex_host_authorize_typed_fs_open(
              principal, a.c_str(), 3, kMkdirSurface, *parent, -1, 0, 1,
              nullptr) != 1 ||
          ex_host_authorize_typed_fs_open(
              principal, a.c_str(), 4, kMkdirSurface, *parent, -1, 0, 1,
              nullptr) != 1) {
        return fsAsyncError(EACCES, "mkdir", a);
      }
      if (::mkdirat(*parent, name.c_str(), 0777) != 0) {
        return fsAsyncError(errno, "mkdir", a);
      }
      int directoryRaw = ::openat(
          *parent, name.c_str(),
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (directoryRaw < 0) {
        int saved = errno;
        ::unlinkat(*parent, name.c_str(), AT_REMOVEDIR);
        return fsAsyncError(saved, "mkdir", a);
      }
      auto directory = retainedFd(directoryRaw);
      if (ex_host_authorize_typed_fs_open(
              principal, a.c_str(), 1, kMkdirSurface, *parent,
              directoryRaw, 0, 1, nullptr) != 1) {
        if (!rollbackCreatedDirectory(*parent, name, directoryRaw)) {
          return fsAsyncError(errno, "rmdir", a);
        }
        return fsAsyncError(EACCES, "mkdir", a);
      }
      return fsAsyncOk();
    }
    std::string firstMissing;
    if (x != 0) {
      std::string prefix = !a.empty() && a[0] == '/' ? "/" : "";
      size_t start = prefix.empty() ? 0 : 1;
      while (start <= a.size()) {
        size_t slash = a.find('/', start);
        std::string part = a.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (!part.empty()) {
          if (!prefix.empty() && prefix.back() != '/') prefix += '/';
          prefix += part;
          struct stat sb = {};
          if (::lstat(prefix.c_str(), &sb) != 0 && errno == ENOENT) { firstMissing = prefix; break; }
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
      }
    }
    if (ex_host_fs_mkdir(a.c_str(), x != 0 ? 1 : 0) != 0) {
      return fsAsyncError(errno, "mkdir", a);
    }
    return x != 0 ? fsAsyncString(std::move(firstMissing)) : fsAsyncOk();
  }
  if (op == "rmdir") {
    if (ex_host_fs_rmdir(a.c_str()) != 0) {
      return fsAsyncError(errno, "rmdir", a);
    }
    return fsAsyncOk();
  }
  if (op == "unlink") {
    if (ex_host_fs_unlink(a.c_str()) != 0) {
      return fsAsyncError(errno, "unlink", a);
    }
    return fsAsyncOk();
  }
  if (op == "rename") {
    if (ex_host_fs_rename(a.c_str(), b.c_str()) != 0) {
      return fsAsyncError(errno, "rename", a);
    }
    return fsAsyncOk();
  }
  if (op == "copyfile") {
    if (ex_host_fs_copy(a.c_str(), b.c_str()) != 0) {
      return fsAsyncError(errno, "copyfile", a);
    }
    return fsAsyncOk();
  }
  if (op == "copyfile_excl") {
    int source = ::open(a.c_str(), O_RDONLY);
    if (source < 0) return fsAsyncError(errno, "copyfile", a);
    struct stat st = {};
    if (::fstat(source, &st) != 0) { int e = errno; ::close(source); return fsAsyncError(e, "copyfile", a); }
    int dest = ::open(b.c_str(), O_WRONLY | O_CREAT | O_EXCL, st.st_mode & 07777);
    if (dest < 0) { int e = errno; ::close(source); return fsAsyncError(e, "copyfile", b); }
    std::vector<uint8_t> buffer(64 * 1024);
    bool failed = false; int saved = 0;
    for (;;) {
      ssize_t n = ::read(source, buffer.data(), buffer.size());
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) { failed = true; saved = errno; break; }
      if (n == 0) break;
      ssize_t off = 0;
      while (off < n) {
        ssize_t written = ::write(dest, buffer.data() + off, static_cast<size_t>(n - off));
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { failed = true; saved = written < 0 ? errno : EIO; break; }
        off += written;
      }
      if (failed) break;
    }
    ::close(source);
    if (::close(dest) != 0 && !failed) { failed = true; saved = errno; }
    if (failed) { ::unlink(b.c_str()); return fsAsyncError(saved, "copyfile", a); }
    return fsAsyncOk();
  }
  if (op == "realpath") {
    char* resolved = ex_host_fs_realpath(a.c_str());
    if (!resolved) {
      return fsAsyncError(errno, "realpath", a);
    }
    std::string out(resolved);
    ex_host_free_string(resolved);
    return fsAsyncString(std::move(out));
  }
  if (op == "access") {
    if (ex_host_fs_access(a.c_str(), static_cast<int32_t>(x)) != 0) {
      return fsAsyncError(errno, "access", a);
    }
    return fsAsyncOk();
  }
  if (op == "chmod") {
    if (ex_host_fs_chmod(a.c_str(), static_cast<uint32_t>(x)) != 0) {
      return fsAsyncError(errno, "chmod", a);
    }
    return fsAsyncOk();
  }
  if (op == "mkdtemp") {
    char* path = ex_host_fs_mkdtemp(a.c_str(), principal);
    if (!path) {
      return fsAsyncError(errno ? errno : EIO, "mkdtemp", a);
    }
    std::string out(path);
    ex_host_free_string(path);
    return fsAsyncString(std::move(out));
  }
  if (op == "symlink") {
    if (::symlink(a.c_str(), b.c_str()) != 0) {
      return fsAsyncError(errno, "symlink", a);
    }
    return fsAsyncOk();
  }
  if (op == "link") {
    if (::link(a.c_str(), b.c_str()) != 0) {
      return fsAsyncError(errno, "link", a);
    }
    return fsAsyncOk();
  }
  if (op == "readlink") {
    char buf[PATH_MAX];
    ssize_t len = ::readlink(a.c_str(), buf, sizeof(buf) - 1);
    if (len < 0) {
      return fsAsyncError(errno, "readlink", a);
    }
    buf[len] = '\0';
    return fsAsyncString(std::string(buf));
  }
  if (op == "truncate") {
    if (::truncate(a.c_str(), static_cast<off_t>(x)) != 0) {
      return fsAsyncError(errno, "truncate", a);
    }
    return fsAsyncOk();
  }
  if (op == "chown") {
    if (::chown(a.c_str(), static_cast<uid_t>(x), static_cast<gid_t>(y)) != 0) {
      return fsAsyncError(errno, "chown", a);
    }
    return fsAsyncOk();
  }
  if (op == "lchown") {
    if (::lchown(a.c_str(), static_cast<uid_t>(x), static_cast<gid_t>(y)) != 0) {
      return fsAsyncError(errno, "lchown", a);
    }
    return fsAsyncOk();
  }
  if (op == "lchmod") {
#if defined(__APPLE__)
    if (::lchmod(a.c_str(), static_cast<mode_t>(x)) != 0) return fsAsyncError(errno, "lchmod", a);
    return fsAsyncOk();
#else
    return fsAsyncError(ENOSYS, "lchmod", a);
#endif
  }
  if (op == "utime") {
    struct timeval times[2] = {fsTimevalFromDouble(x), fsTimevalFromDouble(y)};
    if (::utimes(a.c_str(), times) != 0) {
      return fsAsyncError(errno, "utime", a);
    }
    return fsAsyncOk();
  }
  if (op == "lutime") {
    struct timeval times[2] = {fsTimevalFromDouble(x), fsTimevalFromDouble(y)};
    if (::lutimes(a.c_str(), times) != 0) return fsAsyncError(errno, "lutimes", a);
    return fsAsyncOk();
  }
  if (op == "statfs") {
    return fsStatfsPathWork(a);
  }
  return fsAsyncError(EINVAL, op.c_str(), a);
}

static void appendJsonString(std::ostringstream& out, const std::string& value) {
  out << '"';
  for (unsigned char ch : value) {
    switch (ch) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (ch < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(ch) << std::dec << std::setfill(' ');
        } else {
          out << static_cast<char>(ch);
        }
    }
  }
  out << '"';
}

static FsAsyncResult fsReaddirArmedWork(
    uint64_t principal,
    const std::string& path,
    const std::shared_ptr<int>& parent,
    const std::shared_ptr<int>& target) {
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 5, 4, *parent, *target, 0, 0,
          nullptr) != 1) {
    return fsAsyncError(EACCES, "scandir", path);
  }
  int directoryFd = ::dup(*target);
  if (directoryFd < 0) return fsAsyncError(errno, "scandir", path);
  DIR* directory = ::fdopendir(directoryFd);
  if (!directory) {
    int saved = errno;
    ::close(directoryFd);
    return fsAsyncError(saved, "scandir", path);
  }
  std::vector<std::string> names;
  errno = 0;
  while (auto* entry = ::readdir(directory)) {
    if (std::strcmp(entry->d_name, ".") != 0 &&
        std::strcmp(entry->d_name, "..") != 0) {
      names.emplace_back(entry->d_name);
    }
  }
  int saved = errno;
  ::closedir(directory);
  if (saved != 0) return fsAsyncError(saved, "scandir", path);
  std::sort(names.begin(), names.end());
  std::ostringstream json;
  json << '[';
  for (size_t index = 0; index < names.size(); ++index) {
    if (index != 0) json << ',';
    appendJsonString(json, names[index]);
  }
  json << ']';
  return fsAsyncString(json.str());
}

static FsAsyncResult fsRealpathArmedWork(
    uint64_t principal,
    const std::string& path,
    const std::shared_ptr<int>& parent,
    const std::shared_ptr<int>& target) {
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 5, 9, *parent, *target, 0, 0,
          nullptr) != 1) {
    return fsAsyncError(EACCES, "realpath", path);
  }
  auto resolved = resolvedPathForFd(*target);
  return resolved ? fsAsyncString(std::move(*resolved))
                  : fsAsyncError(errno ? errno : EIO, "realpath", path);
}

static FsAsyncResult fsMkdtempArmedWork(
    uint64_t principal,
    const std::string& prefix) {
  static std::atomic<uint64_t> sequence{1};
  for (size_t attempt = 0; attempt < 128; ++attempt) {
    uint64_t token = sequence.fetch_add(1, std::memory_order_relaxed) ^ nowMs();
    std::ostringstream suffix;
    suffix << std::hex << std::setw(12) << std::setfill('0') << token;
    auto candidate = prefix + suffix.str();
    auto result = fsPathOpWork("mkdir", candidate, "", 0, 0, 0, principal);
    if (result.ok) return fsAsyncString(std::move(candidate));
    if (result.errnoValue != EEXIST) return result;
  }
  return fsAsyncError(EEXIST, "mkdtemp", prefix);
}

static FsAsyncResult fsStatPathWork(const std::string& path, bool isLstat) {
  char* json = isLstat ? ex_host_fs_lstat(path.c_str()) : ex_host_fs_stat(path.c_str());
  if (!json) {
    return fsAsyncError(errno, isLstat ? "lstat" : "stat", path);
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = json;
  ex_host_free_string(json);
  return result;
}

static FsAsyncResult fsFstatWork(int fd) {
  struct stat sb = {};
  if (::fstat(fd, &sb) != 0) {
    return fsAsyncError(errno, "fstat");
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = statJsonFromStat(sb);
  return result;
}

static FsAsyncResult fsStatArmedWork(
    uint64_t principal,
    const std::string& path,
    uint32_t surface,
    const std::string& presentedHandle,
    const std::shared_ptr<int>& parent,
    int targetFd) {
  const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  if (ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 5, surface, *parent, targetFd, 0, 0,
          presented) != 1) {
    return fsAsyncError(EACCES, "fstat", path);
  }
  struct stat sb = {};
  if (::fstat(targetFd, &sb) != 0) return fsAsyncError(errno, "fstat", path);
  auto result = fsAsyncOk(FsAsyncResult::Kind::Json);
  result.json = statJsonFromStat(sb);
  return result;
}

// Run descriptor metadata/durability operations on a duplicate descriptor.
// dup() is intentionally performed on the JS thread before dispatch: it pins
// the open file description while a concurrent close() removes the public fd,
// without changing shared cursor semantics. The worker always owns/ closes it.
static FsAsyncResult fsFdOpWork(
    const std::string& op, int workerFd, double x, double y) {
  int rc = -1;
  const char* syscall = op.c_str();
  if (op == "fchmod") {
    rc = ::fchmod(workerFd, static_cast<mode_t>(x));
  } else if (op == "fchown") {
    rc = ::fchown(workerFd, static_cast<uid_t>(x), static_cast<gid_t>(y));
  } else if (op == "ftruncate") {
    rc = ::ftruncate(workerFd, static_cast<off_t>(x));
  } else if (op == "futimes") {
    struct timeval times[2] = {fsTimevalFromDouble(x), fsTimevalFromDouble(y)};
#if defined(EXACT_PLATFORM_ANDROID)
    struct timespec ts[2] = {
        {times[0].tv_sec, static_cast<long>(times[0].tv_usec) * 1000},
        {times[1].tv_sec, static_cast<long>(times[1].tv_usec) * 1000},
    };
    syscall = "futimens";
    rc = ::futimens(workerFd, ts);
#else
    rc = ::futimes(workerFd, times);
#endif
  } else if (op == "fsync") {
    rc = ::fsync(workerFd);
  } else if (op == "fdatasync") {
#if defined(__APPLE__)
    rc = ::fsync(workerFd);
#else
    rc = ::fdatasync(workerFd);
#endif
  } else {
    return fsAsyncError(EINVAL, op.c_str());
  }
  int saved = errno;
  return rc == 0 ? fsAsyncOk() : fsAsyncError(saved, syscall);
}

static FsAsyncResult fsOpenWork(
    uint64_t owner,
    const std::string& path, int flags, int mode, bool canRead, bool canWrite) {
  int fd = ::open(path.c_str(), flags, mode);
  if (fd < 0) return fsAsyncError(errno, "open", path);
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = fd;
  result.registerOpenedFd = true;
  result.openedFdGuard = std::shared_ptr<int>(new int(fd), [](int* guardedFd) {
    if (*guardedFd >= 0) ::close(*guardedFd);
    delete guardedFd;
  });
  result.openedPath = path;
  result.openedCanRead = canRead;
  result.openedCanWrite = canWrite;
  result.openedOwner = owner;
  return result;
}

static FsAsyncResult fsOpenWorkArmed(
    uint64_t principal,
    const std::string& path,
    const std::string& name,
    int flags,
    int mode,
    bool canRead,
    bool canWrite,
    const std::string& presentedHandle,
    std::shared_ptr<int> parent) {
  const char* handle = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
  auto opened = openArmedTargetAtomically(
      principal, path, name, 0, *parent, flags, O_NOFOLLOW, mode,
      canRead, canWrite, handle);
  int fd = opened.fd;
  const bool created = opened.created;
  if (fd < 0) return fsAsyncError(errno, "open", path);
  auto fdGuard = retainedFd(fd);
  if (denyArmedOpenCommitForTest() || ex_host_authorize_typed_fs_open(
          principal, path.c_str(), 1, 0, *parent, fd,
          canRead ? 1 : 0, canWrite ? 1 : 0, handle) != 1) {
    if (created) rollbackCreatedFile(*parent, name, fd);
    return fsAsyncError(EACCES, "open", path);
  }
  if ((flags & O_TRUNC) != 0 && ::ftruncate(fd, 0) != 0) {
    int saved = errno;
    if (created) rollbackCreatedFile(*parent, name, fd);
    return fsAsyncError(saved, "open", path);
  }
  auto result = fsAsyncOk(FsAsyncResult::Kind::Number);
  result.number = fd;
  result.registerOpenedFd = true;
  result.openedFdGuard = std::move(fdGuard);
  result.openedPath = path;
  result.openedCanRead = canRead;
  result.openedCanWrite = canWrite;
  result.openedOwner = principal;
  result.openedPresentedHandle = presentedHandle;
  result.openedRetainedParent = std::move(parent);
  return result;
}

static FsAsyncResult fsCloseWork(int fd) {
  if (::close(fd) != 0) return fsAsyncError(errno, "close");
  return fsAsyncOk();
}

class OwnedFd {
 public:
  explicit OwnedFd(int fd) : fd_(fd) {}
  ~OwnedFd() { if (fd_ >= 0) ::close(fd_); }
  OwnedFd(const OwnedFd&) = delete;
  OwnedFd& operator=(const OwnedFd&) = delete;
  int get() const { return fd_; }
 private:
  int fd_;
};

static std::shared_ptr<OwnedFd> duplicateFdForAsync(
    facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  int workerFd = ::dup(fd);
  if (workerFd < 0) throwFsError(runtime, syscall, "");
  return std::make_shared<OwnedFd>(workerFd);
}

static FsAsyncResult fsRunOwnedFd(
    const std::shared_ptr<OwnedFd>& workerFd,
    const std::function<FsAsyncResult(int)>& work) {
  return work(workerFd->get());
}

void installFsHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  auto readFileFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactReadFile"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0) {
          return facebook::jsi::Value::undefined();
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — Whole-file reads retain and recheck the actual object for every chunk.
          std::string presentedHandle;
          if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
            if (!args[1].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactReadFile: typed handleId must be a string");
            }
            presentedHandle = args[1].asString(runtime).utf8(runtime);
          }
          const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
          auto prepared = prepareArmedReadTarget(
              runtime, path, 1, presentedHandle);
          auto parent = std::move(prepared.first);
          auto name = std::move(prepared.second);
          int fdRaw = ::openat(
              *parent, name.c_str(),
              O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
          if (fdRaw < 0) throwFsError(runtime, "open", path);
          auto fd = retainedFd(fdRaw);
          struct stat sb = {};
          if (::fstat(fdRaw, &sb) != 0) throwFsError(runtime, "fstat", path);
          if (!S_ISREG(sb.st_mode)) {
            errno = EACCES;
            throwFsError(runtime, "open", path);
          }
          uint64_t principal = currentPrincipalId();
          if (ex_host_authorize_typed_fs_open(
                  principal, path.c_str(), 1, 1, *parent, fdRaw, 1, 0,
                  presented) != 1) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          std::vector<uint8_t> data;
          if (sb.st_size > 0 && static_cast<uint64_t>(sb.st_size) <= data.max_size()) {
            data.reserve(static_cast<size_t>(sb.st_size));
          }
          std::array<uint8_t, 64 * 1024> chunk = {};
          RepeatedFsAuthorizationLease authorizationLease;
          while (true) {
            if (authorizeRepeatedFsWithLease(
                    authorizationLease, principal, path.c_str(), 1, 2, parentRaw,
                    fdRaw, 1, 0, presented) != 1) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            ssize_t amount;
            do {
              amount = ::read(fdRaw, chunk.data(), chunk.size());
            } while (amount < 0 && errno == EINTR);
            if (amount < 0) throwFsError(runtime, "read", path);
            if (amount == 0) break;
            data.insert(data.end(), chunk.begin(), chunk.begin() + amount);
          }
          return makeUint8Array(runtime, std::move(data));
        }
        if (!isAllowAll()) {
          std::string cap = "fs:read:" + path;
          if (!checkCapability(cap)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }

        // Single FFI call: read entire file at once
        uint64_t len = 0;
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
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactWriteFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
            if (!args[2].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactWriteFile: typed handleId must be a string");
            }
            presentedHandle = args[2].asString(runtime).utf8(runtime);
          }
          auto data = extractBytes(runtime, args[1]);
          auto descriptors = openArmedWriteTarget(
              runtime, path, 5, O_WRONLY | O_CREAT | O_TRUNC, 0666, true,
              presentedHandle);
          writeArmedBytes(
              runtime, path, 5, presentedHandle, descriptors, data);
          return facebook::jsi::Value::undefined();
        }
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        auto dataCopy = extractBytes(runtime, args[1]);
        size_t length = dataCopy.size();
        const uint8_t* dataPtr = dataCopy.empty() ? nullptr : dataCopy.data();

        void* handle = ex_host_fs_open(path.c_str(), EXACT_FS_WRITE | EXACT_FS_CREATE | EXACT_FS_TRUNCATE);
        if (!handle) {
          throw facebook::jsi::JSError(runtime, "Failed to open file for writing");
        }
        if (length > 0 && dataPtr) {
          // ex_host_fs_write is a single std::io::Write::write, which may write
          // FEWER bytes than requested (nearly-full disk, RLIMIT_FSIZE, a large
          // buffer). A single call that ignores the returned count silently
          // truncates the file while reporting success, so loop until every byte
          // is written (mirroring the fd-based _writeAllSync path in fs.js).
          size_t totalWritten = 0;
          while (totalWritten < length) {
            size_t remaining = length - totalWritten;
            uint32_t chunk = remaining > kMaxHostWriteChunk
                ? kMaxHostWriteChunk
                : static_cast<uint32_t>(remaining);
            int32_t written = ex_host_fs_write(handle, dataPtr + totalWritten, chunk);
            if (written < 0) {
              // ex_host_fs_write is a single std::io::Write::write;
              // Rust's File::write (unlike write_all) does not retry
              // ErrorKind::Interrupted itself, so a signal arriving mid-write
              // (e.g. SIGCHLD/SIGALRM handled while writeFileSync targets a
              // FIFO or char device) surfaces here as errno EINTR. Treating
              // that as fatal aborted the whole call on a partial write where
              // Node's writeSync retries. (ENG-23042, residual of the
              // ENG-22982/22993 short-write fixes.)
              //
              // EAGAIN/EWOULDBLOCK (non-blocking special file whose reader has
              // stalled) is NOT retried: with no way to poll the host handle
              // for writability, a bare `continue` busy-spins at 100% CPU for
              // as long as the reader stays stalled. Node surfaces EAGAIN as
              // an error here, so fail loudly instead. (ENG-23136)
              if (errno == EINTR) {
                continue;
              }
              ex_host_fs_close(handle);
              throw facebook::jsi::JSError(runtime, "Failed to write file");
            }
            if (written == 0) {
              // No progress and no error: refuse to spin forever.
              ex_host_fs_close(handle);
              throw facebook::jsi::JSError(runtime, "Failed to write file: short write");
            }
            totalWritten += static_cast<size_t>(written);
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
      3,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactAppendFile: path and data required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
            if (!args[2].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactAppendFile: typed handleId must be a string");
            }
            presentedHandle = args[2].asString(runtime).utf8(runtime);
          }
          auto data = extractBytes(runtime, args[1]);
          auto descriptors = openArmedWriteTarget(
              runtime, path, 6, O_WRONLY | O_CREAT | O_APPEND, 0666, true,
              presentedHandle);
          writeArmedBytes(
              runtime, path, 6, presentedHandle, descriptors, data);
          return facebook::jsi::Value::undefined();
        }
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }

        auto dataCopy = extractBytes(runtime, args[1]);
        size_t length = dataCopy.size();
        const uint8_t* dataPtr = dataCopy.empty() ? nullptr : dataCopy.data();

        if (length > 0 && dataPtr) {
          // ex_host_fs_append is allowed to report a short write. Treat append
          // like __exactWriteFile: keep appending until the whole caller buffer
          // is durable, retry transient EINTR, and refuse a zero-progress
          // success so we never silently drop the tail of a streaming write.
          // EAGAIN/EWOULDBLOCK is an error, not a retry: with no way to poll
          // the host handle, retrying busy-spins unboundedly (see the
          // __exactWriteFile loop above; ENG-23136).
          size_t totalWritten = 0;
          while (totalWritten < length) {
            size_t remaining = length - totalWritten;
            uint32_t chunk = remaining > kMaxHostWriteChunk
                ? kMaxHostWriteChunk
                : static_cast<uint32_t>(remaining);
            int32_t written = ex_host_fs_append(path.c_str(), dataPtr + totalWritten, chunk);
            if (written < 0) {
              if (errno == EINTR) {
                continue;
              }
              throw facebook::jsi::JSError(runtime, "Failed to append to file");
            }
            if (written == 0) {
              throw facebook::jsi::JSError(runtime, "Failed to append to file: short write");
            }
            totalWritten += static_cast<size_t>(written);
          }
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactAppendFile", std::move(appendFileFn));

  // __exactStat(path) -> object {size, mtime_ms, is_dir, is_file, mode}
  auto statFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactStat"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactStat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
            if (!args[1].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactStat: typed handleId must be a string");
            }
            presentedHandle = args[1].asString(runtime).utf8(runtime);
          }
          auto descriptors = openArmedListTarget(
              runtime, path, 3, metadataOpenFlags(), presentedHandle);
          struct stat sb = {};
          if (::fstat(*descriptors.target, &sb) != 0) {
            throwFsError(runtime, "fstat", path);
          }
          return facebook::jsi::String::createFromUtf8(runtime, statJsonFromStat(sb));
        }
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
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactLstat: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
            if (!args[1].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactLstat: typed handleId must be a string");
            }
            presentedHandle = args[1].asString(runtime).utf8(runtime);
          }
          auto descriptors = openArmedLinkTarget(runtime, path, 10, presentedHandle);
          struct stat sb = {};
          if (::fstat(*descriptors.target, &sb) != 0) {
            throwFsError(runtime, "fstat", path);
          }
          return facebook::jsi::String::createFromUtf8(runtime, statJsonFromStat(sb));
        }
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
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactReaddir: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
            if (!args[1].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactReaddir: typed handleId must be a string");
            }
            presentedHandle = args[1].asString(runtime).utf8(runtime);
          }
          auto descriptors = openArmedListTarget(
              runtime, path, 4, O_RDONLY | O_DIRECTORY, presentedHandle);
          int directoryFd = ::dup(*descriptors.target);
          if (directoryFd < 0) throwFsError(runtime, "dup", path);
          DIR* directory = ::fdopendir(directoryFd);
          if (!directory) {
            int savedErrno = errno;
            ::close(directoryFd);
            errno = savedErrno;
            throwFsError(runtime, "scandir", path);
          }
          std::vector<std::string> names;
          RepeatedFsAuthorizationLease authorizationLease;
          while (true) {
            const char* presented = presentedHandle.empty()
                ? nullptr
                : presentedHandle.c_str();
            if (authorizeRepeatedFsWithLease(
                    authorizationLease, currentPrincipalId(), path.c_str(), 4,
                    5, *descriptors.parent, *descriptors.target, 0, 0,
                    presented) != 1) {
              ::closedir(directory);
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            errno = 0;
            auto* entry = ::readdir(directory);
            if (!entry) break;
            std::string name(entry->d_name);
            if (name != "." && name != "..") names.push_back(std::move(name));
          }
          int readErrno = errno;
          ::closedir(directory);
          if (readErrno != 0) {
            errno = readErrno;
            throwFsError(runtime, "scandir", path);
          }
          facebook::jsi::Array array(runtime, names.size());
          for (size_t index = 0; index < names.size(); ++index) {
            array.setValueAtIndex(
                runtime, index,
                facebook::jsi::String::createFromUtf8(runtime, names[index]));
          }
          auto json = runtime.global().getPropertyAsObject(runtime, "JSON");
          return json.getPropertyAsFunction(runtime, "stringify").call(runtime, array);
        }
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
        int32_t recursive = 0;
        if (count > 1 && args[1].isBool()) {
          recursive = args[1].getBool() ? 1 : 0;
        } else if (count > 1 && args[1].isNumber()) {
          recursive = args[1].asNumber() != 0 ? 1 : 0;
        }
        if (ex_host_is_armed() == 1) {
          if (recursive != 0) {
            throw facebook::jsi::JSError(
                runtime,
                "recursive mkdir is closed under armed capability startup");
          }
          createArmedDirectory(runtime, path, 0777);
          return facebook::jsi::Value::undefined();
        }
        std::string cap = "fs:write:" + path;
        if (!checkCapability(cap)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
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
        // Rename removes `from` and creates `to`: both are writes. Previously
        // only `from` was checked, so a package granted fs:write on its own dir
        // could rename a file *into* a path it was never granted. (ENG-22627)
        if (!checkCapability("fs:write:" + from)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (!checkCapability("fs:write:" + to)) {
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
      3,
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
        bool exclusive = count > 2 && args[2].isNumber() &&
            (static_cast<int>(args[2].asNumber()) & 1) != 0;
        auto copy = exclusive ? ex_host_fs_copy_exclusive : ex_host_fs_copy;
        if (copy(from.c_str(), to.c_str()) != 0) {
          throwFsError(runtime, "copyfile", from, to);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactCopyFile", std::move(copyFileFn));

  // __exactRealpath(path) -> string
  auto realpathFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactRealpath"),
      2,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactRealpath: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 1 && !args[1].isUndefined() && !args[1].isNull()) {
            if (!args[1].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactRealpath: typed handleId must be a string");
            }
            presentedHandle = args[1].asString(runtime).utf8(runtime);
          }
          auto descriptors = openArmedListTarget(
              runtime, path, 9, metadataOpenFlags(), presentedHandle);
          auto resolved = resolvedPathForFd(*descriptors.target);
          if (!resolved) throwFsError(runtime, "realpath", path);
          return facebook::jsi::String::createFromUtf8(runtime, *resolved);
        }
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
        int32_t mode = 0;
        if (count > 1 && args[1].isNumber()) {
          mode = static_cast<int32_t>(args[1].asNumber());
        }
        // Node-compatible access mode bits: W_OK is 2. A write-permission probe
        // leaks write authority metadata, so POSIX must match the Windows gate
        // and require fs:write when the caller asks about writability. (ENG-22717)
        if ((mode & 2) != 0) {
          if (!checkCapability("fs:write:" + path)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (!checkCapability("fs:read:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
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
        char* path = ex_host_fs_mkdtemp(prefix.c_str(), currentPrincipalId());
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
      4,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count == 0 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsOpen: path required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        const uint64_t principal = currentPrincipalId();

        int posixFlags = parseOpenFlagsArg(runtime, args, count, 1);
        bool needsRead = false;
        bool needsWrite = false;
        const bool armed = ex_host_is_armed() == 1;
        const uint64_t owner = currentPrincipalId();
        std::string presentedHandle;
        const char* presentedHandlePtr = nullptr;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          if (!args[3].isString()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsOpen: typed handleId must be a string");
          }
          presentedHandle = args[3].asString(runtime).utf8(runtime);
          presentedHandlePtr = presentedHandle.c_str();
        }
        if (armed) {
          classifyOpenAccess(posixFlags, needsRead, needsWrite);
          if (ex_host_authorize_typed_fs_open(
                  owner, path.c_str(), 0, 0, -1, -1,
                  needsRead ? 1 : 0, needsWrite ? 1 : 0,
                  presentedHandlePtr) != 1) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else {
          requireOpenCapability(runtime, path, posixFlags, needsRead, needsWrite);
        }

        int mode = 0666;
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }

        std::shared_ptr<int> retainedParent;
        int fd = -1;
        bool created = false;
        if (armed) {
          // @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution — Retain the parent and commit the actual fd before truncation or later I/O.
          auto [parentPath, name] = splitParentAndName(path);
          int parentFd = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
          if (parentFd < 0) throwFsError(runtime, "open", path);
          retainedParent = retainedParentFd(parentFd);
          if (ex_host_authorize_typed_fs_open(
                  owner, path.c_str(), 3, 0, *retainedParent, -1,
                  needsRead ? 1 : 0, needsWrite ? 1 : 0,
                  presentedHandlePtr) != 1) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          // O_TRUNC mutates during open. Delay it until the actual descriptor
          // identity has passed commit authorization.
          auto opened = openArmedTargetAtomically(
              owner, path, name, 0, *retainedParent, posixFlags, O_NOFOLLOW,
              mode, needsRead, needsWrite, presentedHandlePtr);
          fd = opened.fd;
          created = opened.created;
        } else {
          fd = ::open(path.c_str(), posixFlags, mode);
        }
        if (fd < 0) {
          throwFsError(runtime, "open", path);
        }
        if (armed && (denyArmedOpenCommitForTest() || ex_host_authorize_typed_fs_open(
                         owner, path.c_str(), 1, 0,
                         *retainedParent, fd,
                         needsRead ? 1 : 0, needsWrite ? 1 : 0,
                         presentedHandlePtr) != 1)) {
          if ((posixFlags & O_CREAT) != 0) {
            auto parentAndName = splitParentAndName(path);
            // Only remove the name if this open created the exact object.
            // Existing files are never rollback candidates.
            if (created) rollbackCreatedFile(*retainedParent, parentAndName.second, fd);
          }
          ::close(fd);
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (armed && (posixFlags & O_TRUNC) != 0 && ::ftruncate(fd, 0) != 0) {
          int savedErrno = errno;
          if (created) {
            auto parentAndName = splitParentAndName(path);
            rollbackCreatedFile(*retainedParent, parentAndName.second, fd);
          }
          ::close(fd);
          errno = savedErrno;
          throwFsError(runtime, "open", path);
        }
        // @ref LLP 0013#policy — raw POSIX fds are forgeable integers, so the
        // host records the owner/path/access class at open and later fd ops
        // recheck both ownership and the current capability grant. (ENG-22707)
        registerFd(
            fd, path, needsRead, needsWrite, owner, presentedHandle,
            std::move(retainedParent));
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
        (void)requireOwnedFd(runtime, fd, "close");
        if (::close(fd) < 0) {
          throwFsError(runtime, "close", "");
        }
        unregisterFd(fd);
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
        requireFdRead(runtime, fd, "read");

        std::vector<uint8_t> data(length);
        // A numeric position is a *positional* read: Node's readSync leaves the
        // fd's current file offset unchanged when `position` is a number, so use
        // pread rather than lseek+read (which permanently moves the cursor and
        // corrupts subsequent sequential reads — e.g. a header read at a fixed
        // offset followed by streaming). position < 0 / null / undefined means
        // "read at the current position" and keeps the plain read path.
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        // Retry EINTR like the write side (ENG-23136): a signal delivered
        // mid-read (e.g. SIGCHLD while the fd is a FIFO or char device) makes
        // read/pread fail with EINTR having read nothing. Node (libuv) retries
        // the syscall instead of surfacing it. (ENG-23467)
        ssize_t bytesRead;
        do {
          bytesRead = positioned
              ? ::pread(fd, data.data(), length, static_cast<off_t>(args[2].asNumber()))
              : ::read(fd, data.data(), length);
        } while (bytesRead < 0 && errno == EINTR);
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
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          return facebook::jsi::Value(false);
        }
        int fd = static_cast<int>(args[0].asNumber());
        (void)requireOwnedFd(runtime, fd, "poll");
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
        int sendFd = -1;
        if (count > 2 && args[2].isNumber()) {
          sendFd = static_cast<int>(args[2].asNumber());
        }
        exactRequireOwnedIpcFd(runtime, sockFd, "__exactIpcSendMsg");
        if (sendFd >= 0) {
          exactRequireTransferableFd(runtime, sendFd, "__exactIpcSendMsg");
        }
        auto dataBytes = extractBytes(runtime, args[1]);

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
        exactRequireOwnedIpcFd(runtime, sockFd, "__exactIpcRecvMsg");

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
              exactRegisterReceivedFdForCurrentPrincipal(recvFd);
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
        requireFdWrite(runtime, fd, "write");

        // Extract data bytes
        auto dataBytes = extractBytes(runtime, args[1]);

        // A numeric position is a *positional* write: Node's writeSync leaves the
        // fd's current offset unchanged when `position` is a number, so use pwrite
        // rather than lseek+write (which permanently moves the cursor). position <
        // 0 / null / undefined means "write at the current position". (For an
        // O_APPEND fd pwrite still appends, ignoring the offset, matching Node.)
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        // Retry EINTR: a signal delivered mid-write (SIGCHLD/SIGALRM while the
        // fd is a FIFO or char device) makes write/pwrite fail with EINTR
        // having written nothing. Node (libuv) retries the syscall instead of
        // surfacing it, so treating it as fatal aborted every fs.writeSync /
        // writeFileSync(fd, ...) / WriteStream write with a spurious error.
        // ENG-23042 added this retry to the path-based __exactWriteFile loop
        // only; this is the fd-based sibling. (ENG-23136)
        ssize_t bytesWritten;
        do {
          bytesWritten = positioned
              ? ::pwrite(fd, dataBytes.data(), dataBytes.size(),
                         static_cast<off_t>(args[2].asNumber()))
              : ::write(fd, dataBytes.data(), dataBytes.size());
        } while (bytesWritten < 0 && errno == EINTR);
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
        requireFdRead(runtime, fd, "readv");
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        std::vector<IoVecMetadata> targetMetadata;
        if (!parseIoVecArguments(
                runtime, args[1], buffers, iovecs, &targetMetadata, false)) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadv: buffers must be Uint8Array-like objects");
        }
        auto listObj = args[1].asObject(runtime);
        // A numeric position is a *positional* read: Node's readv/readvSync
        // leave the fd's current offset unchanged when `position` is a number
        // (libuv uses preadv), so use preadv rather than lseek+readv — the
        // same contract already applied to the scalar __exactFsRead via
        // pread. position < 0 means "read at the current offset". (ENG-23467)
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 3 && args[3].isObject() && args[3].asObject(runtime).isFunction(runtime)) {
          callback = args[3].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 3) {
          throw facebook::jsi::JSError(runtime, "__exactFsReadv: callback must be a function");
        }

        // Retry EINTR like the scalar read/write paths (ENG-23136).
        ssize_t bytesRead;
        do {
          bytesRead = positioned
              ? ::preadv(fd, iovecs.data(), static_cast<int>(iovecs.size()),
                         static_cast<off_t>(args[2].asNumber()))
              : ::readv(fd, iovecs.data(), static_cast<int>(iovecs.size()));
        } while (bytesRead < 0 && errno == EINTR);
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
        requireFdWrite(runtime, fd, "writev");
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        if (!parseIoVecArguments(runtime, args[1], buffers, iovecs, nullptr)) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritev: buffers must be Uint8Array-like objects");
        }
        // A numeric position is a *positional* write: Node's writev/writevSync
        // leave the fd's current offset unchanged when `position` is a number
        // (libuv uses pwritev), so use pwritev rather than lseek+writev — the
        // same contract already applied to the scalar __exactFsWrite via
        // pwrite. position < 0 means "write at the current offset". (ENG-23467)
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        bool hasCallback = false;
        std::optional<facebook::jsi::Function> callback;
        if (count > 3 && args[3].isObject() && args[3].asObject(runtime).isFunction(runtime)) {
          callback = args[3].asObject(runtime).asFunction(runtime);
          hasCallback = true;
        } else if (count > 3) {
          throw facebook::jsi::JSError(runtime, "__exactFsWritev: callback must be a function");
        }
        // Retry EINTR like the scalar read/write paths (ENG-23136).
        ssize_t bytesWritten;
        do {
          bytesWritten = positioned
              ? ::pwritev(fd, iovecs.data(), static_cast<int>(iovecs.size()),
                          static_cast<off_t>(args[2].asNumber()))
              : ::writev(fd, iovecs.data(), static_cast<int>(iovecs.size()));
        } while (bytesWritten < 0 && errno == EINTR);
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
        // Creating a symlink writes a new filesystem entry at `path`. (ENG-22627)
        if (!checkCapability("fs:write:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        // The link's TARGET is gated too: a path-scoped principal must not
        // plant a link that points outside its write grant for other
        // principals (or external tools) to traverse. Relative targets
        // resolve against the link's directory, exactly as the kernel will
        // resolve them. (ENG-22682)
        {
          std::string absTarget = target;
          if (!absTarget.empty() && absTarget[0] != '/') {
            auto slash = path.find_last_of('/');
            std::string dir = slash == std::string::npos ? std::string(".")
                                                         : path.substr(0, slash);
            absTarget = dir + "/" + absTarget;
          }
          if (!checkCapability("fs:write:" + absTarget)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        }
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
        // A hard link creates a new name (`newp`) for the source inode. It needs
        // fs:write at the link location AND fs:read on the source: without the
        // read check, a package could hard-link a file outside its read grant into
        // its own readable dir and read the contents through the alias. (ENG-22627,
        // review follow-up) It also needs fs:write on the SOURCE: the new name
        // aliases the inode, so a later (in-grant) write through `newp` would
        // mutate a file the caller could only read. (ENG-22682)
        if (!checkCapability("fs:read:" + existing)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (!checkCapability("fs:write:" + existing)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        if (!checkCapability("fs:write:" + newp)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Reading a symlink's target is a read/metadata disclosure. (ENG-22627)
        if (!checkCapability("fs:read:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Truncation modifies file contents. (ENG-22627)
        if (!checkCapability("fs:write:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Changing ownership mutates file metadata. (ENG-22627)
        if (!checkCapability("fs:write:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Changing ownership of the symlink itself mutates the link entry, not
        // the final target. Use no-follow-final normalization so `fs:write:path`
        // names the resource the syscall actually mutates. @ref LLP 0013#policy
        // (ENG-22716)
        if (!checkCapabilityNoFollowFinal("fs:write:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Setting atime/mtime mutates file metadata. (ENG-22627)
        if (!checkCapability("fs:write:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
        // Filesystem stats are a read/metadata disclosure. (ENG-22627)
        if (!checkCapability("fs:read:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
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
    // Setting a link's own atime/mtime mutates the link entry, not the final
    // target. Use no-follow-final normalization for the gate. (ENG-22716)
    if (!checkCapabilityNoFollowFinal("fs:write:" + path)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
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
    // Changing a link's own mode mutates the link entry, not the final target.
    // Use no-follow-final normalization for the gate. (ENG-22716)
    if (!checkCapabilityNoFollowFinal("fs:write:" + path)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
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
        requireFdMetadataWrite(runtime, fd, "ftruncate");
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
        requireFdList(runtime, fd, "fstat");
        struct stat sb;
        if (::fstat(fd, &sb) != 0) {
          throwFsError(runtime, "fstat", "");
        }
        return facebook::jsi::String::createFromUtf8(runtime, statJsonFromStat(sb));
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
        requireFdMetadataWrite(runtime, fd, "fsync");
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
        requireFdMetadataWrite(runtime, fd, "fdatasync");
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
        requireFdMetadataWrite(runtime, fd, "fchmod");
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
        requireFdMetadataWrite(runtime, fd, "fchown");
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
        requireFdMetadataWrite(runtime, fd, "fchmod");
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
        requireFdMetadataWrite(runtime, fd, "fchown");
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
        requireFdMetadataWrite(runtime, fd, "futimes");
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

  // -------------------------------------------------------------------------
  // True-async natives (ENG-23497): worker-pool-backed readFile/writeFile/
  // read/write/stat. Validation + capability checks run here on the JS
  // thread; the returned Promise settles on the JS thread after the worker
  // completes. fs.js routes the callback/promise API through these when
  // present and falls back to the deferred-sync path when absent (e.g. the
  // Windows backend, which does not implement them yet).
  // -------------------------------------------------------------------------

  // __exactFsReadFileAsync(pathOrFd, flags, mode) -> Promise<Uint8Array>
  // fd form reads from the fd's current position to EOF without closing it
  // (mirroring readFileSync's fd branch); path form opens/reads/closes on the
  // worker thread.
  auto openAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsOpenAsync"), 4,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactFsOpenAsync: path and flags required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        int flags = parseOpenFlagsArg(runtime, args, count, 1);
        int mode = count > 2 && args[2].isNumber() ? static_cast<int>(args[2].asNumber()) : 0666;
        bool canRead = false, canWrite = false;
        const bool armed = ex_host_is_armed() == 1;
        uint64_t principal = currentPrincipalId();
        std::string presentedHandle;
        if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
          if (!args[3].isString()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsOpenAsync: typed handleId must be a string");
          }
          presentedHandle = args[3].asString(runtime).utf8(runtime);
        }
        if (!armed) {
          requireOpenCapability(runtime, path, flags, canRead, canWrite);
          return startFsAsync(handle, runtime, [principal, path, flags, mode, canRead, canWrite]() {
            return fsOpenWork(principal, path, flags, mode, canRead, canWrite);
          });
        }
        classifyOpenAccess(flags, canRead, canWrite);
        const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
        if (ex_host_authorize_typed_fs_open(
                principal, path.c_str(), 0, 0, -1, -1,
                canRead ? 1 : 0, canWrite ? 1 : 0, presented) != 1) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        auto parentAndName = splitParentAndName(path);
        auto parentPath = std::move(parentAndName.first);
        auto name = std::move(parentAndName.second);
        int parentFd = ::open(parentPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parentFd < 0) throwFsError(runtime, "open", path);
        auto parent = retainedParentFd(parentFd);
        if (ex_host_authorize_typed_fs_open(
                principal, path.c_str(), 3, 0, *parent, -1,
                canRead ? 1 : 0, canWrite ? 1 : 0, presented) != 1) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        return startFsAsync(
            handle, runtime,
            [principal, path, name, flags, mode, canRead, canWrite,
             presentedHandle, parent = std::move(parent)]() mutable {
          return fsOpenWorkArmed(
              principal, path, name, flags, mode, canRead, canWrite,
              presentedHandle, std::move(parent));
        });
      });
  rt.global().setProperty(rt, "__exactFsOpenAsync", std::move(openAsyncFn));

  auto closeAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsCloseAsync"), 1,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsCloseAsync: fd required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        std::optional<FdEntry> entry = requireOwnedFd(runtime, fd, "close");
        // Revoke authority before dispatch so no later JS operation can race
        // the close or acquire authority through integer fd reuse. Perform the
        // close itself before yielding to the worker: deferring close(fd)
        // would allow a concurrently closed descriptor number to be reused and
        // make the worker close a different kernel object.
        unregisterFd(fd);
        auto closeResult = fsCloseWork(fd);
        if (!closeResult.ok) restoreFdEntry(fd, entry);
        return startFsAsync(
            handle, runtime,
            [closeResult = std::move(closeResult)]() mutable {
              return std::move(closeResult);
            });
      });
  rt.global().setProperty(rt, "__exactFsCloseAsync", std::move(closeAsyncFn));

  auto readFileAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadFileAsync"), 4,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count == 0 || (!args[0].isString() && !args[0].isNumber())) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadFileAsync: path or fd required");
        }
        if (args[0].isNumber()) {
          int fd = static_cast<int>(args[0].asNumber());
          requireFdRead(runtime, fd, "read");
          auto entry = requireOwnedFd(runtime, fd, "read");
          auto workerFd = duplicateFdForAsync(runtime, fd, "read");
          if (ex_host_is_armed() == 1) {
            if (!entry.retainedParent) {
              throw facebook::jsi::JSError(
                  runtime, "readFile: armed fd has no retained parent");
            }
            return startFsAsync(
                handle, runtime,
                [workerFd, principal = entry.owner, path = entry.path,
                 presentedHandle = entry.presentedHandleId,
                 parent = entry.retainedParent]() -> FsAsyncResult {
                  return fsReadFileArmedWork(
                      principal, path, presentedHandle, parent,
                      workerFd->get());
                });
          }
          return startFsAsync(handle, runtime, [workerFd]() -> FsAsyncResult {
            return fsRunOwnedFd(workerFd, [](int owned) {
              return fsReadWholeFdWork(owned, false, "");
            });
          });
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        int posixFlags = parseOpenFlagsArg(runtime, args, count, 1);
        bool needsRead = false;
        bool needsWrite = false;
        if (ex_host_is_armed() == 1) {
          classifyOpenAccess(posixFlags, needsRead, needsWrite);
          if (!needsRead || needsWrite) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          std::string presentedHandle;
          if (count > 3 && !args[3].isUndefined() && !args[3].isNull()) {
            if (!args[3].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactFsReadFileAsync: typed handleId must be a string");
            }
            presentedHandle = args[3].asString(runtime).utf8(runtime);
          }
          auto prepared = prepareArmedReadTarget(
              runtime, path, 2, presentedHandle);
          auto parent = std::move(prepared.first);
          auto name = std::move(prepared.second);
          int fdRaw = ::openat(
              *parent, name.c_str(),
              O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
          if (fdRaw < 0) throwFsError(runtime, "open", path);
          auto fd = retainedFd(fdRaw);
          struct stat sb = {};
          if (::fstat(fdRaw, &sb) != 0 || !S_ISREG(sb.st_mode)) {
            errno = EACCES;
            throwFsError(runtime, "open", path);
          }
          uint64_t principal = currentPrincipalId();
          const char* presented = presentedHandle.empty() ? nullptr : presentedHandle.c_str();
          if (ex_host_authorize_typed_fs_open(
                  principal, path.c_str(), 1, 2, *parent, fdRaw, 1, 0,
                  presented) != 1) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          return startFsAsync(
              handle, runtime,
              [principal, path, presentedHandle, parent = std::move(parent),
               fd = std::move(fd)]() {
                return fsReadFileArmedWork(
                    principal, path, presentedHandle, parent, *fd);
              });
        }
        requireOpenCapability(runtime, path, posixFlags, needsRead, needsWrite);
        int mode = 0666;
        if (count > 2 && args[2].isNumber()) {
          mode = static_cast<int>(args[2].asNumber());
        }
        return startFsAsync(
            handle, runtime, [path, posixFlags, mode]() -> FsAsyncResult {
              return fsReadFilePathWork(path, posixFlags, mode);
            });
      });
  rt.global().setProperty(rt, "__exactFsReadFileAsync", std::move(readFileAsyncFn));

  // __exactFsWriteFileAsync(pathOrFd, data, flags, mode, flush) ->
  // Promise<undefined>. fd form writes at the fd's current position without
  // closing it; path form opens/writes/(fsyncs)/closes on the worker thread.
  auto writeFileAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsWriteFileAsync"), 6,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || (!args[0].isString() && !args[0].isNumber())) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWriteFileAsync: path/fd and data required");
        }
        // Copy the bytes on the JS thread: the caller may mutate or GC the
        // source buffer while the worker is in flight.
        auto dataBytes = std::make_shared<std::vector<uint8_t>>(
            extractBytes(runtime, args[1]));
        bool flush = count > 4 && args[4].isBool() && args[4].getBool();
        if (args[0].isNumber()) {
          int fd = static_cast<int>(args[0].asNumber());
          requireFdWrite(runtime, fd, "write");
          auto workerFd = duplicateFdForAsync(runtime, fd, "write");
          return startFsAsync(handle, runtime, [workerFd, dataBytes, flush]() -> FsAsyncResult {
            return fsRunOwnedFd(workerFd, [dataBytes, flush](int owned) { return fsWriteAllFdWork(owned, *dataBytes, flush, false, ""); });
          });
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        int posixFlags = O_WRONLY | O_CREAT | O_TRUNC;
        if (count > 2 && !args[2].isNull() && !args[2].isUndefined()) {
          posixFlags = parseOpenFlagsArg(runtime, args, count, 2);
        }
        bool needsRead = false;
        bool needsWrite = false;
        int mode = 0666;
        if (count > 3 && args[3].isNumber()) {
          mode = static_cast<int>(args[3].asNumber());
        }
        if (ex_host_is_armed() == 1) {
          classifyOpenAccess(posixFlags, needsRead, needsWrite);
          if (!needsWrite) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          std::string presentedHandle;
          if (count > 5 && !args[5].isUndefined() && !args[5].isNull()) {
            if (!args[5].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactFsWriteFileAsync: typed handleId must be a string");
            }
            presentedHandle = args[5].asString(runtime).utf8(runtime);
          }
          auto descriptors = openArmedWriteTarget(
              runtime, path, 7, posixFlags, mode, true, presentedHandle);
          uint64_t principal = currentPrincipalId();
          return startFsAsync(
              handle, runtime,
              [principal, path, presentedHandle,
               parent = std::move(descriptors.parent),
               fd = std::move(descriptors.target), dataBytes, flush]() {
                return fsWriteFileArmedWork(
                    principal, path, presentedHandle, parent, fd,
                    *dataBytes, flush);
              });
        }
        requireOpenCapability(runtime, path, posixFlags, needsRead, needsWrite);
        return startFsAsync(
            handle, runtime,
            [path, dataBytes, posixFlags, mode, flush]() -> FsAsyncResult {
              return fsWriteFilePathWork(path, *dataBytes, posixFlags, mode, flush);
            });
      });
  rt.global().setProperty(rt, "__exactFsWriteFileAsync", std::move(writeFileAsyncFn));

  // __exactFsReadAsync(fd, length, position) -> Promise<Uint8Array>
  // Async sibling of __exactFsRead (same positional/pread semantics).
  auto fsReadAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadAsync"), 3,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadAsync: fd and length required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        size_t length = static_cast<size_t>(args[1].asNumber());
        requireFdRead(runtime, fd, "read");
        auto workerFd = duplicateFdForAsync(runtime, fd, "read");
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        return startFsAsync(
            handle, runtime, [workerFd, length, positioned, position]() -> FsAsyncResult {
              return fsRunOwnedFd(workerFd, [length, positioned, position](int owned) { return fsReadChunkWork(owned, length, positioned, position); });
            });
      });
  rt.global().setProperty(rt, "__exactFsReadAsync", std::move(fsReadAsyncFn));

  // __exactFsWriteAsync(fd, data, position) -> Promise<number bytesWritten>
  // Async sibling of __exactFsWrite (same positional/pwrite semantics).
  auto fsWriteAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsWriteAsync"), 3,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWriteAsync: fd and data required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        requireFdWrite(runtime, fd, "write");
        auto workerFd = duplicateFdForAsync(runtime, fd, "write");
        auto dataBytes = std::make_shared<std::vector<uint8_t>>(
            extractBytes(runtime, args[1]));
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        return startFsAsync(
            handle, runtime, [workerFd, dataBytes, positioned, position]() -> FsAsyncResult {
              return fsRunOwnedFd(workerFd, [dataBytes, positioned, position](int owned) { return fsWriteChunkWork(owned, *dataBytes, positioned, position); });
            });
      });
  rt.global().setProperty(rt, "__exactFsWriteAsync", std::move(fsWriteAsyncFn));

  // __exactFsReadvAsync(fd, buffers, position) -> Promise<Uint8Array>
  // Worker-pool sibling of __exactFsReadv. The worker reads into copied
  // native buffers and resolves a compact byte payload; fs.js scatters it
  // back into the caller's Buffer/TypedArray/DataView objects on the JS
  // thread, preserving the no-JSI-off-thread rule.
  auto fsReadvAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsReadvAsync"), 3,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadvAsync: fd and buffers required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        requireFdRead(runtime, fd, "readv");
        auto workerFd = duplicateFdForAsync(runtime, fd, "readv");
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        if (!parseIoVecArguments(runtime, args[1], buffers, iovecs, nullptr, false)) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsReadvAsync: buffers must be Uint8Array-like objects");
        }
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto buffersPtr = std::make_shared<std::vector<std::vector<uint8_t>>>(
            std::move(buffers));
        return startFsAsync(
            handle, runtime, [workerFd, buffersPtr, positioned, position]() -> FsAsyncResult {
              return fsRunOwnedFd(workerFd, [buffersPtr, positioned, position](int owned) { return fsReadvWork(owned, *buffersPtr, positioned, position); });
            });
      });
  rt.global().setProperty(rt, "__exactFsReadvAsync", std::move(fsReadvAsyncFn));

  // __exactFsWritevAsync(fd, buffers, position) -> Promise<number bytesWritten>
  // Async sibling of __exactFsWritev (same positional/pwritev semantics).
  auto fsWritevAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsWritevAsync"), 3,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWritevAsync: fd and buffers required");
        }
        int fd = static_cast<int>(args[0].asNumber());
        requireFdWrite(runtime, fd, "writev");
        auto workerFd = duplicateFdForAsync(runtime, fd, "writev");
        std::vector<std::vector<uint8_t>> buffers;
        std::vector<struct iovec> iovecs;
        if (!parseIoVecArguments(runtime, args[1], buffers, iovecs, nullptr)) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsWritevAsync: buffers must be Uint8Array-like objects");
        }
        bool positioned = count > 2 && args[2].isNumber() && args[2].asNumber() >= 0;
        int64_t position = positioned ? static_cast<int64_t>(args[2].asNumber()) : -1;
        auto buffersPtr = std::make_shared<std::vector<std::vector<uint8_t>>>(
            std::move(buffers));
        return startFsAsync(
            handle, runtime, [workerFd, buffersPtr, positioned, position]() -> FsAsyncResult {
              return fsRunOwnedFd(workerFd, [buffersPtr, positioned, position](int owned) { return fsWritevWork(owned, *buffersPtr, positioned, position); });
            });
      });
  rt.global().setProperty(rt, "__exactFsWritevAsync", std::move(fsWritevAsyncFn));

  // __exactFsPathAsync(op, pathOrA, pathOrB, x, y, z) -> Promise<string|undefined>
  // Generic worker-pool path op for simple metadata/directory calls. Argument
  // validation and capability checks remain on the JS thread; the worker gets
  // only plain strings/numbers and performs the blocking syscall.
  auto fsPathAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsPathAsync"), 6,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsPathAsync: op and path required");
        }
        auto op = args[0].toString(runtime).utf8(runtime);
        auto a = args[1].toString(runtime).utf8(runtime);
        std::string b;
        if (count > 2 && args[2].isString()) {
          b = args[2].toString(runtime).utf8(runtime);
        }
        double x = (count > 3 && args[3].isNumber()) ? args[3].asNumber() : 0;
        double y = (count > 4 && args[4].isNumber()) ? args[4].asNumber() : 0;
        double z = (count > 5 && args[5].isNumber()) ? args[5].asNumber() : 0;
        uint64_t principal = currentPrincipalId();

        if (ex_host_is_armed() == 1 && op == "readdir") {
          auto descriptors = openArmedListTarget(
              runtime, a, 4, O_RDONLY | O_DIRECTORY, "");
          return startFsAsync(
              handle, runtime,
              [principal, path = a, parent = std::move(descriptors.parent),
               target = std::move(descriptors.target)]() {
                return fsReaddirArmedWork(principal, path, parent, target);
              });
        }
        if (ex_host_is_armed() == 1 && op == "realpath") {
          auto descriptors = openArmedListTarget(
              runtime, a, 9, metadataOpenFlags(), "");
          return startFsAsync(
              handle, runtime,
              [principal, path = a, parent = std::move(descriptors.parent),
               target = std::move(descriptors.target)]() {
                return fsRealpathArmedWork(principal, path, parent, target);
              });
        }
        if (ex_host_is_armed() == 1 && op == "mkdtemp") {
          return startFsAsync(handle, runtime, [principal, prefix = a]() {
            return fsMkdtempArmedWork(principal, prefix);
          });
        }

        if (op == "readdir" || op == "realpath" || op == "readlink" ||
            op == "statfs") {
          if (!checkCapability("fs:read:" + a)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "mkdir" || op == "rmdir" || op == "unlink" ||
                   op == "chmod" || op == "truncate" || op == "chown" ||
                   op == "utime") {
          if (!(op == "mkdir" && ex_host_is_armed() == 1) &&
              !checkCapability("fs:write:" + a)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "lchown" || op == "lchmod" || op == "lutime") {
          if (!checkCapabilityNoFollowFinal("fs:write:" + a)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "access") {
          if ((static_cast<int32_t>(x) & 2) != 0) {
            if (!checkCapability("fs:write:" + a)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          } else if (!checkCapability("fs:read:" + a)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "rename") {
          if (b.empty()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsPathAsync: rename destination required");
          }
          if (!checkCapability("fs:write:" + a) || !checkCapability("fs:write:" + b)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "copyfile" || op == "copyfile_excl") {
          if (b.empty()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsPathAsync: copy destination required");
          }
          if (!checkCapability("fs:read:" + a) || !checkCapability("fs:write:" + b)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "symlink") {
          if (b.empty()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsPathAsync: symlink path required");
          }
          if (!checkCapability("fs:write:" + b)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          std::string absTarget = a;
          if (!absTarget.empty() && absTarget[0] != '/') {
            auto slash = b.find_last_of('/');
            std::string dir = slash == std::string::npos ? std::string(".")
                                                         : b.substr(0, slash);
            absTarget = dir + "/" + absTarget;
          }
          if (!checkCapability("fs:write:" + absTarget)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op == "link") {
          if (b.empty()) {
            throw facebook::jsi::JSError(
                runtime, "__exactFsPathAsync: link destination required");
          }
          if (!checkCapability("fs:read:" + a) ||
              !checkCapability("fs:write:" + a) ||
              !checkCapability("fs:write:" + b)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
        } else if (op != "mkdtemp") {
          throw facebook::jsi::JSError(runtime, "__exactFsPathAsync: unsupported op");
        }

        return startFsAsync(
            handle, runtime, [op, a, b, x, y, z, principal]() -> FsAsyncResult {
              return fsPathOpWork(op, a, b, x, y, z, principal);
            });
      });
  rt.global().setProperty(rt, "__exactFsPathAsync", std::move(fsPathAsyncFn));

  // __exactFsFdAsync(op, fd, x, y) -> Promise<void>. Capability/ownership
  // validation and dup() happen before dispatch; only the blocking syscall is
  // performed by the worker. @ref LLP 0003#blocking-work-worker-pools
  auto fsFdAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsFdAsync"), 4,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[0].isString() || !args[1].isNumber()) {
          throw facebook::jsi::JSError(runtime, "__exactFsFdAsync: op and fd required");
        }
        auto op = args[0].toString(runtime).utf8(runtime);
        int fd = static_cast<int>(args[1].asNumber());
        double x = count > 2 && args[2].isNumber() ? args[2].asNumber() : 0;
        double y = count > 3 && args[3].isNumber() ? args[3].asNumber() : 0;
        if (op == "fchmod" || op == "fchown" || op == "ftruncate" || op == "futimes") {
          requireFdMetadataWrite(runtime, fd, op.c_str());
        } else if (op == "fsync" || op == "fdatasync") {
          requireFdMetadataWrite(runtime, fd, op.c_str());
        } else {
          throw facebook::jsi::JSError(runtime, "__exactFsFdAsync: unsupported op");
        }
        auto workerFd = duplicateFdForAsync(runtime, fd, op.c_str());
        return startFsAsync(handle, runtime, [op, workerFd, x, y]() -> FsAsyncResult {
          return fsRunOwnedFd(workerFd, [op, x, y](int owned) { return fsFdOpWork(op, owned, x, y); });
        });
      });
  rt.global().setProperty(rt, "__exactFsFdAsync", std::move(fsFdAsyncFn));

  // __exactFsStatAsync(pathOrFd, kind) -> Promise<JSON string>
  // kind is "stat" | "lstat" (path form) | "fstat" (fd form). Payload shape is
  // identical to __exactStat / __exactLstat / __exactFsFstatSync.
  auto fsStatAsyncFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactFsStatAsync"), 3,
      [handle](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
               const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 2 || !args[1].isString()) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsStatAsync: target and kind required");
        }
        auto kind = args[1].toString(runtime).utf8(runtime);
        if (kind == "fstat") {
          if (!args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactFsStatAsync: fd required");
          }
          int fd = static_cast<int>(args[0].asNumber());
          if (ex_host_is_armed() == 1) {
            auto entry = requireOwnedFd(runtime, fd, "fstat");
            if (!entry.retainedParent) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            auto workerFd = duplicateFdForAsync(runtime, fd, "fstat");
            auto parent = entry.retainedParent;
            auto principal = entry.owner;
            auto path = entry.path;
            auto presentedHandle = entry.presentedHandleId;
            return startFsAsync(
                handle, runtime,
                [workerFd, parent, principal, path, presentedHandle]() {
                  return fsStatArmedWork(
                      principal, path, 8, presentedHandle, parent,
                      workerFd->get());
                });
          }
          requireFdRead(runtime, fd, "fstat");
          auto workerFd = duplicateFdForAsync(runtime, fd, "fstat");
          return startFsAsync(handle, runtime, [workerFd]() -> FsAsyncResult {
            return fsRunOwnedFd(workerFd, [](int owned) { return fsFstatWork(owned); });
          });
        }
        if (!args[0].isString() || (kind != "stat" && kind != "lstat")) {
          throw facebook::jsi::JSError(
              runtime, "__exactFsStatAsync: path and stat/lstat kind required");
        }
        auto path = args[0].toString(runtime).utf8(runtime);
        if (ex_host_is_armed() == 1) {
          std::string presentedHandle;
          if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
            if (!args[2].isString()) {
              throw facebook::jsi::JSError(
                  runtime, "__exactFsStatAsync: typed handleId must be a string");
            }
            presentedHandle = args[2].asString(runtime).utf8(runtime);
          }
          uint32_t surface = kind == "lstat" ? 11 : 8;
          auto descriptors = kind == "lstat"
              ? openArmedLinkTarget(runtime, path, surface, presentedHandle)
              : openArmedListTarget(
                    runtime, path, surface, metadataOpenFlags(),
                    presentedHandle);
          uint64_t principal = currentPrincipalId();
          auto targetFd = descriptors.target;
          return startFsAsync(
              handle, runtime,
              [principal, path, surface, presentedHandle,
               parent = std::move(descriptors.parent), targetFd]() {
                return fsStatArmedWork(
                    principal, path, surface, presentedHandle, parent, *targetFd);
              });
        }
        // Same gate as __exactStat / __exactLstat.
        if (!checkCapability("fs:read:" + path)) {
          throw facebook::jsi::JSError(runtime, "Permission denied");
        }
        bool isLstat = kind == "lstat";
        return startFsAsync(handle, runtime, [path, isLstat]() -> FsAsyncResult {
          return fsStatPathWork(path, isLstat);
        });
      });
  rt.global().setProperty(rt, "__exactFsStatAsync", std::move(fsStatAsyncFn));
}
