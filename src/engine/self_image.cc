// @system @ref LLP 0029#3-identity-separated-digest-domains — compiled boot
// opens one descriptor and proves that it names the object backing the mapped
// executable before any envelope bytes are admitted.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_OSX
#include <libproc.h>
#include <mach-o/dyld.h>
#include <sys/proc_info.h>
#endif
#endif

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

namespace {

void set_error(char* out, size_t out_len, const char* message) {
  if (out == nullptr || out_len == 0) return;
  std::snprintf(out, out_len, "%s", message);
}

void set_errno_error(char* out, size_t out_len, const char* action) {
  if (out == nullptr || out_len == 0) return;
  std::snprintf(out, out_len, "%s: %s", action, std::strerror(errno));
}

#if defined(__linux__)
bool linux_mapping_matches(int fd, const void* marker, char* error,
                           size_t error_len) {
  struct stat opened = {};
  if (fstat(fd, &opened) != 0) {
    set_errno_error(error, error_len, "cannot inspect pinned executable");
    return false;
  }

  FILE* maps = std::fopen("/proc/self/maps", "r");
  if (maps == nullptr) {
    set_errno_error(error, error_len, "cannot inspect executable mappings");
    return false;
  }
  const auto address = reinterpret_cast<uintptr_t>(marker);
  char line[4096] = {};
  bool found = false;
  bool matched = false;
  while (std::fgets(line, sizeof(line), maps) != nullptr) {
    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long offset = 0;
    unsigned int device_major = 0;
    unsigned int device_minor = 0;
    unsigned long long inode = 0;
    if (std::sscanf(line, "%llx-%llx %*4s %llx %x:%x %llu", &start, &end,
                    &offset, &device_major, &device_minor, &inode) != 6 ||
        address < start || address >= end) {
      continue;
    }
    found = true;
    const dev_t mapped_device = makedev(device_major, device_minor);
    matched = static_cast<unsigned long long>(opened.st_ino) == inode &&
        opened.st_dev == mapped_device;
    if (!matched) {
      set_error(error, error_len,
                "opened executable is not the object backing its mapped code");
    }
    break;
  }
  std::fclose(maps);
  if (!found) {
    set_error(error, error_len,
              "cannot locate the executable acquisition mapping");
  }
  return matched;
}
#endif

#if defined(__APPLE__) && TARGET_OS_OSX
bool macos_mapping_matches(int fd, char* error, size_t error_len) {
  struct stat opened = {};
  if (fstat(fd, &opened) != 0) {
    set_errno_error(error, error_len, "cannot inspect pinned executable");
    return false;
  }
  const mach_header* header = _dyld_get_image_header(0);
  if (header == nullptr) {
    set_error(error, error_len, "cannot identify the mapped main Mach-O image");
    return false;
  }
  proc_regionwithpathinfo region = {};
  const int bytes = proc_pidinfo(
      getpid(), PROC_PIDREGIONPATHINFO, reinterpret_cast<uint64_t>(header),
      &region, sizeof(region));
  if (bytes != sizeof(region)) {
    set_error(error, error_len, "cannot identify the mapped main Mach-O vnode");
    return false;
  }
  const auto& mapped = region.prp_vip.vip_vi.vi_stat;
  if (opened.st_dev != static_cast<dev_t>(mapped.vst_dev) ||
      opened.st_ino != mapped.vst_ino ||
      mapped.vst_ino == 0) {
    set_error(error, error_len,
              "opened executable is not the object backing the mapped Mach-O image");
    return false;
  }
  return true;
}
#endif

}  // namespace

extern "C" int32_t ex_open_pinned_self_image(char* error, size_t error_len) {
  if (error != nullptr && error_len != 0) error[0] = '\0';
#if defined(__linux__)
  const int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    set_errno_error(error, error_len, "cannot open /proc/self/exe");
    return -1;
  }
  struct stat opened = {};
  if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode)) {
    set_error(error, error_len, "pinned executable is not a regular file");
    close(fd);
    return -1;
  }
  if (!linux_mapping_matches(
          fd, reinterpret_cast<const void*>(&ex_open_pinned_self_image), error,
          error_len)) {
    close(fd);
    return -1;
  }
  return fd;
#elif defined(__APPLE__) && TARGET_OS_OSX
  uint32_t path_size = 0;
  if (_NSGetExecutablePath(nullptr, &path_size) != -1 || path_size == 0) {
    set_error(error, error_len, "cannot size the main executable path");
    return -1;
  }
  char* path = new char[path_size];
  if (_NSGetExecutablePath(path, &path_size) != 0) {
    delete[] path;
    set_error(error, error_len, "cannot identify the main executable path");
    return -1;
  }
  const int fd = open(path, O_RDONLY | O_CLOEXEC);
  delete[] path;
  if (fd < 0) {
    set_errno_error(error, error_len, "cannot open the main executable");
    return -1;
  }
  struct stat opened = {};
  if (fstat(fd, &opened) != 0 || !S_ISREG(opened.st_mode)) {
    set_error(error, error_len, "pinned executable is not a regular file");
    close(fd);
    return -1;
  }
  if (!macos_mapping_matches(fd, error, error_len)) {
    close(fd);
    return -1;
  }
  return fd;
#else
  set_error(error, error_len,
            "pinned self-image acquisition is unsupported on this target");
  return -1;
#endif
}
