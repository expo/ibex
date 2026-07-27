// @system @ref LLP 0029#3-identity-separated-digest-domains — compiled boot
// opens one descriptor and proves that it names the object backing the mapped
// executable before any envelope bytes are admitted.

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#if defined(__APPLE__)
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/mman.h>
#endif

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
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

#if !defined(_WIN32)
void set_errno_error(char* out, size_t out_len, const char* action) {
  if (out == nullptr || out_len == 0) return;
  std::snprintf(out, out_len, "%s: %s", action, std::strerror(errno));
}
#endif

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

#if defined(__APPLE__)
bool apple_vm_object_for_address(
    const void* address,
    vm_region_submap_info_data_64_t* output) {
  vm_address_t region_address = reinterpret_cast<vm_address_t>(address);
  vm_size_t region_size = 0;
  natural_t nesting_depth = 0;
  mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
  if (vm_region_recurse_64(
          mach_task_self(),
          &region_address,
          &region_size,
          &nesting_depth,
          reinterpret_cast<vm_region_recurse_info_t>(output),
          &count) != KERN_SUCCESS) {
    return false;
  }
  const auto requested = reinterpret_cast<vm_address_t>(address);
  return region_size != 0 && requested >= region_address &&
      requested - region_address < region_size &&
      output->external_pager != 0 && output->object_id_full != 0;
}

bool apple_mapping_matches(
    int fd,
    const void* marker,
    char* error,
    size_t error_len) {
  const mach_header* header = _dyld_get_image_header(0);
  if (header == nullptr) {
    set_error(error, error_len, "cannot identify the mapped main Mach-O image");
    return false;
  }
  Dl_info marker_owner = {};
  if (dladdr(marker, &marker_owner) == 0 ||
      marker_owner.dli_fbase != header) {
    set_error(
        error, error_len, "self-image acquisition is not in the main executable");
    return false;
  }
  struct stat opened = {};
  if (fstat(fd, &opened) != 0 || opened.st_size <= 0) {
    set_errno_error(error, error_len, "cannot inspect pinned executable");
    return false;
  }
  void* file_mapping = mmap(
      nullptr,
      static_cast<size_t>(opened.st_size),
      PROT_READ,
      MAP_PRIVATE,
      fd,
      0);
  if (file_mapping == MAP_FAILED) {
    set_errno_error(error, error_len, "cannot map the pinned executable");
    return false;
  }
  vm_region_submap_info_data_64_t loaded_info = {};
  vm_region_submap_info_data_64_t opened_info = {};
  const bool observed =
      apple_vm_object_for_address(header, &loaded_info) &&
      apple_vm_object_for_address(file_mapping, &opened_info);
  munmap(file_mapping, static_cast<size_t>(opened.st_size));
  if (!observed) {
    set_error(
        error, error_len, "cannot identify the mapped main Mach-O VM object");
    return false;
  }
  if (loaded_info.object_id_full != opened_info.object_id_full ||
      loaded_info.offset != opened_info.offset) {
    set_error(error, error_len,
              "opened executable is not the object backing the mapped Mach-O "
              "image");
    return false;
  }
  return true;
}
#endif  // __APPLE__

#if defined(_WIN32)
// Windows does not publish a user-mode API that duplicates the loader's image
// section handle. The strongest constructible proof is therefore:
//   * lock one regular main-executable handle against write/delete sharing;
//   * map that exact handle as SEC_IMAGE;
//   * compare PE headers and every immutable, non-discardable mapped section
//     with the live main image, ignoring only loader-written relocation/IAT
//     bytes; and
//   * retain the handle for all subsequent identity checks and hashing.
// Bytes outside the PE image mapping (notably certificate/overlay bytes) are
// authenticated as current-file and trusted-build input, not as loader-section
// bytes. Any mapped-byte mismatch or unsupported relocation fails closed.
bool checked_image_range(uint32_t start, uint32_t length, uint32_t image_size) {
  return start <= image_size && length <= image_size - start;
}

bool mark_windows_loader_mutations(
    const uint8_t* mapped,
    const IMAGE_NT_HEADERS* headers,
    std::vector<uint8_t>* ignored,
    char* error,
    size_t error_len) {
  const uint32_t image_size = headers->OptionalHeader.SizeOfImage;
  const auto& relocations =
      headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (relocations.Size != 0) {
    if (!checked_image_range(
            relocations.VirtualAddress, relocations.Size, image_size)) {
      set_error(error, error_len, "mapped executable relocation range is invalid");
      return false;
    }
    uint32_t cursor = relocations.VirtualAddress;
    const uint32_t end = cursor + relocations.Size;
    while (cursor < end) {
      if (!checked_image_range(
              cursor, sizeof(IMAGE_BASE_RELOCATION), image_size)) {
        set_error(
            error, error_len, "mapped executable relocation block is invalid");
        return false;
      }
      const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
          mapped + cursor);
      if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
          block->SizeOfBlock > end - cursor ||
          (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) %
                  sizeof(uint16_t) !=
              0) {
        set_error(
            error, error_len, "mapped executable relocation block is malformed");
        return false;
      }
      const auto* entries = reinterpret_cast<const uint16_t*>(
          mapped + cursor + sizeof(IMAGE_BASE_RELOCATION));
      const size_t entry_count =
          (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
          sizeof(uint16_t);
      for (size_t index = 0; index < entry_count; ++index) {
        const uint16_t type = entries[index] >> 12u;
        const uint32_t offset = entries[index] & 0x0fffu;
        uint32_t width = 0;
        switch (type) {
          case IMAGE_REL_BASED_ABSOLUTE:
            continue;
          case IMAGE_REL_BASED_HIGH:
          case IMAGE_REL_BASED_LOW:
            width = 2;
            break;
          case IMAGE_REL_BASED_HIGHLOW:
            width = 4;
            break;
          case IMAGE_REL_BASED_DIR64:
            width = 8;
            break;
          default:
            set_error(
                error,
                error_len,
                "mapped executable uses an unsupported relocation type");
            return false;
        }
        if (block->VirtualAddress > UINT32_MAX - offset) {
          set_error(error, error_len, "mapped executable relocation overflows");
          return false;
        }
        const uint32_t target = block->VirtualAddress + offset;
        if (!checked_image_range(target, width, image_size)) {
          set_error(error, error_len, "mapped executable relocation is invalid");
          return false;
        }
        std::fill(
            ignored->begin() + target,
            ignored->begin() + target + width,
            uint8_t{1});
      }
      cursor += block->SizeOfBlock;
    }
  }

  const auto& iat =
      headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  if (iat.Size != 0) {
    if (!checked_image_range(iat.VirtualAddress, iat.Size, image_size)) {
      set_error(error, error_len, "mapped executable IAT range is invalid");
      return false;
    }
    std::fill(
        ignored->begin() + iat.VirtualAddress,
        ignored->begin() + iat.VirtualAddress + iat.Size,
        uint8_t{1});
  }
  return true;
}

bool windows_mapping_matches(
    HANDLE file,
    HMODULE module,
    char* error,
    size_t error_len) {
  HANDLE section = CreateFileMappingW(
      file,
      nullptr,
      PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
      0,
      0,
      nullptr);
  if (section == nullptr) {
    set_error(error, error_len, "cannot create a pinned executable image view");
    return false;
  }
  void* opened_view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
  if (opened_view == nullptr) {
    CloseHandle(section);
    set_error(error, error_len, "cannot map the pinned executable image");
    return false;
  }
  const auto close_view = [&]() {
    UnmapViewOfFile(opened_view);
    CloseHandle(section);
  };
  const auto* opened = static_cast<const uint8_t*>(opened_view);
  const auto* loaded = reinterpret_cast<const uint8_t*>(module);
  const auto* opened_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(opened);
  const auto* loaded_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(loaded);
  if (opened_dos->e_magic != IMAGE_DOS_SIGNATURE ||
      loaded_dos->e_magic != IMAGE_DOS_SIGNATURE ||
      opened_dos->e_lfanew <= 0 ||
      opened_dos->e_lfanew != loaded_dos->e_lfanew) {
    close_view();
    set_error(error, error_len, "mapped main executable has invalid DOS headers");
    return false;
  }
  const auto* opened_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      opened + opened_dos->e_lfanew);
  const auto* loaded_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(
      loaded + loaded_dos->e_lfanew);
  if (opened_headers->Signature != IMAGE_NT_SIGNATURE ||
      loaded_headers->Signature != IMAGE_NT_SIGNATURE ||
      opened_headers->OptionalHeader.Magic != loaded_headers->OptionalHeader.Magic ||
      opened_headers->OptionalHeader.SizeOfImage == 0 ||
      opened_headers->OptionalHeader.SizeOfImage >
          static_cast<uint32_t>(INT32_MAX) ||
      opened_headers->OptionalHeader.SizeOfHeaders == 0 ||
      !checked_image_range(
          0,
          opened_headers->OptionalHeader.SizeOfHeaders,
          opened_headers->OptionalHeader.SizeOfImage) ||
      std::memcmp(
          opened,
          loaded,
          opened_headers->OptionalHeader.SizeOfHeaders) != 0) {
    close_view();
    set_error(
        error,
        error_len,
        "opened executable headers do not match the mapped main PE image");
    return false;
  }

  const uint32_t image_size = opened_headers->OptionalHeader.SizeOfImage;
  std::vector<uint8_t> ignored;
  try {
    ignored.assign(image_size, uint8_t{0});
  } catch (...) {
    close_view();
    set_error(
        error, error_len, "mapped executable comparison exhausted resources");
    return false;
  }
  if (!mark_windows_loader_mutations(
          opened, opened_headers, &ignored, error, error_len)) {
    close_view();
    return false;
  }
  const auto* opened_sections = IMAGE_FIRST_SECTION(opened_headers);
  const auto* loaded_sections = IMAGE_FIRST_SECTION(loaded_headers);
  size_t checked_bytes = 0;
  size_t checked_executable_bytes = 0;
  for (uint16_t index = 0;
       index < opened_headers->FileHeader.NumberOfSections;
       ++index) {
    const auto& section_header = opened_sections[index];
    if (std::memcmp(
            &section_header,
            &loaded_sections[index],
            sizeof(IMAGE_SECTION_HEADER)) != 0) {
      close_view();
      set_error(
          error,
          error_len,
          "opened executable sections do not match the mapped main PE image");
      return false;
    }
    if ((section_header.Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
        (section_header.Characteristics & IMAGE_SCN_MEM_WRITE) != 0 ||
        (section_header.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0) {
      continue;
    }
    const uint32_t start = section_header.VirtualAddress;
    const uint32_t length = section_header.Misc.VirtualSize;
    if (!checked_image_range(start, length, image_size)) {
      close_view();
      set_error(error, error_len, "mapped executable section range is invalid");
      return false;
    }
    MEMORY_BASIC_INFORMATION memory = {};
    if (length != 0 &&
        (VirtualQuery(loaded + start, &memory, sizeof(memory)) == 0 ||
         memory.State != MEM_COMMIT)) {
      close_view();
      set_error(error, error_len, "mapped executable section is unavailable");
      return false;
    }
    for (uint32_t offset = 0; offset < length; ++offset) {
      const uint32_t rva = start + offset;
      if (ignored[rva] != 0) {
        continue;
      }
      if (loaded[rva] != opened[rva]) {
        close_view();
        set_error(
            error,
            error_len,
            "opened executable bytes do not match the mapped main PE image");
        return false;
      }
      ++checked_bytes;
      if ((section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
        ++checked_executable_bytes;
      }
    }
  }
  close_view();
  if (checked_bytes == 0 || checked_executable_bytes == 0) {
    set_error(
        error,
        error_len,
        "mapped main PE image has no immutable executable comparison range");
    return false;
  }
  return true;
}

bool windows_main_executable_path(
    HMODULE module,
    std::vector<wchar_t>* output,
    char* error,
    size_t error_len) {
  output->resize(512);
  for (;;) {
    const DWORD length = GetModuleFileNameW(
        module, output->data(), static_cast<DWORD>(output->size()));
    if (length == 0) {
      set_error(error, error_len, "cannot identify the main executable path");
      return false;
    }
    if (length < output->size() - 1) {
      output->resize(length + 1);
      return true;
    }
    if (output->size() >= 32768) {
      set_error(error, error_len, "main executable path exceeds Windows limits");
      return false;
    }
    output->resize(output->size() * 2);
  }
}

intptr_t open_windows_pinned_self_image(
    const void* marker,
    char* error,
    size_t error_len) {
  HMODULE marker_owner = nullptr;
  const HMODULE main_module = GetModuleHandleW(nullptr);
  if (main_module == nullptr ||
      GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCWSTR>(marker),
          &marker_owner) == 0 ||
      marker_owner != main_module) {
    set_error(error, error_len, "self-image acquisition is not in the main executable");
    return -1;
  }
  std::vector<wchar_t> path;
  if (!windows_main_executable_path(
          main_module, &path, error, error_len)) {
    return -1;
  }
  HANDLE file = CreateFileW(
      path.data(),
      GENERIC_READ,
      FILE_SHARE_READ,
      nullptr,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
          FILE_FLAG_SEQUENTIAL_SCAN,
      nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    set_error(error, error_len, "cannot lock the mapped main executable file");
    return -1;
  }
  BY_HANDLE_FILE_INFORMATION information = {};
  if (GetFileType(file) != FILE_TYPE_DISK ||
      GetFileInformationByHandle(file, &information) == 0 ||
      (information.nFileSizeHigh == 0 && information.nFileSizeLow == 0) ||
      !windows_mapping_matches(file, main_module, error, error_len)) {
    CloseHandle(file);
    if (error != nullptr && error_len != 0 && error[0] == '\0') {
      set_error(error, error_len, "pinned executable is not a regular file");
    }
    return -1;
  }
  SetHandleInformation(file, HANDLE_FLAG_INHERIT, 0);
  return reinterpret_cast<intptr_t>(file);
}
#endif  // _WIN32

}  // namespace

extern "C" intptr_t ex_open_pinned_self_image(char* error, size_t error_len) {
  if (error != nullptr && error_len != 0) error[0] = '\0';
  try {
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
            fd, reinterpret_cast<const void*>(&ex_open_pinned_self_image),
            error, error_len)) {
      close(fd);
      return -1;
    }
    return fd;
#elif defined(__APPLE__)
    uint32_t path_size = 0;
    if (_NSGetExecutablePath(nullptr, &path_size) != -1 || path_size == 0) {
      set_error(error, error_len, "cannot size the main executable path");
      return -1;
    }
    std::vector<char> path(path_size);
    if (_NSGetExecutablePath(path.data(), &path_size) != 0) {
      set_error(error, error_len, "cannot identify the main executable path");
      return -1;
    }
    const int fd = open(path.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
    if (!apple_mapping_matches(
            fd,
            reinterpret_cast<const void*>(&ex_open_pinned_self_image),
            error,
            error_len)) {
      close(fd);
      return -1;
    }
    return fd;
#elif defined(_WIN32)
    return open_windows_pinned_self_image(
        reinterpret_cast<const void*>(&ex_open_pinned_self_image),
        error,
        error_len);
#else
    set_error(error, error_len,
              "pinned self-image acquisition is unsupported on this target");
    return -1;
#endif
  } catch (...) {
    set_error(
        error, error_len, "pinned self-image acquisition exhausted resources");
    return -1;
  }
}
