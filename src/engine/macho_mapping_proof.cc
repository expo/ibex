// @ref LLP 0035#platform-mapping-requirements — iOS has no public mapped-vnode
// query equivalent to macOS libproc, so bind the exact pinned descriptor to
// the executing Hermes factory by comparing every file-backed r-x Mach-O
// segment against the live mapping. Pathname and UUID agreement are only
// structural selection checks, never the decisive identity proof.

#include "macho_mapping_proof.h"

#include <cstdio>

#if defined(__APPLE__)

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace ibex::engine {
namespace {

constexpr uint32_t kMaxFatSlices = 64;
constexpr uint32_t kMaxLoadCommands = 4096;
constexpr uint32_t kMaxLoadCommandBytes = 4 * 1024 * 1024;
constexpr uint64_t kMaxMachOFileBytes = 1024ULL * 1024ULL * 1024ULL;
constexpr uint64_t kMaxExecutableBytes = 512ULL * 1024ULL * 1024ULL;
constexpr size_t kCompareChunkBytes = 64 * 1024;

struct FileSlice {
  uint64_t offset = 0;
  uint64_t size = 0;
  cpu_type_t cpu_type = 0;
  cpu_subtype_t cpu_subtype = 0;
  bool from_fat = false;
};

struct ParsedSegment {
  segment_command_64 command = {};
};

void set_error(char *output, size_t output_len, const char *format, ...) {
  if (output == nullptr || output_len == 0)
    return;
  va_list arguments;
  va_start(arguments, format);
  std::vsnprintf(output, output_len, format, arguments);
  va_end(arguments);
  output[output_len - 1] = '\0';
}

bool add_u64(uint64_t left, uint64_t right, uint64_t *output) {
  if (left > std::numeric_limits<uint64_t>::max() - right)
    return false;
  *output = left + right;
  return true;
}

bool multiply_u64(uint64_t left, uint64_t right, uint64_t *output) {
  if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
    return false;
  }
  *output = left * right;
  return true;
}

bool ranges_overlap(uint64_t left_offset, uint64_t left_size,
                    uint64_t right_offset, uint64_t right_size) {
  uint64_t left_end = 0;
  uint64_t right_end = 0;
  return !add_u64(left_offset, left_size, &left_end) ||
         !add_u64(right_offset, right_size, &right_end) ||
         (left_offset < right_end && right_offset < left_end);
}

uint32_t read_u32(const uint8_t *bytes, bool little_endian) {
  if (little_endian) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
  }
  return (static_cast<uint32_t>(bytes[0]) << 24) |
         (static_cast<uint32_t>(bytes[1]) << 16) |
         (static_cast<uint32_t>(bytes[2]) << 8) |
         static_cast<uint32_t>(bytes[3]);
}

uint64_t read_u64(const uint8_t *bytes, bool little_endian) {
  if (little_endian) {
    return static_cast<uint64_t>(read_u32(bytes, true)) |
           (static_cast<uint64_t>(read_u32(bytes + 4, true)) << 32);
  }
  return (static_cast<uint64_t>(read_u32(bytes, false)) << 32) |
         static_cast<uint64_t>(read_u32(bytes + 4, false));
}

bool pread_exact(int fd, uint64_t offset, void *output, size_t output_len,
                 char *error, size_t error_len, const char *subject) {
  auto *cursor = static_cast<uint8_t *>(output);
  size_t remaining = output_len;
  while (remaining != 0) {
    const uint64_t completed = output_len - remaining;
    uint64_t current_offset = 0;
    if (!add_u64(offset, completed, &current_offset) ||
        current_offset >
            static_cast<uint64_t>(std::numeric_limits<off_t>::max())) {
      set_error(error, error_len, "%s offset overflows off_t", subject);
      return false;
    }
    const ssize_t amount =
        pread(fd, cursor, remaining, static_cast<off_t>(current_offset));
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount < 0) {
      set_error(error, error_len,
                "failed to read %s from pinned Hermes file: %s", subject,
                std::strerror(errno));
      return false;
    }
    if (amount == 0) {
      set_error(error, error_len, "pinned Hermes file is truncated in %s",
                subject);
      return false;
    }
    cursor += static_cast<size_t>(amount);
    remaining -= static_cast<size_t>(amount);
  }
  return true;
}

bool validate_slice_range(const FileSlice &slice, uint64_t file_size,
                          uint64_t minimum_offset, char *error,
                          size_t error_len) {
  uint64_t end = 0;
  if (slice.size < sizeof(mach_header_64) || slice.size > kMaxMachOFileBytes ||
      slice.offset < minimum_offset ||
      !add_u64(slice.offset, slice.size, &end) || end > file_size) {
    set_error(error, error_len, "fat Hermes slice has an invalid file range");
    return false;
  }
  return true;
}

bool select_file_slice(int fd, uint64_t file_size, cpu_type_t mapped_cpu_type,
                       cpu_subtype_t mapped_cpu_subtype, FileSlice *selected,
                       char *error, size_t error_len) {
  std::array<uint8_t, 8> prefix = {};
  if (!pread_exact(fd, 0, prefix.data(), prefix.size(), error, error_len,
                   "Mach-O prefix")) {
    return false;
  }

  const uint32_t magic_be = read_u32(prefix.data(), false);
  bool fat = true;
  bool fat_64 = false;
  bool little_endian = false;
  switch (magic_be) {
  case 0xcafebabe:
    break;
  case 0xcafebabf:
    fat_64 = true;
    break;
  case 0xbebafeca:
    little_endian = true;
    break;
  case 0xbfbafeca:
    fat_64 = true;
    little_endian = true;
    break;
  default:
    fat = false;
    break;
  }

  if (!fat) {
    mach_header_64 header = {};
    if (!pread_exact(fd, 0, &header, sizeof(header), error, error_len,
                     "thin Mach-O header")) {
      return false;
    }
    if (header.magic != MH_MAGIC_64) {
      set_error(error, error_len,
                "pinned Hermes file is not a native 64-bit Mach-O");
      return false;
    }
    if (file_size > kMaxMachOFileBytes) {
      set_error(error, error_len,
                "thin Hermes Mach-O exceeds the parser byte bound");
      return false;
    }
    *selected = {
        0, file_size, header.cputype, header.cpusubtype, false,
    };
    return true;
  }

  const uint32_t slice_count = read_u32(prefix.data() + 4, little_endian);
  if (slice_count == 0 || slice_count > kMaxFatSlices) {
    set_error(error, error_len, "fat Hermes Mach-O has an invalid slice count");
    return false;
  }
  const uint64_t row_size = fat_64 ? 32 : 20;
  uint64_t table_bytes = 0;
  uint64_t table_end = 0;
  if (!multiply_u64(slice_count, row_size, &table_bytes) ||
      !add_u64(8, table_bytes, &table_end) || table_end > file_size ||
      table_bytes > kMaxFatSlices * 32ULL) {
    set_error(error, error_len,
              "fat Hermes Mach-O table exceeds its parser bound");
    return false;
  }
  std::vector<uint8_t> table(static_cast<size_t>(table_bytes));
  if (!pread_exact(fd, 8, table.data(), table.size(), error, error_len,
                   "fat Mach-O slice table")) {
    return false;
  }

  std::vector<FileSlice> slices;
  slices.reserve(slice_count);
  for (uint32_t index = 0; index < slice_count; ++index) {
    const uint8_t *row = table.data() + index * row_size;
    FileSlice slice = {};
    slice.cpu_type = static_cast<cpu_type_t>(read_u32(row, little_endian));
    slice.cpu_subtype =
        static_cast<cpu_subtype_t>(read_u32(row + 4, little_endian));
    slice.offset = fat_64 ? read_u64(row + 8, little_endian)
                          : read_u32(row + 8, little_endian);
    slice.size = fat_64 ? read_u64(row + 16, little_endian)
                        : read_u32(row + 12, little_endian);
    const uint32_t alignment =
        read_u32(row + (fat_64 ? 24 : 16), little_endian);
    if (fat_64 && read_u32(row + 28, little_endian) != 0) {
      set_error(error, error_len,
                "fat64 Hermes slice has a nonzero reserved field");
      return false;
    }
    if (alignment > 30 ||
        (slice.offset & ((uint64_t{1} << alignment) - 1)) != 0) {
      set_error(error, error_len, "fat Hermes slice has invalid alignment");
      return false;
    }
    slice.from_fat = true;
    if (!validate_slice_range(slice, file_size, table_end, error, error_len)) {
      return false;
    }
    for (const FileSlice &prior : slices) {
      if (ranges_overlap(slice.offset, slice.size, prior.offset, prior.size)) {
        set_error(error, error_len, "fat Hermes Mach-O slices overlap");
        return false;
      }
    }
    slices.push_back(slice);
  }

  bool found = false;
  for (const FileSlice &slice : slices) {
    if (slice.cpu_type != mapped_cpu_type ||
        slice.cpu_subtype != mapped_cpu_subtype) {
      continue;
    }
    if (found) {
      set_error(error, error_len,
                "fat Hermes Mach-O has ambiguous native slices");
      return false;
    }
    *selected = slice;
    found = true;
  }
  if (!found) {
    set_error(error, error_len,
              "fat Hermes Mach-O has no exact mapped CPU slice");
    return false;
  }
  return true;
}

const char *
classify_load_command_difference(const std::vector<uint8_t> &file_commands,
                                 const std::vector<uint8_t> &mapped_commands,
                                 uint32_t command_count) {
  size_t file_cursor = 0;
  size_t mapped_cursor = 0;
  for (uint32_t index = 0; index < command_count; ++index) {
    if (file_commands.size() - file_cursor < sizeof(load_command) ||
        mapped_commands.size() - mapped_cursor < sizeof(load_command)) {
      return "pinned Hermes load-command geometry differs from mapped image";
    }
    load_command file_command = {};
    load_command mapped_command = {};
    std::memcpy(&file_command, file_commands.data() + file_cursor,
                sizeof(file_command));
    std::memcpy(&mapped_command, mapped_commands.data() + mapped_cursor,
                sizeof(mapped_command));
    const bool file_size_valid =
        file_command.cmdsize >= sizeof(load_command) &&
        file_command.cmdsize <= file_commands.size() - file_cursor;
    const bool mapped_size_valid =
        mapped_command.cmdsize >= sizeof(load_command) &&
        mapped_command.cmdsize <= mapped_commands.size() - mapped_cursor;
    if (!file_size_valid || !mapped_size_valid) {
      return "pinned Hermes load-command geometry differs from mapped image";
    }
    if (file_command.cmd != mapped_command.cmd ||
        file_command.cmdsize != mapped_command.cmdsize) {
      if (file_command.cmd == LC_UUID || mapped_command.cmd == LC_UUID) {
        return "pinned Hermes LC_UUID geometry differs from mapped image";
      }
      if (file_command.cmd == LC_SEGMENT_64 ||
          mapped_command.cmd == LC_SEGMENT_64) {
        return "pinned Hermes segment geometry differs from mapped image";
      }
      return "pinned Hermes load-command geometry differs from mapped image";
    }
    if (std::memcmp(file_commands.data() + file_cursor,
                    mapped_commands.data() + mapped_cursor,
                    file_command.cmdsize) != 0) {
      if (file_command.cmd == LC_UUID) {
        return "pinned Hermes LC_UUID differs from mapped image";
      }
      if (file_command.cmd == LC_SEGMENT_64) {
        return "pinned Hermes segment geometry differs from mapped image";
      }
      return "pinned Hermes load commands differ from mapped image";
    }
    file_cursor += file_command.cmdsize;
    mapped_cursor += mapped_command.cmdsize;
  }
  return "pinned Hermes load commands differ from mapped image";
}

bool parse_load_commands(const std::vector<uint8_t> &commands,
                         const mach_header_64 &header, const FileSlice &slice,
                         std::vector<ParsedSegment> *segments,
                         uint64_t *header_vmaddr, char *error,
                         size_t error_len) {
  size_t cursor = 0;
  uint32_t uuid_count = 0;
  uint32_t encryption_count = 0;
  uint32_t header_segment_count = 0;

  for (uint32_t index = 0; index < header.ncmds; ++index) {
    if (commands.size() - cursor < sizeof(load_command)) {
      set_error(error, error_len,
                "Hermes Mach-O load-command table is truncated");
      return false;
    }
    load_command command = {};
    std::memcpy(&command, commands.data() + cursor, sizeof(command));
    if (command.cmdsize < sizeof(load_command) || (command.cmdsize & 7U) != 0 ||
        command.cmdsize > commands.size() - cursor) {
      set_error(error, error_len,
                "Hermes Mach-O has an invalid load-command size");
      return false;
    }

    if (command.cmd == LC_SEGMENT_64) {
      if (command.cmdsize < sizeof(segment_command_64)) {
        set_error(error, error_len,
                  "Hermes Mach-O segment command is truncated");
        return false;
      }
      segment_command_64 segment = {};
      std::memcpy(&segment, commands.data() + cursor, sizeof(segment));
      uint64_t section_bytes = 0;
      uint64_t expected_size = 0;
      if (segment.nsects > 4096 ||
          !multiply_u64(segment.nsects, sizeof(section_64), &section_bytes) ||
          !add_u64(sizeof(segment_command_64), section_bytes, &expected_size) ||
          expected_size != segment.cmdsize) {
        set_error(error, error_len,
                  "Hermes Mach-O segment geometry is invalid");
        return false;
      }
      uint64_t file_end = 0;
      uint64_t vm_end = 0;
      if (segment.filesize > segment.vmsize ||
          !add_u64(segment.fileoff, segment.filesize, &file_end) ||
          file_end > slice.size ||
          !add_u64(segment.vmaddr, segment.vmsize, &vm_end)) {
        set_error(error, error_len, "Hermes Mach-O segment range is invalid");
        return false;
      }
      if (segment.fileoff == 0 &&
          segment.filesize >= sizeof(mach_header_64) + header.sizeofcmds) {
        ++header_segment_count;
        *header_vmaddr = segment.vmaddr;
      }
      for (const ParsedSegment &prior : *segments) {
        if (segment.filesize != 0 && prior.command.filesize != 0 &&
            ranges_overlap(segment.fileoff, segment.filesize,
                           prior.command.fileoff, prior.command.filesize)) {
          set_error(error, error_len,
                    "Hermes Mach-O segment file ranges overlap");
          return false;
        }
        if (segment.vmsize != 0 && prior.command.vmsize != 0 &&
            ranges_overlap(segment.vmaddr, segment.vmsize, prior.command.vmaddr,
                           prior.command.vmsize)) {
          set_error(error, error_len,
                    "Hermes Mach-O segment virtual ranges overlap");
          return false;
        }
      }
      segments->push_back({segment});
    } else if (command.cmd == LC_UUID) {
      if (command.cmdsize != sizeof(uuid_command)) {
        set_error(error, error_len,
                  "Hermes Mach-O UUID command has invalid geometry");
        return false;
      }
      ++uuid_count;
    } else if (command.cmd == LC_ENCRYPTION_INFO ||
               command.cmd == LC_ENCRYPTION_INFO_64) {
      uint32_t cryptoff = 0;
      uint32_t cryptsize = 0;
      uint32_t cryptid = 0;
      if (command.cmd == LC_ENCRYPTION_INFO) {
        if (command.cmdsize != sizeof(encryption_info_command)) {
          set_error(error, error_len,
                    "Hermes Mach-O encryption command has invalid geometry");
          return false;
        }
        encryption_info_command encryption = {};
        std::memcpy(&encryption, commands.data() + cursor, sizeof(encryption));
        cryptoff = encryption.cryptoff;
        cryptsize = encryption.cryptsize;
        cryptid = encryption.cryptid;
      } else {
        if (command.cmdsize != sizeof(encryption_info_command_64)) {
          set_error(error, error_len,
                    "Hermes Mach-O encryption64 command has invalid geometry");
          return false;
        }
        encryption_info_command_64 encryption = {};
        std::memcpy(&encryption, commands.data() + cursor, sizeof(encryption));
        cryptoff = encryption.cryptoff;
        cryptsize = encryption.cryptsize;
        cryptid = encryption.cryptid;
      }
      uint64_t crypt_end = 0;
      if (!add_u64(cryptoff, cryptsize, &crypt_end) || crypt_end > slice.size) {
        set_error(error, error_len,
                  "Hermes Mach-O encryption range is invalid");
        return false;
      }
      if (cryptid != 0) {
        set_error(error, error_len,
                  "encrypted Hermes Mach-O executable bytes cannot be compared "
                  "to the pinned file");
        return false;
      }
      ++encryption_count;
    }
    cursor += command.cmdsize;
  }

  if (cursor != commands.size()) {
    set_error(error, error_len,
              "Hermes Mach-O load commands do not fill sizeofcmds");
    return false;
  }
  if (segments->empty() || header_segment_count != 1) {
    set_error(error, error_len,
              "Hermes Mach-O has no unique mapped header segment");
    return false;
  }
  if (uuid_count != 1) {
    set_error(error, error_len, "Hermes Mach-O must carry exactly one LC_UUID");
    return false;
  }
  if (encryption_count > 1) {
    set_error(error, error_len,
              "Hermes Mach-O has ambiguous encryption commands");
    return false;
  }
  return true;
}

bool mapped_segment_start(uintptr_t mapped_base, uint64_t header_vmaddr,
                          uint64_t segment_vmaddr, uintptr_t *output) {
  if (segment_vmaddr >= header_vmaddr) {
    const uint64_t delta = segment_vmaddr - header_vmaddr;
    if (delta > std::numeric_limits<uintptr_t>::max() ||
        mapped_base > std::numeric_limits<uintptr_t>::max() -
                          static_cast<uintptr_t>(delta)) {
      return false;
    }
    *output = mapped_base + static_cast<uintptr_t>(delta);
    return true;
  }
  const uint64_t delta = header_vmaddr - segment_vmaddr;
  if (delta > mapped_base)
    return false;
  *output = mapped_base - static_cast<uintptr_t>(delta);
  return true;
}

bool compare_executable_segments(int fd, const FileSlice &slice,
                                 const std::vector<ParsedSegment> &segments,
                                 uint64_t header_vmaddr,
                                 const void *mapped_header,
                                 const void *factory_address, char *error,
                                 size_t error_len) {
  const uintptr_t mapped_base = reinterpret_cast<uintptr_t>(mapped_header);
  const uintptr_t factory = reinterpret_cast<uintptr_t>(factory_address);
  bool factory_in_file_backed_executable = false;
  uint32_t compared_segments = 0;
  uint64_t compared_bytes = 0;

  for (const ParsedSegment &parsed : segments) {
    const segment_command_64 &segment = parsed.command;
    uintptr_t segment_start = 0;
    if (!mapped_segment_start(mapped_base, header_vmaddr, segment.vmaddr,
                              &segment_start) ||
        segment.vmsize >
            std::numeric_limits<uintptr_t>::max() - segment_start) {
      set_error(error, error_len, "mapped Hermes segment address overflows");
      return false;
    }
    const uintptr_t segment_end =
        segment_start + static_cast<uintptr_t>(segment.vmsize);
    const bool executable = (segment.initprot & VM_PROT_EXECUTE) != 0;
    if (executable && ((segment.initprot & VM_PROT_READ) == 0 ||
                       (segment.initprot & VM_PROT_WRITE) != 0 ||
                       (segment.maxprot & VM_PROT_READ) == 0 ||
                       (segment.maxprot & VM_PROT_EXECUTE) == 0 ||
                       (segment.maxprot & VM_PROT_WRITE) != 0)) {
      // The proof relies on trusted dyld applying the Mach-O protections.
      // Reject every source-declared writable executable mapping, including
      // non-factory segments, rather than silently excluding mutable code
      // from the descriptor-to-mapping byte join.
      set_error(error, error_len,
                "Hermes executable segment is not declared read-only "
                "executable");
      return false;
    }
    if (factory >= segment_start && factory < segment_end) {
      const uint64_t factory_offset = factory - segment_start;
      if (!executable || factory_offset >= segment.filesize) {
        set_error(error, error_len,
                  "Hermes factory is not in a file-backed non-writable "
                  "executable segment");
        return false;
      }
      factory_in_file_backed_executable = true;
    }

    if (!executable || segment.filesize == 0) {
      continue;
    }
    if (segment.filesize > segment.vmsize ||
        !add_u64(compared_bytes, segment.filesize, &compared_bytes) ||
        compared_bytes > kMaxExecutableBytes) {
      set_error(error, error_len,
                "Hermes executable segment bytes exceed the proof bound");
      return false;
    }

    uint64_t file_offset = 0;
    if (!add_u64(slice.offset, segment.fileoff, &file_offset)) {
      set_error(error, error_len, "Hermes executable file offset overflows");
      return false;
    }
    std::array<uint8_t, kCompareChunkBytes> chunk = {};
    uint64_t completed = 0;
    while (completed < segment.filesize) {
      const size_t amount = static_cast<size_t>(
          std::min<uint64_t>(chunk.size(), segment.filesize - completed));
      uint64_t chunk_file_offset = 0;
      if (!add_u64(file_offset, completed, &chunk_file_offset) ||
          !pread_exact(fd, chunk_file_offset, chunk.data(), amount, error,
                       error_len, "executable Mach-O segment")) {
        return false;
      }
      if (completed > std::numeric_limits<uintptr_t>::max() - segment_start ||
          amount > std::numeric_limits<uintptr_t>::max() -
                       (segment_start + static_cast<uintptr_t>(completed))) {
        set_error(error, error_len,
                  "mapped Hermes comparison address overflows");
        return false;
      }
      const auto *mapped = reinterpret_cast<const uint8_t *>(
          segment_start + static_cast<uintptr_t>(completed));
      if (std::memcmp(chunk.data(), mapped, amount) != 0) {
        char segment_name[17] = {};
        std::memcpy(segment_name, segment.segname, 16);
        set_error(error, error_len,
                  "mapped Hermes executable bytes differ from pinned file "
                  "segment %.16s",
                  segment_name);
        return false;
      }
      completed += amount;
    }
    ++compared_segments;
  }

  if (compared_segments == 0) {
    set_error(error, error_len, "Hermes Mach-O has no file-backed r-x segment");
    return false;
  }
  if (!factory_in_file_backed_executable) {
    set_error(error, error_len,
              "Hermes factory is outside compared executable bytes");
    return false;
  }
  return true;
}

} // namespace

bool verify_mapped_macho_file(int fd, const void *mapped_header_pointer,
                              const void *factory_address, char *error,
                              size_t error_len) {
  if (error != nullptr && error_len != 0)
    error[0] = '\0';
  if (fd < 0 || mapped_header_pointer == nullptr ||
      factory_address == nullptr) {
    set_error(error, error_len, "invalid iOS Hermes mapped-file proof input");
    return false;
  }

  struct stat status = {};
  if (fstat(fd, &status) != 0) {
    set_error(error, error_len,
              "failed to inspect pinned Hermes descriptor: %s",
              std::strerror(errno));
    return false;
  }
  if (!S_ISREG(status.st_mode) || status.st_size <= 0 ||
      static_cast<uint64_t>(status.st_size) > kMaxMachOFileBytes) {
    set_error(error, error_len,
              "pinned Hermes descriptor is not a bounded regular file");
    return false;
  }

  mach_header_64 mapped_header = {};
  std::memcpy(&mapped_header, mapped_header_pointer, sizeof(mapped_header));
  if (mapped_header.magic != MH_MAGIC_64) {
    set_error(error, error_len,
              "mapped Hermes image is not a native 64-bit Mach-O");
    return false;
  }
  if (mapped_header.filetype != MH_DYLIB) {
    set_error(error, error_len, "mapped Hermes image is not MH_DYLIB");
    return false;
  }
  if (mapped_header.ncmds == 0 || mapped_header.ncmds > kMaxLoadCommands ||
      mapped_header.sizeofcmds < mapped_header.ncmds * sizeof(load_command) ||
      mapped_header.sizeofcmds > kMaxLoadCommandBytes) {
    set_error(error, error_len,
              "mapped Hermes load-command bounds are invalid");
    return false;
  }

  FileSlice slice = {};
  if (!select_file_slice(fd, static_cast<uint64_t>(status.st_size),
                         mapped_header.cputype, mapped_header.cpusubtype,
                         &slice, error, error_len)) {
    return false;
  }

  mach_header_64 file_header = {};
  if (!pread_exact(fd, slice.offset, &file_header, sizeof(file_header), error,
                   error_len, "selected Mach-O header")) {
    return false;
  }
  if (file_header.magic != mapped_header.magic ||
      file_header.cputype != mapped_header.cputype ||
      file_header.cpusubtype != mapped_header.cpusubtype ||
      file_header.filetype != mapped_header.filetype ||
      file_header.ncmds != mapped_header.ncmds ||
      file_header.sizeofcmds != mapped_header.sizeofcmds ||
      file_header.flags != mapped_header.flags ||
      file_header.reserved != mapped_header.reserved) {
    set_error(error, error_len,
              "pinned Hermes Mach-O header differs from mapped image");
    return false;
  }
  if (slice.from_fat && (slice.cpu_type != file_header.cputype ||
                         slice.cpu_subtype != file_header.cpusubtype)) {
    set_error(error, error_len,
              "fat Hermes slice metadata disagrees with its Mach-O header");
    return false;
  }

  uint64_t commands_offset = 0;
  uint64_t commands_end = 0;
  if (!add_u64(slice.offset, sizeof(mach_header_64), &commands_offset) ||
      !add_u64(sizeof(mach_header_64), file_header.sizeofcmds, &commands_end) ||
      commands_end > slice.size) {
    set_error(error, error_len,
              "Hermes load-command bytes exceed selected slice");
    return false;
  }
  std::vector<uint8_t> file_commands(file_header.sizeofcmds);
  if (!pread_exact(fd, commands_offset, file_commands.data(),
                   file_commands.size(), error, error_len,
                   "selected Mach-O load commands")) {
    return false;
  }
  const auto *mapped_commands =
      static_cast<const uint8_t *>(mapped_header_pointer) +
      sizeof(mach_header_64);
  std::vector<uint8_t> mapped_command_bytes(file_commands.size());
  std::memcpy(mapped_command_bytes.data(), mapped_commands,
              mapped_command_bytes.size());
  if (file_commands != mapped_command_bytes) {
    set_error(error, error_len, "%s",
              classify_load_command_difference(
                  file_commands, mapped_command_bytes, file_header.ncmds));
    return false;
  }

  std::vector<ParsedSegment> segments;
  uint64_t header_vmaddr = 0;
  if (!parse_load_commands(file_commands, file_header, slice, &segments,
                           &header_vmaddr, error, error_len)) {
    return false;
  }
  return compare_executable_segments(fd, slice, segments, header_vmaddr,
                                     mapped_header_pointer, factory_address,
                                     error, error_len);
}

} // namespace ibex::engine

#else

namespace ibex::engine {

bool verify_mapped_macho_file(int, const void *, const void *, char *error,
                              size_t error_len) {
  if (error != nullptr && error_len != 0) {
    std::snprintf(error, error_len, "%s",
                  "Mach-O mapped-file proof is unavailable on this target");
  }
  return false;
}

} // namespace ibex::engine

#endif
