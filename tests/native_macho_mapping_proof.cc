#include "macho_mapping_proof.h"

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach/vm_prot.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr size_t kImageSize = 4096;
constexpr size_t kFactoryOffset = 512;

struct SyntheticImage {
  std::vector<uint8_t> bytes;
  size_t segment_offset = 0;
  size_t second_segment_offset = 0;
  size_t uuid_offset = 0;
  size_t encryption_offset = 0;
};

[[noreturn]] void fail(const std::string &message) {
  std::fprintf(stderr, "native_macho_mapping_proof: %s\n", message.c_str());
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition)
    fail(message);
}

void write_u32(std::vector<uint8_t> *bytes, size_t offset, uint32_t value,
               bool little) {
  require(offset <= bytes->size() && bytes->size() - offset >= 4,
          "u32 write overflow");
  for (size_t index = 0; index < 4; ++index) {
    const size_t source = little ? index : 3 - index;
    (*bytes)[offset + index] = static_cast<uint8_t>(value >> (source * 8));
  }
}

void write_u64(std::vector<uint8_t> *bytes, size_t offset, uint64_t value,
               bool little) {
  require(offset <= bytes->size() && bytes->size() - offset >= 8,
          "u64 write overflow");
  for (size_t index = 0; index < 8; ++index) {
    const size_t source = little ? index : 7 - index;
    (*bytes)[offset + index] = static_cast<uint8_t>(value >> (source * 8));
  }
}

SyntheticImage make_thin_image(cpu_type_t cpu_type, cpu_subtype_t cpu_subtype,
                               uint8_t seed, uint32_t cryptid = 0,
                               bool include_second_executable = false) {
  SyntheticImage image = {};
  image.bytes.resize(include_second_executable ? 2 * kImageSize : kImageSize);
  for (size_t index = 0; index < image.bytes.size(); ++index) {
    image.bytes[index] = static_cast<uint8_t>(seed + index * 17);
  }

  mach_header_64 header = {};
  header.magic = MH_MAGIC_64;
  header.cputype = cpu_type;
  header.cpusubtype = cpu_subtype;
  header.filetype = MH_DYLIB;
  header.ncmds = include_second_executable ? 4 : 3;
  header.sizeofcmds =
      (include_second_executable ? 2 : 1) * sizeof(segment_command_64) +
      sizeof(uuid_command) + sizeof(encryption_info_command_64);
  header.flags = MH_DYLDLINK | MH_TWOLEVEL;
  std::memcpy(image.bytes.data(), &header, sizeof(header));

  image.segment_offset = sizeof(header);
  segment_command_64 segment = {};
  segment.cmd = LC_SEGMENT_64;
  segment.cmdsize = sizeof(segment);
  std::memcpy(segment.segname, "__TEXT", 6);
  segment.vmaddr = 0;
  segment.vmsize = include_second_executable ? kImageSize : image.bytes.size();
  segment.fileoff = 0;
  segment.filesize =
      include_second_executable ? kImageSize : image.bytes.size();
  segment.maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
  segment.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
  std::memcpy(image.bytes.data() + image.segment_offset, &segment,
              sizeof(segment));

  size_t command_cursor = image.segment_offset + sizeof(segment);
  if (include_second_executable) {
    image.second_segment_offset = command_cursor;
    segment_command_64 second = {};
    second.cmd = LC_SEGMENT_64;
    second.cmdsize = sizeof(second);
    std::memcpy(second.segname, "__TEXT2", 7);
    second.vmaddr = kImageSize;
    second.vmsize = kImageSize;
    second.fileoff = kImageSize;
    second.filesize = kImageSize;
    second.maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
    second.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    std::memcpy(image.bytes.data() + image.second_segment_offset, &second,
                sizeof(second));
    command_cursor += sizeof(second);
  }

  image.uuid_offset = command_cursor;
  uuid_command uuid = {};
  uuid.cmd = LC_UUID;
  uuid.cmdsize = sizeof(uuid);
  for (size_t index = 0; index < sizeof(uuid.uuid); ++index) {
    uuid.uuid[index] = static_cast<uint8_t>(seed + index);
  }
  std::memcpy(image.bytes.data() + image.uuid_offset, &uuid, sizeof(uuid));

  image.encryption_offset = image.uuid_offset + sizeof(uuid);
  encryption_info_command_64 encryption = {};
  encryption.cmd = LC_ENCRYPTION_INFO_64;
  encryption.cmdsize = sizeof(encryption);
  encryption.cryptoff = kFactoryOffset;
  encryption.cryptsize = 256;
  encryption.cryptid = cryptid;
  std::memcpy(image.bytes.data() + image.encryption_offset, &encryption,
              sizeof(encryption));
  return image;
}

int pinned_file(const std::vector<uint8_t> &bytes, size_t retained_size = 0) {
  char path[] = "/tmp/ibex-macho-proof.XXXXXX";
  const int fd = mkstemp(path);
  if (fd < 0)
    fail("mkstemp failed");
  unlink(path);
  size_t written = 0;
  while (written < bytes.size()) {
    const ssize_t amount =
        pwrite(fd, bytes.data() + written, bytes.size() - written, written);
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount <= 0)
      fail("pwrite failed");
    written += static_cast<size_t>(amount);
  }
  if (retained_size != 0 && ftruncate(fd, retained_size) != 0) {
    fail("ftruncate failed");
  }
  return fd;
}

bool verify(const std::vector<uint8_t> &file, const SyntheticImage &mapped,
            std::string *error, size_t retained_size = 0,
            size_t factory_offset = kFactoryOffset) {
  const int fd = pinned_file(file, retained_size);
  char buffer[512] = {};
  const bool result = ibex::engine::verify_mapped_macho_file(
      fd, mapped.bytes.data(), mapped.bytes.data() + factory_offset, buffer,
      sizeof(buffer));
  close(fd);
  *error = buffer;
  return result;
}

void expect_failure(const std::vector<uint8_t> &file,
                    const SyntheticImage &mapped, const char *expected,
                    size_t retained_size = 0,
                    size_t factory_offset = kFactoryOffset) {
  std::string error;
  require(!verify(file, mapped, &error, retained_size, factory_offset),
          "hostile proof unexpectedly passed");
  require(error.find(expected) != std::string::npos,
          "unexpected error for hostile proof: " + error);
}

void write_fat_row(std::vector<uint8_t> *file, size_t row, bool fat64,
                   bool little, cpu_type_t cpu_type, cpu_subtype_t cpu_subtype,
                   uint64_t offset, uint64_t size) {
  write_u32(file, row, static_cast<uint32_t>(cpu_type), little);
  write_u32(file, row + 4, static_cast<uint32_t>(cpu_subtype), little);
  if (fat64) {
    write_u64(file, row + 8, offset, little);
    write_u64(file, row + 16, size, little);
    write_u32(file, row + 24, 12, little);
    write_u32(file, row + 28, 0, little);
  } else {
    write_u32(file, row + 8, static_cast<uint32_t>(offset), little);
    write_u32(file, row + 12, static_cast<uint32_t>(size), little);
    write_u32(file, row + 16, 12, little);
  }
}

std::vector<uint8_t> make_fat_file(const SyntheticImage &x86,
                                   const SyntheticImage &arm, bool fat64,
                                   bool little) {
  constexpr uint64_t x86_offset = 4096;
  constexpr uint64_t arm_offset = 8192;
  std::vector<uint8_t> file(arm_offset + arm.bytes.size(), 0);
  const uint32_t magic = fat64 ? (little ? 0xbfbafeca : 0xcafebabf)
                               : (little ? 0xbebafeca : 0xcafebabe);
  write_u32(&file, 0, magic, false);
  write_u32(&file, 4, 2, little);
  const size_t row_size = fat64 ? 32 : 20;
  write_fat_row(&file, 8, fat64, little, CPU_TYPE_X86_64,
                CPU_SUBTYPE_X86_64_ALL, x86_offset, x86.bytes.size());
  write_fat_row(&file, 8 + row_size, fat64, little, CPU_TYPE_ARM64,
                CPU_SUBTYPE_ARM64_ALL, arm_offset, arm.bytes.size());
  std::memcpy(file.data() + x86_offset, x86.bytes.data(), x86.bytes.size());
  std::memcpy(file.data() + arm_offset, arm.bytes.data(), arm.bytes.size());
  return file;
}

void verify_real_image(const char *pinned_path, const char *mapped_path) {
  const int pinned = open(pinned_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  require(pinned >= 0, "could not open real pinned Mach-O fixture");
  const int mapped_fd = open(mapped_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  require(mapped_fd >= 0, "could not open real mapped Mach-O fixture");
  struct stat status = {};
  require(fstat(mapped_fd, &status) == 0 && status.st_size > 0,
          "could not inspect real mapped Mach-O fixture");
  void *mapping = mmap(nullptr, static_cast<size_t>(status.st_size), PROT_READ,
                       MAP_PRIVATE, mapped_fd, 0);
  require(mapping != MAP_FAILED, "could not mmap real Mach-O fixture");
  require(static_cast<size_t>(status.st_size) > sizeof(mach_header_64),
          "real mapped Mach-O fixture is too short");

  char error[512] = {};
  const bool valid = ibex::engine::verify_mapped_macho_file(
      pinned, mapping,
      static_cast<const uint8_t *>(mapping) + sizeof(mach_header_64), error,
      sizeof(error));
  munmap(mapping, static_cast<size_t>(status.st_size));
  close(mapped_fd);
  close(pinned);
  require(valid, std::string("real Mach-O fixture failed: ") + error);
}

} // namespace

int main(int argc, char **argv) {
  require(argc % 2 == 1, "usage: native_macho_mapping_proof "
                         "[pinned-file mapped-thin-file]...");
  const SyntheticImage arm =
      make_thin_image(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x31);
  const SyntheticImage x86 =
      make_thin_image(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, 0x72);

  std::string error;
  require(verify(arm.bytes, arm, &error), "valid thin Mach-O failed: " + error);

  const std::vector<uint8_t> fat32 = make_fat_file(x86, arm, false, false);
  require(verify(fat32, arm, &error),
          "valid big-endian fat32 Mach-O failed: " + error);

  const std::vector<uint8_t> swapped_fat64 =
      make_fat_file(x86, arm, true, true);
  require(verify(swapped_fat64, arm, &error),
          "valid swapped fat64 Mach-O failed: " + error);

  const SyntheticImage two_executable_segments =
      make_thin_image(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x45, 0, true);
  require(
      verify(two_executable_segments.bytes, two_executable_segments, &error),
      "valid two-segment Mach-O failed: " + error);
  std::vector<uint8_t> mutated_non_factory_segment =
      two_executable_segments.bytes;
  mutated_non_factory_segment[kImageSize + 19] ^= 0x40;
  expect_failure(mutated_non_factory_segment, two_executable_segments,
                 "segment __TEXT2");

  SyntheticImage writable_non_factory_segment = two_executable_segments;
  segment_command_64 writable_second = {};
  std::memcpy(&writable_second,
              writable_non_factory_segment.bytes.data() +
                  writable_non_factory_segment.second_segment_offset,
              sizeof(writable_second));
  writable_second.maxprot |= VM_PROT_WRITE;
  std::memcpy(writable_non_factory_segment.bytes.data() +
                  writable_non_factory_segment.second_segment_offset,
              &writable_second, sizeof(writable_second));
  std::vector<uint8_t> mutated_writable_non_factory_segment =
      writable_non_factory_segment.bytes;
  mutated_writable_non_factory_segment[kImageSize + 19] ^= 0x20;
  expect_failure(mutated_writable_non_factory_segment,
                 writable_non_factory_segment,
                 "not declared read-only executable");

  std::vector<uint8_t> mutated = arm.bytes;
  mutated[kFactoryOffset + 19] ^= 0x80;
  expect_failure(mutated, arm, "executable bytes differ");

  std::vector<uint8_t> wrong_uuid = arm.bytes;
  wrong_uuid[arm.uuid_offset + offsetof(uuid_command, uuid) + 3] ^= 0x01;
  expect_failure(wrong_uuid, arm, "LC_UUID differs");

  std::vector<uint8_t> wrong_geometry = arm.bytes;
  segment_command_64 geometry = {};
  std::memcpy(&geometry, wrong_geometry.data() + arm.segment_offset,
              sizeof(geometry));
  geometry.filesize -= 1;
  std::memcpy(wrong_geometry.data() + arm.segment_offset, &geometry,
              sizeof(geometry));
  expect_failure(wrong_geometry, arm, "segment geometry differs");

  expect_failure(arm.bytes, arm, "segment range is invalid", 256);

  const SyntheticImage encrypted =
      make_thin_image(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, 0x31, 1);
  expect_failure(encrypted.bytes, encrypted, "encrypted Hermes Mach-O");

  SyntheticImage writable_executable = arm;
  segment_command_64 segment = {};
  std::memcpy(&segment, writable_executable.bytes.data() + arm.segment_offset,
              sizeof(segment));
  segment.maxprot |= VM_PROT_WRITE;
  segment.initprot |= VM_PROT_WRITE;
  std::memcpy(writable_executable.bytes.data() + arm.segment_offset, &segment,
              sizeof(segment));
  expect_failure(writable_executable.bytes, writable_executable,
                 "not declared read-only executable");

  SyntheticImage unreadable_executable = arm;
  std::memcpy(&segment, unreadable_executable.bytes.data() + arm.segment_offset,
              sizeof(segment));
  segment.maxprot &= ~VM_PROT_READ;
  segment.initprot &= ~VM_PROT_READ;
  std::memcpy(unreadable_executable.bytes.data() + arm.segment_offset, &segment,
              sizeof(segment));
  expect_failure(unreadable_executable.bytes, unreadable_executable,
                 "not declared read-only executable");

  SyntheticImage factory_in_zero_fill = arm;
  std::memcpy(&segment, factory_in_zero_fill.bytes.data() + arm.segment_offset,
              sizeof(segment));
  segment.filesize = kFactoryOffset;
  std::memcpy(factory_in_zero_fill.bytes.data() + arm.segment_offset, &segment,
              sizeof(segment));
  expect_failure(factory_in_zero_fill.bytes, factory_in_zero_fill,
                 "not in a file-backed");
  expect_failure(arm.bytes, arm, "outside compared executable bytes", 0,
                 arm.bytes.size());

  SyntheticImage duplicate_uuid = arm;
  load_command replacement_uuid = {};
  replacement_uuid.cmd = LC_UUID;
  replacement_uuid.cmdsize = sizeof(uuid_command);
  std::memcpy(duplicate_uuid.bytes.data() + arm.encryption_offset,
              &replacement_uuid, sizeof(replacement_uuid));
  expect_failure(duplicate_uuid.bytes, duplicate_uuid, "exactly one LC_UUID");

  std::vector<uint8_t> overlapping = fat32;
  write_u32(&overlapping, 8 + 20 + 8, 4096, false);
  expect_failure(overlapping, arm, "slices overlap");

  SyntheticImage excessive_commands = arm;
  mach_header_64 header = {};
  std::memcpy(&header, excessive_commands.bytes.data(), sizeof(header));
  header.ncmds = 4097;
  std::memcpy(excessive_commands.bytes.data(), &header, sizeof(header));
  expect_failure(excessive_commands.bytes, excessive_commands,
                 "load-command bounds are invalid");

  SyntheticImage unmatched = arm;
  std::memcpy(&header, unmatched.bytes.data(), sizeof(header));
  header.cpusubtype = CPU_SUBTYPE_ARM64E;
  std::memcpy(unmatched.bytes.data(), &header, sizeof(header));
  expect_failure(fat32, unmatched, "no exact mapped CPU slice");

  for (int index = 1; index < argc; index += 2) {
    verify_real_image(argv[index], argv[index + 1]);
  }

  std::puts("native_macho_mapping_proof: ok");
  return 0;
}
