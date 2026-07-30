#pragma once

#include <cstddef>

namespace ibex::engine {

// Prove that `fd` supplies the exact Mach-O slice whose mapped executable
// bytes contain `factory_address`. The descriptor is owned by the caller and
// remains open for the complete comparison.
//
// This is an internal C++ seam so production and the standalone adversarial
// parser test exercise the same bounded implementation. The Rust/C ABI wrapper
// remains iOS-only and hidden.
#if defined(__GNUC__)
__attribute__((visibility("hidden")))
#endif
bool verify_mapped_macho_file(int fd, const void *mapped_header,
                              const void *factory_address, char *error,
                              size_t error_len);

} // namespace ibex::engine
