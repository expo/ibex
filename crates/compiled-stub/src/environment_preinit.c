#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compiled_environment_allowlist.h"

#if defined(__APPLE__)
#include <crt_externs.h>
#endif

static char *ibex_empty_environment[] = {NULL};
static char **ibex_captured_environment = NULL;
static char **ibex_sanitized_environment = NULL;
static size_t ibex_captured_environment_count = 0;
static size_t ibex_scrubbed_environment_count = 0;
static size_t ibex_restored_environment_count = 0;
static int ibex_environment_capture_state = 0;
static int ibex_environment_constructor_probe_state = 0;
static int ibex_compiled_boot_mode_state = 0;

enum {
  IBEX_COMPILED_BOOT_AMBIENT = 1,
  IBEX_COMPILED_BOOT_CAPSEC = 2,
  IBEX_COMPILED_BOOT_INFORMATION = 3
};

static char ***ibex_environment_slot(void) {
#if defined(__APPLE__)
  return _NSGetEnviron();
#else
  extern char **environ;
  return &environ;
#endif
}

static int ibex_entry_has_name(const char *entry, const char *name) {
  size_t length = strlen(name);
  return strncmp(entry, name, length) == 0 && entry[length] == '=';
}

static int ibex_allowlist_index(const char *entry) {
  /* A variable bound keeps GCC's -Wtype-limits quiet when the generated
     allowlist is empty and the macro expands to a literal 0. */
  const size_t allowlist_count = IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT;
  size_t index;
  for (index = 0; index < allowlist_count; ++index) {
    if (ibex_entry_has_name(entry,
                            IBEX_COMPILED_ENVIRONMENT_ALLOWLIST[index])) {
      return (int)index;
    }
  }
  return -1;
}

static int ibex_select_boot_mode(int argc, char **argv) {
  if (argc < 1 || argv == NULL || argv[0] == NULL) {
    return -1;
  }
  if (argc > 1 && argv[1] != NULL &&
      strcmp(argv[1], "--ibex-capsec") == 0) {
    return IBEX_COMPILED_BOOT_CAPSEC;
  }
  if (argc > 1 && argv[1] != NULL && strcmp(argv[1], "--ibex-info") == 0) {
    return IBEX_COMPILED_BOOT_INFORMATION;
  }
  return IBEX_COMPILED_BOOT_AMBIENT;
}

// @ref LLP 0029#4-compiled-mode-authority — CapSec sanitizes before controlled
// constructors, including across a loader republish of the original envp.
static void ibex_install_empty_environment(char ***slot, char **source) {
  /* glibc may restore its original envp vector after .preinit_array and before
     .init_array. Clear that vector in place as well as publishing it through
     environ, so a later pointer restoration cannot resurrect inherited
     authority. The immutable snapshot, when available, owns deep copies. */
  if (source != NULL) {
    source[0] = NULL;
  }
  if (slot != NULL) {
    *slot = source == NULL ? ibex_empty_environment : source;
  }
}

static void ibex_capture_and_sanitize_environment(int argc, char **argv,
                                                  char **raw_envp) {
  char ***slot = ibex_environment_slot();
  /* Linux's preinit ABI gives us the loader's authoritative envp vector.
     `environ` can temporarily name a different vector and may be republished
     from envp before constructors, so sanitize envp itself when available. */
  char **source = raw_envp != NULL ? raw_envp : (slot == NULL ? NULL : *slot);
  size_t count = 0;
  size_t index;
  char **captured;
  char **sanitized;
  unsigned char restored[IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT > 0
                             ? IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT
                             : 1] = {0};

  if (ibex_environment_capture_state != 0) {
    ibex_environment_capture_state = -2;
    ibex_install_empty_environment(slot, source);
    return;
  }
  ibex_compiled_boot_mode_state = ibex_select_boot_mode(argc, argv);
  if (ibex_compiled_boot_mode_state < 0) {
    ibex_environment_capture_state = -3;
    ibex_install_empty_environment(slot, source);
    return;
  }
  while (source != NULL && source[count] != NULL) {
    ++count;
  }

  captured = (char **)calloc(count + 1, sizeof(char *));
  sanitized = (char **)calloc(
      (IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT > 0
           ? IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT
           : 0) +
          1,
      sizeof(char *));
  if (captured == NULL || sanitized == NULL) {
    free(captured);
    free(sanitized);
    ibex_environment_capture_state = -1;
    if (ibex_compiled_boot_mode_state == IBEX_COMPILED_BOOT_CAPSEC) {
      ibex_install_empty_environment(slot, source);
    }
    return;
  }

  for (index = 0; index < count; ++index) {
    size_t length = strlen(source[index]);
    int allowlist_index;
    captured[index] = (char *)malloc(length + 1);
    if (captured[index] == NULL) {
      ibex_environment_capture_state = -1;
      if (ibex_compiled_boot_mode_state == IBEX_COMPILED_BOOT_CAPSEC) {
        ibex_install_empty_environment(slot, source);
      }
      return;
    }
    memcpy(captured[index], source[index], length + 1);
    allowlist_index = ibex_allowlist_index(captured[index]);
    if (allowlist_index >= 0 && !restored[(size_t)allowlist_index]) {
      restored[(size_t)allowlist_index] = 1;
      sanitized[ibex_restored_environment_count++] = captured[index];
    }
  }
  captured[count] = NULL;
  sanitized[ibex_restored_environment_count] = NULL;
  ibex_captured_environment = captured;
  ibex_sanitized_environment = sanitized;
  ibex_captured_environment_count = count;
  if (ibex_compiled_boot_mode_state != IBEX_COMPILED_BOOT_CAPSEC) {
    ibex_restored_environment_count = count;
    ibex_scrubbed_environment_count = 0;
  } else {
    ibex_scrubbed_environment_count = count - ibex_restored_environment_count;
  }
  ibex_environment_capture_state = 1;
  if (slot != NULL) {
    if (ibex_compiled_boot_mode_state != IBEX_COMPILED_BOOT_CAPSEC) {
      *slot = source;
    } else if (source == NULL) {
      *slot = sanitized;
    } else {
      /* Keep the loader-owned vector sanitized even if glibc republishes its
         address after preinit. Point its retained entries at the immutable
         copies so later mutation of the original strings cannot change them. */
      for (index = 0; index < ibex_restored_environment_count; ++index) {
        source[index] = sanitized[index];
      }
      source[ibex_restored_environment_count] = NULL;
      *slot = source;
    }
  }
}

#if defined(__APPLE__)
__attribute__((constructor(101))) static void
ibex_environment_preinit_entry(void) {
  ibex_capture_and_sanitize_environment(*_NSGetArgc(), *_NSGetArgv(), NULL);
}
#else
static void ibex_environment_preinit_linux(int argc, char **argv, char **envp) {
  ibex_capture_and_sanitize_environment(argc, argv, envp);
}
typedef void (*ibex_preinit_function)(int, char **, char **);
__attribute__((section(".preinit_array"), used)) static ibex_preinit_function
    ibex_environment_preinit_entry = ibex_environment_preinit_linux;
#endif

__attribute__((constructor(102))) static void
ibex_environment_constructor_probe(void) {
  char ***slot = ibex_environment_slot();
  char **environment = slot == NULL ? NULL : *slot;
  size_t count = 0;
  if (ibex_environment_capture_state != 1) {
    ibex_environment_constructor_probe_state = -1;
    return;
  }
  if (ibex_compiled_boot_mode_state != IBEX_COMPILED_BOOT_CAPSEC) {
    /* glibc and foreign constructors may replace, resize, or reorder environ
       after .preinit_array. What Ibex promises here is narrower and exact: its
       non-CapSec branch did not install either of its scrubbed vectors. */
    ibex_environment_constructor_probe_state =
        environment != ibex_empty_environment &&
                environment != ibex_sanitized_environment
            ? 1
            : -4;
    return;
  }
  while (environment != NULL && environment[count] != NULL) {
    int index = ibex_allowlist_index(environment[count]);
    if (index < 0) {
      ibex_environment_constructor_probe_state = -2;
      return;
    }
    ++count;
  }
  ibex_environment_constructor_probe_state =
      count == ibex_restored_environment_count ? 1 : -3;
}

int ibex_compiled_environment_capture_state(void) {
  return ibex_environment_capture_state;
}

int ibex_compiled_environment_constructor_probe_state(void) {
  return ibex_environment_constructor_probe_state;
}

size_t ibex_compiled_environment_snapshot_count(void) {
  return ibex_captured_environment_count;
}

const char *ibex_compiled_environment_snapshot_entry(size_t index) {
  if (ibex_captured_environment == NULL ||
      index >= ibex_captured_environment_count) {
    return NULL;
  }
  return ibex_captured_environment[index];
}

size_t ibex_compiled_environment_scrubbed_count(void) {
  return ibex_scrubbed_environment_count;
}

size_t ibex_compiled_environment_restored_count(void) {
  return ibex_restored_environment_count;
}

int ibex_compiled_boot_mode(void) {
  return ibex_compiled_boot_mode_state;
}
