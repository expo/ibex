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
static size_t ibex_captured_environment_count = 0;
static size_t ibex_scrubbed_environment_count = 0;
static size_t ibex_restored_environment_count = 0;
static int ibex_environment_capture_state = 0;
static int ibex_environment_constructor_probe_state = 0;

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

static void ibex_capture_and_sanitize_environment(void) {
  char ***slot = ibex_environment_slot();
  char **source = slot == NULL ? NULL : *slot;
  size_t count = 0;
  size_t index;
  char **captured;
  char **sanitized;
  unsigned char restored[IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT > 0
                             ? IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT
                             : 1] = {0};

  if (ibex_environment_capture_state != 0) {
    ibex_environment_capture_state = -2;
    if (slot != NULL) {
      *slot = ibex_empty_environment;
    }
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
    if (slot != NULL) {
      *slot = ibex_empty_environment;
    }
    return;
  }

  for (index = 0; index < count; ++index) {
    size_t length = strlen(source[index]);
    int allowlist_index;
    captured[index] = (char *)malloc(length + 1);
    if (captured[index] == NULL) {
      ibex_environment_capture_state = -1;
      if (slot != NULL) {
        *slot = ibex_empty_environment;
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
  ibex_captured_environment_count = count;
  ibex_scrubbed_environment_count = count - ibex_restored_environment_count;
  ibex_environment_capture_state = 1;
  if (slot != NULL) {
    *slot = sanitized;
  }
}

#if defined(__APPLE__)
__attribute__((constructor(101))) static void
ibex_environment_preinit_entry(void) {
  ibex_capture_and_sanitize_environment();
}
#else
typedef void (*ibex_preinit_function)(void);
__attribute__((section(".preinit_array"), used)) static ibex_preinit_function
    ibex_environment_preinit_entry = ibex_capture_and_sanitize_environment;
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
