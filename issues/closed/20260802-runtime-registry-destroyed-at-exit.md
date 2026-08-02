# Drive-guard unwind aborts when process exit destroys the runtime registry

**Status:** Closed
**Resolution:** The registry mutex, the active-runtime map, and the host-call
target table are now immortal (intentionally leaked), so a drive unwinding
after `exit()` locks a mutex that still exists. LLP 0002's runtime-driving
thread contract records the exit-safety clause in the same commit.
**Systems:** Host Embedding, Engine
**Author:** Daehyeon Mun
**Date:** 2026-08-02
**Related:** LLP 0002 §Runtime-driving thread contract

`ExactAppMac` died with SIGABRT on `com.exact.runtime` at the end of an XCTest
run. The crash report tells the whole story:

- Thread 0 (main) is in `_XCTestMain` → `exit()` → `__cxa_finalize_ranges`,
  i.e. running static destructors (it happened to be inside RiveRuntime's
  `rive::DataEnum::~DataEnum()` — an innocent bystander that marks where
  finalization had got to).
- Thread 7 (`com.exact.runtime`) is still inside `ex_hermes_eval`, unwinding
  `ExactRuntimeDriveGuard::~ExactRuntimeDriveGuard()` →
  `std::terminate()` → `abort()`.

`g_runtimeRegistryMutex` and `g_activeRuntimes` were ordinary namespace-scope
globals in `hermes_runtime.cc`, so `exit()` destroyed them while the dedicated
runtime thread was mid-drive. The guard's destructor then did
`std::lock_guard<std::mutex> lock(g_runtimeRegistryMutex)` on a destroyed
mutex; on libc++ that throws `std::system_error`, the exception escapes the
implicitly-`noexcept` destructor, and the process terminates. Nothing about
the drive itself was wrong — the registry simply had a shorter lifetime than
the threads that use it.

`g_hostCallTargetMutex` and `g_hostCallTargets` had the identical exposure on
the any-thread host-call completion path and were fixed in the same way.
`ex_host_restore_context` and the other teardown steps in the destructor are
Rust `extern "C"` or trivially-destructible state, so they were never at risk.

Not fixed by hardening the destructor with try/catch: locking a destroyed
mutex is undefined behaviour, not a recoverable error — the throw is a
courtesy of one implementation. The leak is the correct shape: a
process-lifetime registry must have process lifetime.
