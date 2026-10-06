# Windows: Hermes's load-time `icuuc`/`icuin` forwarders resolve `icu.dll` by the standard search order

**Status:** Open
**Systems:** Engine, Build, Platform
**Severity:** P3
**Author:** Claude (Opus 5.5), from the lane I1 fix round (LLP 0057.000 §5.1.1)
**Date:** 2026-10-06

Every Windows `ibex2` binary, with or without `intl`, imports `icuuc.dll` and
`icuin.dll` at load time for the Hermes VM's basic-Unicode fallback. Since
Windows 10 1903 both DLLs are forwarders: each export is `icu.<name>`. The
loader resolves the forwarded `icu.dll` before `main` with the process's
standard DLL search order, which puts the application directory ahead of
System32. This is pre-existing Hermes behaviour. Lane I1 did not introduce it.

## Concrete scenario

An application that bundles its own `icu.dll` beside its executable, or an
attacker who can write to that directory, gets that `icu.dll` mapped into the
process at startup, and every call that goes through `icuuc`/`icuin` runs it.
That covers the Hermes VM's own Unicode calls and the 39 ICU entry points
the Intl shims link through `icuuc`/`icuin` (`uloc_*`, `udat_*`, `ucal_*`,
`ufieldpositer_*` and so on).

Observed on Windows 11 25H2 (ICU 72.1) by
`ibex2-runtime/tests/intl_windows_icu_binding.rs`
(`an_application_directory_icu_dll_does_not_capture_the_bound_pointers`).
The test copies itself and System32's `icu.dll` into a temp directory and runs
there. Before any probe, the module named `icu.dll` is
`…\Temp\ibex2-planted-icu-<pid>\icu.DLL`, the application-directory copy.

What Ibex already guarantees: the `icu.dll`-only entry points (the eight
`unumf_*` calls) are never imported. `intl_os` binds them through pointers
from System32's `icu.dll`, loaded by full path and checked with
`GetModuleFileNameW`. The same test checks that this still holds in the
planted directory. So a planted `icu.dll` cannot take the number formatter
alone, and no `unumf_*` call can fault on a missing export. It does not stop
the forwarded calls.

A consequence beyond hijacking: with a *different* (non-identical) ICU in the
application directory, one shim call can mix two ICU instances. The number
shim opens a `UFieldPositionIterator` through `icuin` (the planted copy) and
fills it with `unumf_resultGetAllFieldPositions` (System32). The test passes
only because its planted copy is byte-identical to System32's.

## Possible fixes (not attempted)

- **Refuse `INTL` on a mismatch.** This is cheap and Ibex-only. The probe
  resolves one `icuuc` and one `icuin` export through the process's own
  imports, then uses `GetModuleHandleExW(FROM_ADDRESS)` to check that both
  land in the System32 module it bound. If they do not, `INTL` is refused.
  That stops instance mixing and keeps Intl off a planted ICU. It does not
  protect Hermes's own Unicode calls.
- **Delay-load `icuuc`/`icuin` with a notify hook.** `/DELAYLOAD:icuuc.dll
  /DELAYLOAD:icuin.dll` plus a `__pfnDliNotifyHook2` that, on
  `dliNotePreLoadLibrary`, loads `GetSystemDirectoryW()\icuuc.dll` by full path.
  The forwarders inside a System32 `icuuc.dll` still resolve `icu.dll` by
  name, so the hook must also map System32's `icu.dll` by full path first.
  The by-name resolution then finds that already-loaded module. This changes
  every Windows binary's link (each final link needs the flags, as the
  retired `/DELAYLOAD:icu.dll` did) and needs a Hermes-wide test.
- **`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`** is impossible
  for load-time imports: they are resolved before any code in the executable
  runs. It only helps when combined with delay-loading.
- **Bind everything through pointers.** Hermes's own imports would also have
  to move, which means patching or wrapping the engine's ICU calls. That is
  out of proportion for a P3.

The first fix is the proportionate next step if this is taken up. The second
removes the residual for the engine as well.
