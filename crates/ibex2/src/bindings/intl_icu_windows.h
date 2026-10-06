// The Windows include for Ibex's ICU shims: the SDK's single <icu.h>, which
// declares the same unversioned ICU C API backed by the operating system's
// icu.dll (no bundled ICU code or data).
//
// @ref LLP 0057.000#511-windows-intl-uses-the-os-icu — the stated floor is
// Windows 10 2004, so the shims see only the API that release exports.
//
// <icu.h> gates each declaration on the first Windows release that exported
// it (NTDDI_VERSION blocks). Pinning NTDDI_VERSION here, before any Windows
// header is read, makes a call to a newer entry point (for example the
// Windows 11 `unumf_resultAsValue`/`ufmtval_*`/`ucfpos_*`) a compile error in
// these files instead of a load-time import that would stop the process from
// starting on an older Windows. This header must be the first include of
// every shim translation unit; it overrides a global NTDDI_VERSION on purpose.
#pragma once

#if !defined(_WIN32)
#error "intl_icu_windows.h is the Windows-only ICU include"
#endif

#if defined(_SDKDDKVER_)
#error "include intl_icu_windows.h before any Windows SDK header"
#endif

#undef NTDDI_VERSION
#undef _WIN32_WINNT
#undef WINVER
// NTDDI_WIN10_VB (Windows 10 2004, build 19041): the first release whose
// icu.dll exports the `unumf_*` number formatter the shims use.
#define NTDDI_VERSION 0x0A000008
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

#include <sdkddkver.h>

static_assert(NTDDI_VERSION == NTDDI_WIN10_VB,
              "Ibex's Windows ICU shims are pinned to the Windows 10 2004 API");

#include <icu.h>
