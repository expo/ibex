//! Windows: the operating system's ICU behind Ibex's Intl shims.
//!
//! On Windows the shims call the OS `icu.dll`, which the final link loads
//! lazily (`/DELAYLOAD:icu.dll`). Before `INTL` may be installed, and before
//! any Intl host operation runs, [`available`] checks once that `icu.dll` is
//! present in System32 and exports every entry point the shims call. A
//! Windows without them (before 1903 there is no `icu.dll`; before 2004 it
//! lacks `unumf_*`) then refuses `INTL` with a clear error instead of failing
//! to start or faulting on the first `Intl` call.
//!
//! The ICU version, its CLDR data, and its tzdata belong to Windows and change
//! with Windows Update. [`os_icu`] reports what this process observes; it is a
//! diagnostic, never a pinned identity, and nothing here claims a digest.
//!
//! @ref LLP 0057.000#511-windows-intl-uses-the-os-icu — OS ICU, probe-gated INTL, observed versions

/// The OS ICU DLL that `hermes-lean-sys`'s `icu` feature imports on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const DLL: &str = "icu.dll";

/// Every ICU C entry point the Windows shims (`intl_icu.cc`,
/// `intl_case_icu.cc`, `intl_datetime_icu.cc`) call. A shim that calls a new
/// ICU function must add it here, or the probe would admit a Windows that
/// lacks it; `shim_sources_call_only_probed_entry_points` enforces this.
/// `intl_icu_windows.h` independently pins the declarations to Windows 10
/// 2004, so nothing newer than that release can appear.
#[cfg_attr(not(windows), allow(dead_code))]
pub const SHIM_ENTRY_POINTS: &[&str] = &[
    "u_strCaseCompare",
    "u_strFromUTF8",
    "u_strToLower",
    "u_strToUTF8",
    "u_strToUpper",
    "ucal_close",
    "ucal_getCanonicalTimeZoneID",
    "ucal_getDefaultTimeZone",
    "ucal_getKeywordValuesForLocale",
    "ucal_getType",
    "ucal_open",
    "ucal_openTimeZones",
    "ucurr_getDefaultFractionDigits",
    "udat_close",
    "udat_format",
    "udat_formatForFields",
    "udat_open",
    "udat_toPattern",
    "udatpg_close",
    "udatpg_getBestPattern",
    "udatpg_open",
    "uenum_close",
    "uenum_next",
    "uenum_unext",
    "ufieldpositer_close",
    "ufieldpositer_next",
    "ufieldpositer_open",
    "uloc_countAvailable",
    "uloc_forLanguageTag",
    "uloc_getAvailable",
    "uloc_getDefault",
    "uloc_getParent",
    "uloc_toLanguageTag",
    "uloc_toUnicodeLocaleType",
    "unumf_close",
    "unumf_closeResult",
    "unumf_formatDecimal",
    "unumf_formatDouble",
    "unumf_openForSkeletonAndLocale",
    "unumf_openResult",
    "unumf_resultGetAllFieldPositions",
    "unumf_resultToString",
    "unumsys_close",
    "unumsys_getName",
    "unumsys_isAlgorithmic",
    "unumsys_open",
    "unumsys_openByName",
];

/// The `UFormattedValue` field walk, exported by `icu.dll` only from Windows
/// 11. The Linux shim uses it; the Windows shim must not.
#[cfg_attr(not(windows), allow(dead_code))]
pub const WINDOWS_11_ONLY: &[&str] = &[
    "unumf_resultAsValue",
    "ufmtval_getString",
    "ufmtval_nextPosition",
    "ucfpos_open",
    "ucfpos_close",
    "ucfpos_constrainCategory",
    "ucfpos_getField",
    "ucfpos_getIndexes",
];

/// What this process observes of the operating system's ICU. Every field is
/// an unpinned fact about the machine running the process, not about the
/// build; the same binary reports different values after a Windows update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsIcu {
    /// The DLL the shims call (`icu.dll`).
    pub dll: &'static str,
    /// `u_getVersion`, for example `72.1.0.4`.
    pub icu: String,
    /// `u_getUnicodeVersion`, for example `15.1`.
    pub unicode: String,
    /// `ulocdata_getCLDRVersion`, for example `42.0`. Microsoft modifies the
    /// CLDR data it ships, so this names the base release only.
    pub cldr: String,
    /// `ucal_getTZDataVersion`, for example `2022g`.
    pub tzdata: String,
}

#[cfg(windows)]
mod os {
    use super::{OsIcu, DLL, SHIM_ENTRY_POINTS};
    use std::ffi::{c_char, c_int, CStr, CString};
    use std::sync::OnceLock;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    /// An `HMODULE` that is never freed: it pins System32's `icu.dll`, so
    /// the delay-load helper's later by-name load resolves to this module.
    #[derive(Clone, Copy)]
    struct Module(usize);

    fn module() -> Result<Module, &'static str> {
        static MODULE: OnceLock<Result<Module, String>> = OnceLock::new();
        MODULE
            .get_or_init(load)
            .as_ref()
            .copied()
            .map_err(String::as_str)
    }

    fn load() -> Result<Module, String> {
        let name: Vec<u16> = DLL.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives the
        // call; System32-only search keeps a planted application-directory
        // icu.dll out of the process.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(format!(
                "{DLL} is not present in System32 (Windows 10 version 1903 or later provides it)"
            ));
        }
        let module = Module(module as usize);
        for name in SHIM_ENTRY_POINTS {
            if symbol(module, name).is_none() {
                return Err(format!(
                    "{DLL} does not export {name} (Windows 10 version 2004 or later is required)"
                ));
            }
        }
        Ok(module)
    }

    fn symbol(module: Module, name: &str) -> Option<unsafe extern "system" fn() -> isize> {
        let name = CString::new(name).expect("ICU entry point names contain no NUL");
        // SAFETY: the module handle is live for the process (never freed) and
        // `name` is NUL-terminated.
        unsafe { GetProcAddress(module.0 as _, name.as_ptr().cast()) }
    }

    pub(crate) fn available() -> Result<(), &'static str> {
        module().map(|_| ())
    }

    /// What this process observes of the operating system's ICU, or why
    /// `INTL` is unavailable on this Windows.
    pub fn os_icu() -> Result<&'static OsIcu, &'static str> {
        static OBSERVED: OnceLock<Result<OsIcu, String>> = OnceLock::new();
        OBSERVED
            .get_or_init(|| observe(module().map_err(str::to_owned)?))
            .as_ref()
            .map_err(String::as_str)
    }

    type GetVersion = unsafe extern "C" fn(*mut u8);
    type GetCldrVersion = unsafe extern "C" fn(*mut u8, *mut c_int);
    type GetTzDataVersion = unsafe extern "C" fn(*mut c_int) -> *const c_char;

    fn observe(module: Module) -> Result<OsIcu, String> {
        let resolve = |name: &str| {
            symbol(module, name).ok_or_else(|| format!("{DLL} does not export {name}"))
        };
        // SAFETY: each pointer was resolved by name from icu.dll, and each
        // type matches the ICU C declaration in the Windows SDK's <icu.h>
        // (UVersionInfo is uint8_t[4]; UErrorCode is a C enum, i.e. int).
        unsafe {
            let get_version: GetVersion = std::mem::transmute(resolve("u_getVersion")?);
            let get_unicode: GetVersion = std::mem::transmute(resolve("u_getUnicodeVersion")?);
            let get_cldr: GetCldrVersion = std::mem::transmute(resolve("ulocdata_getCLDRVersion")?);
            let get_tzdata: GetTzDataVersion =
                std::mem::transmute(resolve("ucal_getTZDataVersion")?);

            let mut icu = [0u8; 4];
            get_version(icu.as_mut_ptr());
            let mut unicode = [0u8; 4];
            get_unicode(unicode.as_mut_ptr());
            let mut cldr = [0u8; 4];
            let mut status: c_int = 0;
            get_cldr(cldr.as_mut_ptr(), &mut status);
            if status > 0 {
                return Err(format!(
                    "ulocdata_getCLDRVersion failed with UErrorCode {status}"
                ));
            }
            let mut status: c_int = 0;
            let tzdata = get_tzdata(&mut status);
            if status > 0 || tzdata.is_null() {
                return Err(format!(
                    "ucal_getTZDataVersion failed with UErrorCode {status}"
                ));
            }
            Ok(OsIcu {
                dll: DLL,
                icu: super::version_string(icu),
                unicode: super::version_string(unicode),
                cldr: super::version_string(cldr),
                tzdata: CStr::from_ptr(tzdata).to_string_lossy().into_owned(),
            })
        }
    }
}

#[cfg(windows)]
pub(crate) use os::available;
#[cfg(windows)]
pub use os::os_icu;

/// `u_versionToString`'s format: dotted fields, trailing zero fields omitted,
/// but never fewer than two.
#[cfg_attr(not(windows), allow(dead_code))]
fn version_string(version: [u8; 4]) -> String {
    let mut fields = 4;
    while fields > 2 && version[fields - 1] == 0 {
        fields -= 1;
    }
    version[..fields]
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// The C++ installer's half of the INTL check: `validate_groups` refuses the
/// group exactly when [`crate::bindings::Groups::validate`] does.
#[cfg(windows)]
#[no_mangle]
pub extern "C" fn ibex2_intl_os_icu_available() -> std::ffi::c_int {
    std::ffi::c_int::from(available().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[cfg(windows)]
    #[test]
    fn this_windows_provides_the_probed_os_icu() {
        available().expect("this Windows exports every probed icu.dll entry point");
        let observed = os_icu().expect("observed OS ICU versions");
        assert_eq!(observed.dll, "icu.dll");
        assert!(!observed.icu.is_empty() && !observed.cldr.is_empty());
    }

    #[test]
    fn versions_format_like_icu() {
        assert_eq!(version_string([72, 1, 0, 4]), "72.1.0.4");
        assert_eq!(version_string([42, 0, 0, 0]), "42.0");
        assert_eq!(version_string([15, 1, 0, 0]), "15.1");
        assert_eq!(version_string([74, 2, 1, 0]), "74.2.1");
    }

    /// Every ICU call in the shim sources is probed on Windows, except the
    /// Windows 11 field walk, which only the Linux branch may use.
    #[test]
    fn shim_sources_call_only_probed_entry_points() {
        const ICU_PREFIXES: &[&str] = &[
            "u",
            "ucal",
            "ucfpos",
            "ucol",
            "ucurr",
            "udat",
            "udatpg",
            "uenum",
            "ufieldpositer",
            "ufmtval",
            "uloc",
            "ulocdata",
            "unorm2",
            "unum",
            "unumf",
            "unumsys",
            "uplrules",
        ];
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings/");
        let mut called = BTreeSet::new();
        for file in ["intl_icu.cc", "intl_case_icu.cc", "intl_datetime_icu.cc"] {
            let source = std::fs::read_to_string(format!("{root}{file}")).unwrap();
            for token in source.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                // An ICU C function: a known prefix, `_`, then a lower-case
                // letter (`ULOC_*` constants and `U*` types do not match).
                let Some((prefix, rest)) = token.split_once('_') else {
                    continue;
                };
                if ICU_PREFIXES.contains(&prefix)
                    && rest.starts_with(|c: char| c.is_ascii_lowercase())
                {
                    called.insert(token.to_owned());
                }
            }
        }
        let probed: BTreeSet<_> = SHIM_ENTRY_POINTS.iter().map(|s| s.to_string()).collect();
        let windows_11: BTreeSet<_> = WINDOWS_11_ONLY.iter().map(|s| s.to_string()).collect();
        assert!(probed.is_disjoint(&windows_11));
        let unprobed: Vec<_> = called
            .difference(&probed)
            .filter(|name| !windows_11.contains(*name))
            .collect();
        assert!(
            unprobed.is_empty(),
            "shims call ICU entry points the Windows probe does not check: {unprobed:?}"
        );
        let stale: Vec<_> = probed.difference(&called).collect();
        assert!(
            stale.is_empty(),
            "probe checks entry points no shim calls: {stale:?}"
        );
    }
}
