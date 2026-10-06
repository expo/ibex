//! Windows Intl uses the operating system's ICU (LLP 0057.000 §5.1.1). These
//! witnesses check the properties that make that safe to ship: the shims'
//! `icu.dll` is a delay-load import, no Windows 11-only ICU symbol is
//! imported (the number shim takes the field-position iterator path), the
//! probe admits only entry points it checked, and the observed OS ICU
//! versions are reported rather than pinned.
#![cfg(all(windows, feature = "intl"))]

use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};

#[test]
fn the_probe_reports_the_observed_os_icu() {
    let observed = ibex2::bindings::os_icu().expect("this Windows provides the OS ICU");
    assert_eq!(observed.dll, "icu.dll");
    let major: u32 = observed.icu.split('.').next().unwrap().parse().unwrap();
    // Windows 10 2004, the stated floor, ships ICU 64.
    assert!(
        major >= 64,
        "ICU {} is older than the floor's",
        observed.icu
    );
    for version in [&observed.icu, &observed.unicode, &observed.cldr] {
        assert!(
            version.split('.').count() >= 2 && version.split('.').all(|f| f.parse::<u8>().is_ok()),
            "{version}"
        );
    }
    let year = &observed.tzdata[..4];
    assert!(
        year.parse::<u32>().is_ok() && observed.tzdata[4..].chars().all(|c| c.is_ascii_lowercase()),
        "tzdata {}",
        observed.tzdata
    );

    // No digest is claimed for bytes that belong to Windows.
    assert_eq!(hermes_lean_sys::LINKED_OS_ICU, Some("icu.dll"));
    assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_ARCHIVE, None);
    assert_eq!(hermes_lean_sys::LINKED_ICU_DATA_DIGEST, None);
    assert_eq!(ibex2_runtime::LINKED_ICU_DATA_ARCHIVE, None);
    assert_eq!(ibex2_runtime::LINKED_ICU_DATA_DIGEST, None);
}

#[test]
fn the_intl_group_validates_and_installs_on_this_windows() {
    Groups::INTL
        .validate()
        .expect("INTL validates where the OS ICU is present");
    assert!(Groups::DEFAULT.contains(Groups::INTL));
    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    runtime
        .install_runtime(Groups::DEFAULT, &Context::new(GrantSet::none()))
        .expect("install DEFAULT with INTL");
    assert_eq!(
        runtime
            .eval(r#"typeof Intl + "|" + (1234.5).toLocaleString("de-DE")"#)
            .unwrap(),
        "object|1.234,5"
    );
}

#[test]
fn icu_dll_is_delay_loaded_and_only_windows_10_2004_symbols_are_imported() {
    let image = Image::read(&std::env::current_exe().unwrap());
    let is_icu = |dll: &str| {
        let dll = dll.to_ascii_lowercase();
        dll == "icu.dll" || dll == "icuuc.dll" || dll == "icuin.dll"
    };

    let eager = image.imports(Directory::Import);
    assert!(
        eager
            .iter()
            .all(|(dll, _)| !dll.eq_ignore_ascii_case("icu.dll")),
        "icu.dll must not be a load-time import"
    );
    let delayed = image.imports(Directory::DelayImport);
    let icu: Vec<&String> = delayed
        .iter()
        .filter(|(dll, _)| dll.eq_ignore_ascii_case("icu.dll"))
        .flat_map(|(_, names)| names)
        .collect();
    assert!(
        icu.iter()
            .any(|name| *name == "unumf_resultGetAllFieldPositions"),
        "the number shim takes the field-position iterator path: {icu:?}"
    );
    for name in &icu {
        assert!(
            ibex2::bindings::OS_ICU_ENTRY_POINTS.contains(&name.as_str()),
            "{name} is imported from icu.dll but not checked by the INTL probe"
        );
    }

    for (dll, names) in eager.iter().chain(&delayed).filter(|(dll, _)| is_icu(dll)) {
        for name in names {
            assert!(
                !ibex2::bindings::OS_ICU_WINDOWS_11_ONLY.contains(&name.as_str()),
                "{dll}!{name} exists only on Windows 11"
            );
        }
    }
}

#[derive(Clone, Copy)]
enum Directory {
    Import = 1,
    DelayImport = 13,
}

/// Just enough of a PE32+ reader to list named imports.
struct Image {
    bytes: Vec<u8>,
    /// (virtual address, virtual size, file offset) per section.
    sections: Vec<(u32, u32, u32)>,
    /// (RVA, size) per data directory.
    directories: Vec<(u32, u32)>,
}

impl Image {
    fn read(path: &std::path::Path) -> Self {
        let bytes = std::fs::read(path).expect("read the test executable");
        let pe = u32_at(&bytes, 0x3c) as usize;
        assert_eq!(&bytes[pe..pe + 4], b"PE\0\0");
        let sections = u16_at(&bytes, pe + 6) as usize;
        let optional_size = u16_at(&bytes, pe + 20) as usize;
        let optional = pe + 24;
        assert_eq!(u16_at(&bytes, optional), 0x20b, "PE32+");
        let directory_count = u32_at(&bytes, optional + 108) as usize;
        let directories = (0..directory_count)
            .map(|i| {
                let at = optional + 112 + i * 8;
                (u32_at(&bytes, at), u32_at(&bytes, at + 4))
            })
            .collect();
        let table = optional + optional_size;
        let sections = (0..sections)
            .map(|i| {
                let at = table + i * 40;
                let virtual_size = u32_at(&bytes, at + 8).max(u32_at(&bytes, at + 16));
                (
                    u32_at(&bytes, at + 12),
                    virtual_size,
                    u32_at(&bytes, at + 20),
                )
            })
            .collect();
        Self {
            bytes,
            sections,
            directories,
        }
    }

    fn offset(&self, rva: u32) -> usize {
        let (base, _, raw) = self
            .sections
            .iter()
            .copied()
            .find(|&(base, size, _)| rva >= base && rva < base + size)
            .unwrap_or_else(|| panic!("RVA {rva:#x} is in no section"));
        (rva - base + raw) as usize
    }

    fn name(&self, rva: u32) -> String {
        let start = self.offset(rva);
        let end = start + self.bytes[start..].iter().position(|&b| b == 0).unwrap();
        String::from_utf8_lossy(&self.bytes[start..end]).into_owned()
    }

    /// `(dll, named imports)` from the import or delay-import directory.
    fn imports(&self, directory: Directory) -> Vec<(String, Vec<String>)> {
        let Some(&(rva, _)) = self.directories.get(directory as usize) else {
            return Vec::new();
        };
        if rva == 0 {
            return Vec::new();
        }
        // IMAGE_IMPORT_DESCRIPTOR is 20 bytes (names at 0, DLL at 12, IAT at
        // 16); the delay-load descriptor is 32 bytes (DLL at 4, names at 16).
        let (size, dll_at, names_at, fallback_at) = match directory {
            Directory::Import => (20, 12, 0, 16),
            Directory::DelayImport => (32, 4, 16, 16),
        };
        let mut result = Vec::new();
        let mut at = self.offset(rva);
        loop {
            let dll = u32_at(&self.bytes, at + dll_at);
            if dll == 0 {
                break;
            }
            let mut thunk = match u32_at(&self.bytes, at + names_at) {
                0 => u32_at(&self.bytes, at + fallback_at),
                names => names,
            };
            let mut names = Vec::new();
            loop {
                let entry = u64_at(&self.bytes, self.offset(thunk));
                if entry == 0 {
                    break;
                }
                if entry & (1 << 63) == 0 {
                    // IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
                    names.push(self.name(entry as u32 + 2));
                }
                thunk += 8;
            }
            result.push((self.name(dll), names));
            at += size;
        }
        result
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
