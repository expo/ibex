//! Earliest-hook environment capture and the immutable compiled application
//! base snapshot.
//!
//! The C shim copies raw `environ` entries before constructors owned by this
//! image. Ambient boot leaves the inherited environment installed; CapSec boot
//! replaces it with the contract-generated allowlist. Both expose the immutable
//! copy here. Broker projection is first-wins and records names that cannot
//! enter CapSec's canonical environment vocabulary.
//! @ref LLP 0029#4-compiled-mode-authority

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, CStr};

use anyhow::{bail, Context, Result};
use capsec_semantics::model::EnvironmentName;

unsafe extern "C" {
    fn ibex_compiled_environment_capture_state() -> i32;
    fn ibex_compiled_environment_constructor_probe_state() -> i32;
    fn ibex_compiled_environment_snapshot_count() -> usize;
    fn ibex_compiled_environment_snapshot_entry(index: usize) -> *const c_char;
    fn ibex_compiled_environment_scrubbed_count() -> usize;
    fn ibex_compiled_environment_restored_count() -> usize;
    fn ibex_compiled_boot_mode() -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledBootMode {
    AmbientCompatibility,
    CapsecRequested,
    InformationRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedEnvironmentEntry {
    pub index: usize,
    pub raw_name: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledEnvironmentSnapshot {
    pub boot_mode: CompiledBootMode,
    pub raw_entries: Vec<Vec<u8>>,
    pub broker_base: BTreeMap<EnvironmentName, Vec<u8>>,
    pub duplicate_names: Vec<EnvironmentName>,
    pub rejected_entries: Vec<RejectedEnvironmentEntry>,
    pub scrubbed_count: usize,
    pub restored_count: usize,
}

impl CompiledEnvironmentSnapshot {
    pub fn broker_base(&self) -> Result<ibex_runtime::host::process::CompiledEnvironmentBase> {
        ibex_runtime::host::process::CompiledEnvironmentBase::new(
            self.broker_base
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        )
    }
}

pub fn captured_environment() -> Result<CompiledEnvironmentSnapshot> {
    // SAFETY: the pre-init object owns immutable process-lifetime allocations;
    // its query functions never mutate or free them.
    let capture_state = unsafe { ibex_compiled_environment_capture_state() };
    if capture_state != 1 {
        bail!("compiled environment pre-init capture failed with state {capture_state}");
    }
    let probe_state = unsafe { ibex_compiled_environment_constructor_probe_state() };
    if probe_state != 1 {
        bail!("compiled environment constructor-order probe failed with state {probe_state}");
    }
    let boot_mode = match unsafe { ibex_compiled_boot_mode() } {
        1 => CompiledBootMode::AmbientCompatibility,
        2 => CompiledBootMode::CapsecRequested,
        3 => CompiledBootMode::InformationRequested,
        state => bail!("compiled pre-init boot-mode selection failed with state {state}"),
    };
    let count = unsafe { ibex_compiled_environment_snapshot_count() };
    let mut raw_entries = Vec::with_capacity(count);
    for index in 0..count {
        let pointer = unsafe { ibex_compiled_environment_snapshot_entry(index) };
        if pointer.is_null() {
            bail!("compiled environment snapshot entry {index} is absent");
        }
        let entry = unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec();
        raw_entries.push(entry);
    }
    let scrubbed_count = unsafe { ibex_compiled_environment_scrubbed_count() };
    let restored_count = unsafe { ibex_compiled_environment_restored_count() };
    if scrubbed_count
        .checked_add(restored_count)
        .context("compiled environment count overflow")?
        != count
    {
        bail!("compiled environment scrub/restore counts do not cover the captured snapshot");
    }
    Ok(project_environment_entries(
        boot_mode,
        raw_entries,
        scrubbed_count,
        restored_count,
    ))
}

fn project_environment_entries(
    boot_mode: CompiledBootMode,
    raw_entries: Vec<Vec<u8>>,
    scrubbed_count: usize,
    restored_count: usize,
) -> CompiledEnvironmentSnapshot {
    let mut broker_base = BTreeMap::new();
    let mut duplicate_names = Vec::new();
    let mut duplicate_set = BTreeSet::new();
    let mut rejected_entries = Vec::new();
    for (index, entry) in raw_entries.iter().enumerate() {
        let Some(separator) = entry.iter().position(|byte| *byte == b'=') else {
            rejected_entries.push(RejectedEnvironmentEntry {
                index,
                raw_name: entry.clone(),
            });
            continue;
        };
        let raw_name = &entry[..separator];
        let Ok(name_text) = std::str::from_utf8(raw_name) else {
            rejected_entries.push(RejectedEnvironmentEntry {
                index,
                raw_name: raw_name.to_vec(),
            });
            continue;
        };
        let Ok(name) = EnvironmentName::new(name_text) else {
            rejected_entries.push(RejectedEnvironmentEntry {
                index,
                raw_name: raw_name.to_vec(),
            });
            continue;
        };
        if broker_base.contains_key(&name) {
            if duplicate_set.insert(name.clone()) {
                duplicate_names.push(name);
            }
            continue;
        }
        broker_base.insert(name, entry[separator + 1..].to_vec());
    }
    CompiledEnvironmentSnapshot {
        boot_mode,
        raw_entries,
        broker_base,
        duplicate_names,
        rejected_entries,
        scrubbed_count,
        restored_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_projection_is_first_wins_and_records_unrepresentable_names() {
        let snapshot = project_environment_entries(
            CompiledBootMode::CapsecRequested,
            vec![
                b"VALID_NAME=first".to_vec(),
                b"VALID_NAME=second".to_vec(),
                b"lowercase=rejected".to_vec(),
                vec![0xff, b'=', b'x'],
                b"NO_SEPARATOR".to_vec(),
            ],
            5,
            0,
        );
        assert_eq!(
            snapshot
                .broker_base
                .get(&EnvironmentName::new("VALID_NAME").unwrap()),
            Some(&b"first".to_vec())
        );
        assert_eq!(snapshot.duplicate_names.len(), 1);
        assert_eq!(snapshot.rejected_entries.len(), 3);
    }

    #[test]
    fn preinit_snapshot_and_constructor_probe_are_coherent() {
        let snapshot = captured_environment().unwrap();
        assert_eq!(
            snapshot.scrubbed_count + snapshot.restored_count,
            snapshot.raw_entries.len()
        );
        assert_eq!(snapshot.boot_mode, CompiledBootMode::AmbientCompatibility);
        assert_eq!(snapshot.scrubbed_count, 0);
        assert_eq!(snapshot.restored_count, snapshot.raw_entries.len());
    }
}
