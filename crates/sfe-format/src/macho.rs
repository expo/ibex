//! Minimal fail-closed Mach-O 64-bit envelope segment injection.
//!
//! The implementation intentionally supports only thin little-endian 64-bit
//! executables with header slack. It never rewrites existing section offsets.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — macOS payloads live in a named segment and remain discoverable after code signing appends its signature

use super::app_bound::{FOOTER_MAGIC_V3, FORMAT_VERSION_V3};
use super::{Error, Result, FOOTER_LEN_V1, FOOTER_MAGIC_V2, FORMAT_VERSION_V2};

const MACH_HEADER_64_LEN: usize = 32;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_EXECUTE: u32 = 2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE: [u8; 4] = [0xfa, 0xde, 0x0c, 0xc0];
const SEGMENT_COMMAND_64_LEN: usize = 72;
const SECTION_64_LEN: usize = 80;
const IBEX_COMMAND_LEN: usize = SEGMENT_COMMAND_64_LEN + SECTION_64_LEN;
const MACHO_PAGE_ALIGNMENT: usize = 16 * 1024;

#[derive(Clone, Copy, Debug)]
struct MachHeaderFacts {
    ncmds: u32,
    sizeofcmds: u32,
    commands_end: usize,
    first_section_offset: usize,
    linkedit: LinkeditFacts,
    code_signature: Option<(usize, usize)>,
    ibex_payload: Option<(usize, usize)>,
}

#[derive(Clone, Copy, Debug)]
struct LinkeditFacts {
    command_offset: usize,
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
}

/// Return the footer offset inside `__IBEX,__payload`, if this is a supported
/// Mach-O carrying such a section. Non-Mach-O files return `None`; malformed
/// Mach-O files fail rather than falling back to an EOF trailer.
pub(crate) fn embedded_footer_offset(file: &[u8]) -> Result<Option<usize>> {
    if file.get(..4) != Some(&MH_MAGIC_64.to_le_bytes()) {
        return Ok(None);
    }
    let facts = parse(file)?;
    let Some((offset, size)) = facts.ibex_payload else {
        return Ok(None);
    };
    let end = offset.checked_add(size).ok_or(Error::EnvelopeRange)?;
    if end > file.len() || size < FOOTER_LEN_V1 {
        return Err(Error::EnvelopeRange);
    }
    Ok(Some(end - FOOTER_LEN_V1))
}

/// Validate the post-signing layout relied on by compiled-stub boot. This is
/// structural validation in addition to the platform loader's cryptographic
/// signature enforcement: the one signature blob and `__LINKEDIT` terminate
/// the file, and the signature starts after the injected envelope.
pub fn validate_signed_envelope_layout_v1(file: &[u8]) -> Result<()> {
    if file.get(..4) != Some(&MH_MAGIC_64.to_le_bytes()) {
        return Err(Error::Contract(
            "signed Mach-O validation requires Mach-O bytes".into(),
        ));
    }
    let facts = parse(file)?;
    let (payload_offset, payload_size) = facts
        .ibex_payload
        .ok_or_else(|| Error::Contract("signed Mach-O has no __IBEX payload".into()))?;
    let payload_end = payload_offset
        .checked_add(payload_size)
        .ok_or(Error::EnvelopeRange)?;
    let (signature_offset, signature_size) = facts
        .code_signature
        .ok_or_else(|| Error::Contract("signed Mach-O has no LC_CODE_SIGNATURE".into()))?;
    let signature_end = signature_offset
        .checked_add(signature_size)
        .ok_or(Error::EnvelopeRange)?;
    let linkedit_end = usize::try_from(facts.linkedit.fileoff)
        .ok()
        .and_then(|offset| {
            usize::try_from(facts.linkedit.filesize)
                .ok()
                .and_then(|size| offset.checked_add(size))
        });
    if signature_size == 0
        || signature_offset < payload_end
        || signature_end != file.len()
        || linkedit_end != Some(file.len())
        || usize::try_from(facts.linkedit.fileoff)
            .ok()
            .is_none_or(|offset| offset < payload_end)
        || file.get(signature_offset..signature_offset + 4) != Some(&CSMAGIC_EMBEDDED_SIGNATURE)
    {
        return Err(Error::Contract(
            "LC_CODE_SIGNATURE or __LINKEDIT does not seal the __IBEX payload".into(),
        ));
    }
    Ok(())
}

/// Return the catalog stub's original `__LINKEDIT` virtual size. Apple's
/// signer rewrites this value to fit the new signature, and signature removal
/// does not restore it, so release provenance carries the catalog value for
/// inspection-time reconstruction.
pub fn linkedit_vmsize_v1(unsigned_stub: &[u8]) -> Result<u64> {
    let facts = parse(unsigned_stub)?;
    if facts.code_signature.is_some() || facts.ibex_payload.is_some() {
        return Err(Error::Contract(
            "stub-core reconstruction facts require an uninjected signature-stripped Mach-O".into(),
        ));
    }
    Ok(read_u64(unsigned_stub, facts.linkedit.command_offset + 32)?)
}

/// Project the catalog's signature-stripped stub bytes back out of an injected
/// Mach-O. This is the inverse of `inject_envelope_segment_v1` for the portion
/// sealed by the catalog instance digest. It deliberately ignores the
/// replaceable platform-signature tail.
/// @ref LLP 0029#2-executable-layout-stub-envelope-footer — the inspector rehashes the actual stub-core projection
pub fn reconstruct_stub_core_v1(
    file: &[u8],
    original_size: u64,
    original_linkedit_vmsize: u64,
) -> Result<Vec<u8>> {
    let facts = parse(file)?;
    let (payload_offset, payload_size) = facts
        .ibex_payload
        .ok_or_else(|| Error::Contract("Mach-O has no __IBEX payload to remove".into()))?;
    let insertion_size =
        align_up(payload_size, MACHO_PAGE_ALIGNMENT).ok_or(Error::EnvelopeRange)?;
    let current_linkedit_offset =
        usize::try_from(facts.linkedit.fileoff).map_err(|_| Error::EnvelopeRange)?;
    if payload_offset
        .checked_add(insertion_size)
        .is_none_or(|expected| expected != current_linkedit_offset)
    {
        return Err(Error::Contract(
            "Mach-O __IBEX allocation does not immediately precede __LINKEDIT".into(),
        ));
    }
    let original_size = usize::try_from(original_size).map_err(|_| Error::EnvelopeRange)?;
    let original_linkedit_size = original_size
        .checked_sub(payload_offset)
        .ok_or_else(|| Error::Contract("stub-core size precedes its __LINKEDIT offset".into()))?;
    let current_linkedit_end = current_linkedit_offset
        .checked_add(original_linkedit_size)
        .ok_or(Error::EnvelopeRange)?;
    if current_linkedit_end > file.len()
        || facts
            .code_signature
            .is_some_and(|(offset, _)| current_linkedit_end > offset)
    {
        return Err(Error::Contract(
            "completed Mach-O does not retain the catalog stub's complete __LINKEDIT bytes".into(),
        ));
    }

    let mut commands = Vec::with_capacity(facts.sizeofcmds as usize);
    let mut cursor = MACH_HEADER_64_LEN;
    let mut removed_payload = 0usize;
    let mut removed_signature = 0usize;
    for _ in 0..facts.ncmds {
        let cmd = read_u32(file, cursor)?;
        let cmdsize = read_u32(file, cursor + 4)? as usize;
        let is_payload = cmd == LC_SEGMENT_64 && fixed_name(file, cursor + 8)? == "__IBEX";
        if is_payload {
            removed_payload += 1;
        } else if cmd == LC_CODE_SIGNATURE {
            removed_signature += 1;
        } else {
            commands.extend_from_slice(
                file.get(cursor..cursor + cmdsize)
                    .ok_or(Error::EnvelopeRange)?,
            );
        }
        cursor = cursor.checked_add(cmdsize).ok_or(Error::EnvelopeRange)?;
    }
    if cursor != facts.commands_end
        || removed_payload != 1
        || removed_signature != usize::from(facts.code_signature.is_some())
    {
        return Err(Error::Contract(
            "Mach-O command table cannot be projected to one unsigned stub".into(),
        ));
    }
    let original_ncmds = facts
        .ncmds
        .checked_sub(u32::try_from(removed_payload + removed_signature).unwrap())
        .ok_or(Error::EnvelopeRange)?;
    let original_sizeofcmds = u32::try_from(commands.len()).map_err(|_| Error::EnvelopeRange)?;
    let commands_end = MACH_HEADER_64_LEN
        .checked_add(commands.len())
        .ok_or(Error::EnvelopeRange)?;
    if commands_end > facts.first_section_offset || original_size < payload_offset {
        return Err(Error::EnvelopeRange);
    }

    let mut output = Vec::with_capacity(original_size);
    output.extend_from_slice(file.get(..payload_offset).ok_or(Error::EnvelopeRange)?);
    output.extend_from_slice(
        file.get(current_linkedit_offset..current_linkedit_end)
            .ok_or(Error::EnvelopeRange)?,
    );
    if output.len() != original_size {
        return Err(Error::EnvelopeRange);
    }
    output[MACH_HEADER_64_LEN..facts.commands_end].fill(0);
    output[MACH_HEADER_64_LEN..commands_end].copy_from_slice(&commands);
    write_u32(&mut output, 16, original_ncmds);
    write_u32(&mut output, 20, original_sizeofcmds);
    reverse_linkedit_layout(
        &mut output,
        current_linkedit_offset as u64,
        insertion_size as u64,
        original_linkedit_vmsize,
        original_linkedit_size as u64,
    )?;

    let reconstructed = parse(&output)?;
    if reconstructed.code_signature.is_some()
        || reconstructed.ibex_payload.is_some()
        || usize::try_from(reconstructed.linkedit.fileoff)
            .ok()
            .and_then(|offset| {
                usize::try_from(reconstructed.linkedit.filesize)
                    .ok()
                    .and_then(|size| offset.checked_add(size))
            })
            != Some(output.len())
    {
        return Err(Error::Contract(
            "reconstructed Mach-O is not a terminal signature-stripped stub".into(),
        ));
    }
    Ok(output)
}

/// Insert a standalone envelope (built with an empty stub) as the
/// `__IBEX,__payload` section of an unsigned thin Mach-O. The envelope footer's
/// absolute start is relocated without changing its envelope digest.
pub fn inject_envelope_segment_v1(
    unsigned_stub: &[u8],
    standalone_envelope: &[u8],
) -> Result<Vec<u8>> {
    let facts = parse(unsigned_stub)?;
    if facts.code_signature.is_some() {
        return Err(Error::Contract(
            "Mach-O stub still carries LC_CODE_SIGNATURE; strip it before injection".into(),
        ));
    }
    if facts.ibex_payload.is_some() {
        return Err(Error::Contract(
            "Mach-O stub already contains an __IBEX payload section".into(),
        ));
    }
    if facts
        .commands_end
        .checked_add(IBEX_COMMAND_LEN)
        .is_none_or(|end| end > facts.first_section_offset)
    {
        return Err(Error::Contract(
            "Mach-O header has insufficient load-command slack for __IBEX".into(),
        ));
    }
    if unsigned_stub[facts.commands_end..facts.commands_end + IBEX_COMMAND_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::Contract(
            "Mach-O load-command slack is not zero-filled".into(),
        ));
    }
    validate_standalone_envelope(standalone_envelope)?;
    let payload_offset =
        usize::try_from(facts.linkedit.fileoff).map_err(|_| Error::EnvelopeRange)?;
    let linkedit_size =
        usize::try_from(facts.linkedit.filesize).map_err(|_| Error::EnvelopeRange)?;
    if !payload_offset.is_multiple_of(MACHO_PAGE_ALIGNMENT)
        || payload_offset
            .checked_add(linkedit_size)
            .is_none_or(|end| end != unsigned_stub.len())
    {
        return Err(Error::Contract(
            "signature-stripped __LINKEDIT must be aligned and terminate the stub".into(),
        ));
    }
    let payload_offset_u32 = u32::try_from(payload_offset)
        .map_err(|_| Error::Contract("Mach-O payload offset exceeds section_64".into()))?;
    let payload_len = standalone_envelope.len();
    let vmsize =
        u64::try_from(align_up(payload_len, MACHO_PAGE_ALIGNMENT).ok_or(Error::EnvelopeRange)?)
            .map_err(|_| Error::EnvelopeRange)?;
    let insertion_size = usize::try_from(vmsize).map_err(|_| Error::EnvelopeRange)?;

    let mut output = unsigned_stub.to_vec();
    let command = segment_command(
        facts.linkedit.vmaddr,
        vmsize,
        payload_offset as u64,
        payload_len as u64,
        payload_offset_u32,
    );
    output.copy_within(
        facts.linkedit.command_offset..facts.commands_end,
        facts.linkedit.command_offset + IBEX_COMMAND_LEN,
    );
    output[facts.linkedit.command_offset..facts.linkedit.command_offset + IBEX_COMMAND_LEN]
        .copy_from_slice(&command);
    write_u32(
        &mut output,
        16,
        facts.ncmds.checked_add(1).ok_or(Error::EnvelopeRange)?,
    );
    write_u32(
        &mut output,
        20,
        facts
            .sizeofcmds
            .checked_add(IBEX_COMMAND_LEN as u32)
            .ok_or(Error::EnvelopeRange)?,
    );
    adjust_linkedit_layout(
        &mut output,
        facts.linkedit.fileoff,
        insertion_size as u64,
        vmsize,
    )?;
    let mut relocated = standalone_envelope.to_vec();
    let footer_start = relocated.len() - FOOTER_LEN_V1;
    write_u64(&mut relocated, footer_start + 24, payload_offset as u64);
    let mut image = Vec::with_capacity(
        unsigned_stub
            .len()
            .checked_add(insertion_size)
            .ok_or(Error::EnvelopeRange)?,
    );
    image.extend_from_slice(&output[..payload_offset]);
    image.extend_from_slice(&relocated);
    image.resize(payload_offset + insertion_size, 0);
    image.extend_from_slice(&output[payload_offset..]);
    Ok(image)
}

fn adjust_linkedit_layout(
    header: &mut [u8],
    old_linkedit_fileoff: u64,
    file_delta: u64,
    vm_delta: u64,
) -> Result<()> {
    let ncmds = read_u32(header, 16)?;
    let commands_end = MACH_HEADER_64_LEN + read_u32(header, 20)? as usize;
    let mut cursor = MACH_HEADER_64_LEN;
    for _ in 0..ncmds {
        let cmd = read_u32(header, cursor)?;
        let cmdsize = read_u32(header, cursor + 4)? as usize;
        if cmd == LC_SEGMENT_64 {
            let name = fixed_name(header, cursor + 8)?.to_owned();
            if name == "__LINKEDIT" {
                add_u64(header, cursor + 24, vm_delta)?;
                add_u64(header, cursor + 40, file_delta)?;
            }
            let nsects = read_u32(header, cursor + 64)? as usize;
            if name != "__IBEX" {
                for index in 0..nsects {
                    let section = cursor + SEGMENT_COMMAND_64_LEN + index * SECTION_64_LEN;
                    add_offset_u32_if_at_or_after(
                        header,
                        section + 48,
                        old_linkedit_fileoff,
                        file_delta,
                    )?;
                    add_offset_u32_if_at_or_after(
                        header,
                        section + 56,
                        old_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
        }
        match cmd {
            0x2 => {
                for offset in [8usize, 16] {
                    add_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        old_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0xb => {
                for offset in [32usize, 40, 48, 56, 64, 72] {
                    add_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        old_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0x22 | 0x8000_0022 => {
                for offset in [8usize, 16, 24, 32, 40] {
                    add_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        old_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0x16 | 0x1d | 0x1e | 0x21 | 0x25 | 0x26 | 0x29 | 0x2b | 0x2c | 0x2e | 0x8000_0033
            | 0x8000_0034 => {
                add_offset_u32_if_at_or_after(header, cursor + 8, old_linkedit_fileoff, file_delta)?
            }
            _ => {}
        }
        cursor = cursor.checked_add(cmdsize).ok_or(Error::EnvelopeRange)?;
    }
    if cursor != commands_end {
        return Err(Error::Contract(
            "Mach-O command table changed during __LINKEDIT adjustment".into(),
        ));
    }
    Ok(())
}

fn reverse_linkedit_layout(
    header: &mut [u8],
    current_linkedit_fileoff: u64,
    file_delta: u64,
    original_linkedit_vmsize: u64,
    original_linkedit_filesize: u64,
) -> Result<()> {
    let ncmds = read_u32(header, 16)?;
    let commands_end = MACH_HEADER_64_LEN + read_u32(header, 20)? as usize;
    let mut cursor = MACH_HEADER_64_LEN;
    let mut restored_linkedit = false;
    for _ in 0..ncmds {
        let cmd = read_u32(header, cursor)?;
        let cmdsize = read_u32(header, cursor + 4)? as usize;
        if cmd == LC_SEGMENT_64 {
            let name = fixed_name(header, cursor + 8)?.to_owned();
            if name == "__LINKEDIT" {
                sub_u64(header, cursor + 24, file_delta)?;
                write_u64(header, cursor + 32, original_linkedit_vmsize);
                sub_u64(header, cursor + 40, file_delta)?;
                write_u64(header, cursor + 48, original_linkedit_filesize);
                restored_linkedit = true;
            }
            let nsects = read_u32(header, cursor + 64)? as usize;
            for index in 0..nsects {
                let section = cursor + SEGMENT_COMMAND_64_LEN + index * SECTION_64_LEN;
                sub_offset_u32_if_at_or_after(
                    header,
                    section + 48,
                    current_linkedit_fileoff,
                    file_delta,
                )?;
                sub_offset_u32_if_at_or_after(
                    header,
                    section + 56,
                    current_linkedit_fileoff,
                    file_delta,
                )?;
            }
        }
        match cmd {
            0x2 => {
                for offset in [8usize, 16] {
                    sub_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        current_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0xb => {
                for offset in [32usize, 40, 48, 56, 64, 72] {
                    sub_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        current_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0x22 | 0x8000_0022 => {
                for offset in [8usize, 16, 24, 32, 40] {
                    sub_offset_u32_if_at_or_after(
                        header,
                        cursor + offset,
                        current_linkedit_fileoff,
                        file_delta,
                    )?;
                }
            }
            0x16 | 0x1d | 0x1e | 0x21 | 0x25 | 0x26 | 0x29 | 0x2b | 0x2c | 0x2e | 0x8000_0033
            | 0x8000_0034 => sub_offset_u32_if_at_or_after(
                header,
                cursor + 8,
                current_linkedit_fileoff,
                file_delta,
            )?,
            _ => {}
        }
        cursor = cursor.checked_add(cmdsize).ok_or(Error::EnvelopeRange)?;
    }
    if cursor != commands_end || !restored_linkedit {
        return Err(Error::Contract(
            "Mach-O command table changed during stub-core reconstruction".into(),
        ));
    }
    Ok(())
}

fn add_offset_u32_if_at_or_after(
    bytes: &mut [u8],
    offset: usize,
    threshold: u64,
    delta: u64,
) -> Result<()> {
    let value = read_u32(bytes, offset)?;
    if value != 0 && u64::from(value) >= threshold {
        let adjusted = u64::from(value)
            .checked_add(delta)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::EnvelopeRange)?;
        write_u32(bytes, offset, adjusted);
    }
    Ok(())
}

fn add_u64(bytes: &mut [u8], offset: usize, delta: u64) -> Result<()> {
    let adjusted = read_u64(bytes, offset)?
        .checked_add(delta)
        .ok_or(Error::EnvelopeRange)?;
    write_u64(bytes, offset, adjusted);
    Ok(())
}

fn sub_offset_u32_if_at_or_after(
    bytes: &mut [u8],
    offset: usize,
    threshold: u64,
    delta: u64,
) -> Result<()> {
    let value = read_u32(bytes, offset)?;
    if value != 0 && u64::from(value) >= threshold {
        let adjusted = u64::from(value)
            .checked_sub(delta)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(Error::EnvelopeRange)?;
        write_u32(bytes, offset, adjusted);
    }
    Ok(())
}

fn sub_u64(bytes: &mut [u8], offset: usize, delta: u64) -> Result<()> {
    let adjusted = read_u64(bytes, offset)?
        .checked_sub(delta)
        .ok_or(Error::EnvelopeRange)?;
    write_u64(bytes, offset, adjusted);
    Ok(())
}

fn validate_standalone_envelope(bytes: &[u8]) -> Result<()> {
    if bytes.len() < FOOTER_LEN_V1 {
        return Err(Error::Footer);
    }
    let footer = &bytes[bytes.len() - FOOTER_LEN_V1..];
    let profile = (&footer[..16], read_u32(footer, 16)?);
    if !matches!(profile, (magic, version) if (magic == FOOTER_MAGIC_V2 && version == FORMAT_VERSION_V2) || (magic == FOOTER_MAGIC_V3 && version == FORMAT_VERSION_V3))
        || read_u32(footer, 20)? as usize != FOOTER_LEN_V1
        || read_u64(footer, 24)? != 0
    {
        return Err(Error::Footer);
    }
    let directory_end = usize::try_from(read_u64(footer, 32)?)
        .ok()
        .and_then(|offset| {
            usize::try_from(read_u64(footer, 40).ok()?)
                .ok()
                .and_then(|length| offset.checked_add(length))
        });
    if directory_end != Some(bytes.len() - FOOTER_LEN_V1) {
        return Err(Error::EnvelopeRange);
    }
    Ok(())
}

fn parse(file: &[u8]) -> Result<MachHeaderFacts> {
    if file.len() < MACH_HEADER_64_LEN
        || read_u32(file, 0)? != MH_MAGIC_64
        || read_u32(file, 12)? != MH_EXECUTE
    {
        return Err(Error::Contract(
            "only thin little-endian Mach-O 64-bit executables are supported".into(),
        ));
    }
    let ncmds = read_u32(file, 16)?;
    let sizeofcmds = read_u32(file, 20)?;
    if ncmds == 0 || ncmds > 4096 {
        return Err(Error::Contract(
            "Mach-O load-command count is invalid".into(),
        ));
    }
    let commands_end = MACH_HEADER_64_LEN
        .checked_add(sizeofcmds as usize)
        .ok_or(Error::EnvelopeRange)?;
    if commands_end > file.len() {
        return Err(Error::EnvelopeRange);
    }
    let mut cursor = MACH_HEADER_64_LEN;
    let mut first_section_offset = usize::MAX;
    let mut linkedit = None;
    let mut code_signature = None;
    let mut ibex_payload = None;
    for _ in 0..ncmds {
        let cmd = read_u32(file, cursor)?;
        let cmdsize = read_u32(file, cursor + 4)? as usize;
        if cmdsize < 8
            || !cmdsize.is_multiple_of(8)
            || cursor
                .checked_add(cmdsize)
                .is_none_or(|end| end > commands_end)
        {
            return Err(Error::Contract("Mach-O load command is malformed".into()));
        }
        if cmd == LC_CODE_SIGNATURE {
            if cmdsize != 16 {
                return Err(Error::Contract(
                    "LC_CODE_SIGNATURE has the wrong size".into(),
                ));
            }
            let signature = (
                read_u32(file, cursor + 8)? as usize,
                read_u32(file, cursor + 12)? as usize,
            );
            if code_signature.replace(signature).is_some() {
                return Err(Error::Contract(
                    "Mach-O has duplicate code signatures".into(),
                ));
            }
        }
        if cmd == LC_SEGMENT_64 {
            if cmdsize < SEGMENT_COMMAND_64_LEN {
                return Err(Error::Contract(
                    "Mach-O segment command is truncated".into(),
                ));
            }
            let vmaddr = read_u64(file, cursor + 24)?;
            let fileoff = read_u64(file, cursor + 40)?;
            let filesize = read_u64(file, cursor + 48)?;
            let nsects = read_u32(file, cursor + 64)? as usize;
            if SEGMENT_COMMAND_64_LEN.checked_add(
                nsects
                    .checked_mul(SECTION_64_LEN)
                    .ok_or(Error::EnvelopeRange)?,
            ) != Some(cmdsize)
            {
                return Err(Error::Contract(
                    "Mach-O section table size is invalid".into(),
                ));
            }
            let segment_name = fixed_name(file, cursor + 8)?;
            if segment_name == "__LINKEDIT" {
                let facts = LinkeditFacts {
                    command_offset: cursor,
                    vmaddr,
                    fileoff,
                    filesize,
                };
                if linkedit.replace(facts).is_some() {
                    return Err(Error::Contract(
                        "Mach-O has duplicate __LINKEDIT segments".into(),
                    ));
                }
            }
            for index in 0..nsects {
                let section = cursor + SEGMENT_COMMAND_64_LEN + index * SECTION_64_LEN;
                let section_name = fixed_name(file, section)?;
                let section_segment = fixed_name(file, section + 16)?;
                let size = usize::try_from(read_u64(file, section + 40)?)
                    .map_err(|_| Error::EnvelopeRange)?;
                let offset = read_u32(file, section + 48)? as usize;
                if offset != 0 {
                    first_section_offset = first_section_offset.min(offset);
                }
                if segment_name == "__IBEX"
                    && section_segment == "__IBEX"
                    && section_name == "__payload"
                    && ibex_payload.replace((offset, size)).is_some()
                {
                    return Err(Error::Contract(
                        "Mach-O has duplicate __IBEX payloads".into(),
                    ));
                }
            }
        }
        cursor += cmdsize;
    }
    if cursor != commands_end || first_section_offset == usize::MAX || linkedit.is_none() {
        return Err(Error::Contract(
            "Mach-O executable layout is incomplete".into(),
        ));
    }
    Ok(MachHeaderFacts {
        ncmds,
        sizeofcmds,
        commands_end,
        first_section_offset,
        linkedit: linkedit.unwrap(),
        code_signature,
        ibex_payload,
    })
}

fn segment_command(
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    section_offset: u32,
) -> [u8; IBEX_COMMAND_LEN] {
    let mut bytes = [0u8; IBEX_COMMAND_LEN];
    write_u32(&mut bytes, 0, LC_SEGMENT_64);
    write_u32(&mut bytes, 4, IBEX_COMMAND_LEN as u32);
    write_name(&mut bytes, 8, "__IBEX");
    write_u64(&mut bytes, 24, vmaddr);
    write_u64(&mut bytes, 32, vmsize);
    write_u64(&mut bytes, 40, fileoff);
    write_u64(&mut bytes, 48, filesize);
    write_u32(&mut bytes, 56, 1);
    write_u32(&mut bytes, 60, 1);
    write_u32(&mut bytes, 64, 1);
    write_name(&mut bytes, 72, "__payload");
    write_name(&mut bytes, 88, "__IBEX");
    write_u64(&mut bytes, 104, vmaddr);
    write_u64(&mut bytes, 112, filesize);
    write_u32(&mut bytes, 120, section_offset);
    write_u32(&mut bytes, 124, 14);
    bytes
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

fn fixed_name(bytes: &[u8], offset: usize) -> Result<&str> {
    let raw = bytes.get(offset..offset + 16).ok_or(Error::EnvelopeRange)?;
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    std::str::from_utf8(&raw[..end])
        .map_err(|_| Error::Contract("Mach-O name is not ASCII/UTF-8".into()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::EnvelopeRange)?
            .try_into()
            .map_err(|_| Error::EnvelopeRange)?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(Error::EnvelopeRange)?
            .try_into()
            .map_err(|_| Error::EnvelopeRange)?,
    ))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_name(bytes: &mut [u8], offset: usize, value: &str) {
    bytes[offset..offset + value.len()].copy_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admit_executable_v1, build_executable_v1, EntryDesignationV1, SectionInputV1, SectionKindV1,
    };

    fn synthetic_stub() -> Vec<u8> {
        let mut bytes = vec![0u8; 32 * 1024];
        write_u32(&mut bytes, 0, MH_MAGIC_64);
        write_u32(&mut bytes, 12, MH_EXECUTE);
        write_u32(&mut bytes, 16, 2);
        write_u32(
            &mut bytes,
            20,
            (IBEX_COMMAND_LEN + SEGMENT_COMMAND_64_LEN) as u32,
        );
        let command = segment_command(0x1_0000_0000, 16 * 1024, 0, 16 * 1024, 512);
        bytes[MACH_HEADER_64_LEN..MACH_HEADER_64_LEN + IBEX_COMMAND_LEN].copy_from_slice(&command);
        write_name(&mut bytes, MACH_HEADER_64_LEN + 8, "__TEXT");
        write_name(&mut bytes, MACH_HEADER_64_LEN + 72, "__text");
        write_name(&mut bytes, MACH_HEADER_64_LEN + 88, "__TEXT");
        let linkedit = MACH_HEADER_64_LEN + IBEX_COMMAND_LEN;
        write_u32(&mut bytes, linkedit, LC_SEGMENT_64);
        write_u32(&mut bytes, linkedit + 4, SEGMENT_COMMAND_64_LEN as u32);
        write_name(&mut bytes, linkedit + 8, "__LINKEDIT");
        write_u64(&mut bytes, linkedit + 24, 0x1_0000_4000);
        write_u64(&mut bytes, linkedit + 32, 16 * 1024);
        write_u64(&mut bytes, linkedit + 40, 16 * 1024);
        write_u64(&mut bytes, linkedit + 48, 16 * 1024);
        write_u32(&mut bytes, linkedit + 56, 1);
        write_u32(&mut bytes, linkedit + 60, 1);
        bytes
    }

    fn standalone_envelope() -> Vec<u8> {
        let contract_value = crate::fixture_stub_contract();
        let contract = contract_value.digest().unwrap();
        let entry = EntryDesignationV1::one(
            "ibex-source-id-v1:eyJkb21haW4iOiJpYmV4LXJ1bnRpbWUiLCJraW5kIjoiYnVpbHRpbiIsInNvdXJjZV9rZXkiOiJleGFjdDpmcyJ9",
        )
        .canonical_bytes()
        .unwrap();
        build_executable_v1(
            b"",
            &contract,
            vec![
                SectionInputV1::canonical(
                    "stub-contract",
                    SectionKindV1::StubContract,
                    contract_value.canonical_bytes().unwrap(),
                ),
                SectionInputV1::canonical(
                    "provenance",
                    SectionKindV1::ProvenanceManifest,
                    br#"{"schema":"ibex/package-provenance/1"}"#.to_vec(),
                ),
                SectionInputV1::canonical(
                    "graph",
                    SectionKindV1::EmbeddedModuleGraph,
                    br#"{"schema":"ibex/embedded-module-graph/1"}"#.to_vec(),
                ),
                SectionInputV1::canonical(
                    "policy",
                    SectionKindV1::ResolvedPolicy,
                    br#"{"policySchema":"ibex/capsec-policy/2"}"#.to_vec(),
                ),
                SectionInputV1::canonical("entry", SectionKindV1::EntryDesignation, entry),
                SectionInputV1::carrier(
                    "carrier-manifest",
                    SectionKindV1::CarrierManifest,
                    "pair",
                    br#"{"schema":"ibex/module-carrier/2"}"#.to_vec(),
                ),
                SectionInputV1::carrier(
                    "carrier-payload",
                    SectionKindV1::CarrierPayload,
                    "pair",
                    b"payload".to_vec(),
                ),
            ],
        )
        .unwrap()
    }

    fn structurally_signed_image() -> (Vec<u8>, usize) {
        let mut image =
            inject_envelope_segment_v1(&synthetic_stub(), &standalone_envelope()).unwrap();
        let facts = parse(&image).unwrap();
        assert!(facts.commands_end + 16 <= facts.first_section_offset);
        let signature_command = facts.commands_end;
        let signature_offset = image.len() as u32;
        write_u32(&mut image, signature_command, LC_CODE_SIGNATURE);
        write_u32(&mut image, signature_command + 4, 16);
        write_u32(&mut image, signature_command + 8, signature_offset);
        write_u32(&mut image, signature_command + 12, 16);
        write_u32(&mut image, 16, facts.ncmds + 1);
        write_u32(&mut image, 20, facts.sizeofcmds + 16);
        write_u64(
            &mut image,
            facts.linkedit.command_offset + 48,
            facts.linkedit.filesize + 16,
        );
        image.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE);
        image.extend_from_slice(&[0; 12]);
        (image, signature_command)
    }

    #[test]
    fn synthetic_header_has_space_for_one_new_segment() {
        let stub = synthetic_stub();
        let facts = parse(&stub).unwrap();
        assert_eq!(facts.first_section_offset, 512);
        assert_eq!(facts.commands_end, 256);
        assert!(facts.code_signature.is_none());
    }

    #[test]
    fn injected_segment_remains_admissible_with_post_signing_tail_bytes() {
        let contract_value = crate::fixture_stub_contract();
        let contract = contract_value.digest().unwrap();
        let standalone = standalone_envelope();
        let image = inject_envelope_segment_v1(&synthetic_stub(), &standalone).unwrap();
        let admitted = admit_executable_v1(&image, &contract).unwrap();
        assert_eq!(admitted.stub_len, 16 * 1024);
        assert_eq!(
            admitted.section("carrier-payload").unwrap().bytes,
            b"payload"
        );

        let mut post_signing = image;
        post_signing.extend_from_slice(b"detached-signature-placeholder");
        assert!(admit_executable_v1(&post_signing, &contract).is_ok());

        let (structurally_signed, _) = structurally_signed_image();
        validate_signed_envelope_layout_v1(&structurally_signed).unwrap();
    }

    #[test]
    fn completed_image_reconstructs_the_exact_catalog_stub_core() {
        // @ref LLP 0029#2-executable-layout-stub-envelope-footer — platform signing
        // may rewrite __LINKEDIT metadata, but inspection still rehashes the
        // exact signature-stripped catalog instance
        let stub = synthetic_stub();
        let original_vmsize = linkedit_vmsize_v1(&stub).unwrap();
        let unsigned = inject_envelope_segment_v1(&stub, &standalone_envelope()).unwrap();
        assert_eq!(
            reconstruct_stub_core_v1(&unsigned, stub.len() as u64, original_vmsize).unwrap(),
            stub
        );

        let (mut signed, _) = structurally_signed_image();
        let signed_facts = parse(&signed).unwrap();
        write_u64(
            &mut signed,
            signed_facts.linkedit.command_offset + 32,
            MACHO_PAGE_ALIGNMENT as u64,
        );
        assert_eq!(
            reconstruct_stub_core_v1(&signed, stub.len() as u64, original_vmsize).unwrap(),
            stub
        );
    }

    #[test]
    fn injection_refuses_signed_duplicate_nonzero_slack_and_nonterminal_inputs() {
        // @ref LLP 0029#2-executable-layout-stub-envelope-footer — injection
        // is defined only over the stripped, unique, zero-slack-safe layout
        let envelope = standalone_envelope();

        let mut signature_bearing = synthetic_stub();
        let facts = parse(&signature_bearing).unwrap();
        write_u32(
            &mut signature_bearing,
            facts.commands_end,
            LC_CODE_SIGNATURE,
        );
        write_u32(&mut signature_bearing, facts.commands_end + 4, 16);
        write_u32(&mut signature_bearing, facts.commands_end + 8, 1);
        write_u32(&mut signature_bearing, facts.commands_end + 12, 1);
        write_u32(&mut signature_bearing, 16, facts.ncmds + 1);
        write_u32(&mut signature_bearing, 20, facts.sizeofcmds + 16);
        assert!(inject_envelope_segment_v1(&signature_bearing, &envelope)
            .unwrap_err()
            .to_string()
            .contains("strip it before injection"));

        let already_injected = inject_envelope_segment_v1(&synthetic_stub(), &envelope).unwrap();
        assert!(inject_envelope_segment_v1(&already_injected, &envelope)
            .unwrap_err()
            .to_string()
            .contains("already contains an __IBEX payload"));

        let mut nonzero_slack = synthetic_stub();
        let facts = parse(&nonzero_slack).unwrap();
        nonzero_slack[facts.commands_end] = 1;
        assert!(inject_envelope_segment_v1(&nonzero_slack, &envelope)
            .unwrap_err()
            .to_string()
            .contains("slack is not zero-filled"));

        let mut insufficient_slack = synthetic_stub();
        let facts = parse(&insufficient_slack).unwrap();
        write_u32(
            &mut insufficient_slack,
            MACH_HEADER_64_LEN + 120,
            (facts.commands_end + IBEX_COMMAND_LEN - 1) as u32,
        );
        assert!(inject_envelope_segment_v1(&insufficient_slack, &envelope)
            .unwrap_err()
            .to_string()
            .contains("insufficient load-command slack"));

        let mut nonterminal_linkedit = synthetic_stub();
        let facts = parse(&nonterminal_linkedit).unwrap();
        write_u64(
            &mut nonterminal_linkedit,
            facts.linkedit.command_offset + 48,
            facts.linkedit.filesize - 1,
        );
        assert!(inject_envelope_segment_v1(&nonterminal_linkedit, &envelope)
            .unwrap_err()
            .to_string()
            .contains("must be aligned and terminate"));
    }

    #[test]
    fn signed_layout_refuses_tail_magic_range_linkedit_and_duplicate_signature_mutations() {
        // @ref LLP 0029#2-executable-layout-stub-envelope-footer — one
        // terminal signature and terminal __LINKEDIT must seal the payload
        let (signed, signature_command) = structurally_signed_image();
        validate_signed_envelope_layout_v1(&signed).unwrap();

        let mut trailing = signed.clone();
        trailing.push(0);
        assert!(validate_signed_envelope_layout_v1(&trailing).is_err());

        let mut zero_size = signed.clone();
        write_u32(&mut zero_size, signature_command + 12, 0);
        assert!(validate_signed_envelope_layout_v1(&zero_size).is_err());

        let mut wrong_magic = signed.clone();
        let signature_offset = read_u32(&wrong_magic, signature_command + 8).unwrap() as usize;
        wrong_magic[signature_offset] ^= 1;
        assert!(validate_signed_envelope_layout_v1(&wrong_magic).is_err());

        let mut before_payload_end = signed.clone();
        let facts = parse(&before_payload_end).unwrap();
        let (payload_offset, _) = facts.ibex_payload.unwrap();
        write_u32(
            &mut before_payload_end,
            signature_command + 8,
            payload_offset as u32,
        );
        assert!(validate_signed_envelope_layout_v1(&before_payload_end).is_err());

        let mut short_linkedit = signed.clone();
        let facts = parse(&short_linkedit).unwrap();
        write_u64(
            &mut short_linkedit,
            facts.linkedit.command_offset + 48,
            facts.linkedit.filesize - 1,
        );
        assert!(validate_signed_envelope_layout_v1(&short_linkedit).is_err());

        let mut duplicate_signature = signed;
        let facts = parse(&duplicate_signature).unwrap();
        let second = facts.commands_end;
        assert!(second + 16 <= facts.first_section_offset);
        let original_signature_offset =
            read_u32(&duplicate_signature, signature_command + 8).unwrap();
        let original_signature_size =
            read_u32(&duplicate_signature, signature_command + 12).unwrap();
        write_u32(&mut duplicate_signature, second, LC_CODE_SIGNATURE);
        write_u32(&mut duplicate_signature, second + 4, 16);
        write_u32(
            &mut duplicate_signature,
            second + 8,
            original_signature_offset,
        );
        write_u32(
            &mut duplicate_signature,
            second + 12,
            original_signature_size,
        );
        write_u32(&mut duplicate_signature, 16, facts.ncmds + 1);
        write_u32(&mut duplicate_signature, 20, facts.sizeofcmds + 16);
        assert!(validate_signed_envelope_layout_v1(&duplicate_signature)
            .unwrap_err()
            .to_string()
            .contains("duplicate code signatures"));
    }
}
