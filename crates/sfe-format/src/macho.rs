//! Minimal fail-closed Mach-O 64-bit envelope segment injection.
//!
//! The implementation intentionally supports only thin little-endian 64-bit
//! executables with header slack. It never rewrites existing section offsets.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — macOS payloads live in a named segment and remain discoverable after code signing appends its signature

use super::{Error, Result, FOOTER_LEN_V1, FOOTER_MAGIC_V1, FORMAT_VERSION_V1};

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

fn validate_standalone_envelope(bytes: &[u8]) -> Result<()> {
    if bytes.len() < FOOTER_LEN_V1 {
        return Err(Error::Footer);
    }
    let footer = &bytes[bytes.len() - FOOTER_LEN_V1..];
    if footer[..16] != FOOTER_MAGIC_V1
        || read_u32(footer, 16)? != FORMAT_VERSION_V1
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
        let contract = crate::digest(b"macho contract");
        let entry = EntryDesignationV1::one(
            "ibex-source-id-v1:eyJkb21haW4iOiJpYmV4LXJ1bnRpbWUiLCJraW5kIjoiYnVpbHRpbiIsInNvdXJjZV9rZXkiOiJleGFjdDpmcyJ9",
        )
        .canonical_bytes()
        .unwrap();
        let standalone = build_executable_v1(
            b"",
            &contract,
            vec![
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
        .unwrap();
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

        let mut structurally_signed = post_signing;
        structurally_signed
            .truncate(structurally_signed.len() - b"detached-signature-placeholder".len());
        let facts = parse(&structurally_signed).unwrap();
        assert!(facts.commands_end + 16 <= facts.first_section_offset);
        let signature_offset = structurally_signed.len() as u32;
        write_u32(
            &mut structurally_signed,
            facts.commands_end,
            LC_CODE_SIGNATURE,
        );
        write_u32(&mut structurally_signed, facts.commands_end + 4, 16);
        write_u32(
            &mut structurally_signed,
            facts.commands_end + 8,
            signature_offset,
        );
        write_u32(&mut structurally_signed, facts.commands_end + 12, 16);
        write_u32(&mut structurally_signed, 16, facts.ncmds + 1);
        write_u32(&mut structurally_signed, 20, facts.sizeofcmds + 16);
        write_u64(
            &mut structurally_signed,
            facts.linkedit.command_offset + 48,
            facts.linkedit.filesize + 16,
        );
        structurally_signed.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE);
        structurally_signed.extend_from_slice(&[0; 12]);
        validate_signed_envelope_layout_v1(&structurally_signed).unwrap();
    }
}
