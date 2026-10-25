use crate::pe::image::SectionInfo;

use std::collections::HashSet;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("unsupported PE machine hint: {0}")]
    UnsupportedMachine(String),
    #[error("cannot synthesize PE headers without section hints")]
    MissingSections,
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHeaderInfo {
    pub machine: u16,
    pub machine_name: &'static str,
    pub section_count: u16,
    pub optional_header_size: u16,
    pub optional_magic: u16,
    pub characteristics: u16,
    pub is_dll: bool,
    pub section_table_offset: usize,
    pub sections: Vec<SectionInfo>,
}

/// Surviving PE-header pattern recognized in a byte scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum HeaderArtifactKind {
    /// DOS and NT signatures identify a PE header candidate.
    MzPe,
    /// NT signature and associated headers survive without requiring a DOS header.
    NtHeaders,
    /// COFF and optional-header evidence survives without requiring signatures.
    FileHeader,
    /// A plausible section table survives without usable preceding headers.
    SectionTable,
}

impl HeaderArtifactKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderArtifact {
    pub kind: HeaderArtifactKind,
    pub address: u64,
    pub offset: u64,
    pub score: u32,
    pub sections: Vec<SectionInfo>,
    pub machine: Option<u16>,
    pub machine_name: Option<&'static str>,
    pub is_dll: Option<bool>,
    pub section_table_offset: Option<u64>,
    pub e_lfanew: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticImage {
    pub data: Vec<u8>,
    pub image_base: u64,
    pub header_prefix: u32,
    pub entry_point: u32,
    pub image_size: u32,
}

pub const PE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const PE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const PE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const PE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const PE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const PE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const PE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const PE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const PE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const PE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const PE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const PE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const PE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const PE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const PE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub const PE_DIRECTORY_ENTRY_RESERVED: usize = 15;

pub const PE_DATA_DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "ComDescriptor",
    "Reserved",
];

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
pub const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;
pub const IMAGE_FILE_MACHINE_CHPE_X86: u16 = 0x3a64;
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
pub const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
pub const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
pub const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
pub const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
pub const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
pub const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
pub const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
pub const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
pub const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
pub const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;
pub const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
pub const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
pub const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
pub const IMAGE_GUARD_CASTGUARD_PRESENT: u32 = 0x0100_0000;
pub const IMAGE_GUARD_MEMCPY_PRESENT: u32 = 0x0200_0000;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 0xf000_0000;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28;
pub const MAX_SECTIONS: usize = 96;
pub const SECTION_HEADER_SIZE: usize = 40;

const COMMON_SECTION_NAMES: [&[u8]; 10] = [
    b".text",
    b"CODE",
    b".rdata",
    b".data",
    b".pdata",
    b".rsrc",
    b".reloc",
    b".tls",
    b".edata",
    b".idata",
];

impl HeaderArtifact {
    pub fn reason(&self, coverage_count: usize) -> String {
        match self.kind {
            HeaderArtifactKind::MzPe => format!("intact MZ/PE header at allocation+0x{:x}", self.offset),
            HeaderArtifactKind::NtHeaders => format!("NT headers at allocation+0x{:x}", self.offset),
            HeaderArtifactKind::FileHeader => format!(
                "PE file header at allocation+0x{:x} sections={} covered_sections={coverage_count}",
                self.offset,
                self.sections.len()
            ),
            HeaderArtifactKind::SectionTable => format!("section-table shaped data at allocation+0x{:x}", self.offset),
        }
    }
}

pub fn machine_name(machine: u16) -> Option<&'static str> {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Some("x86"),
        IMAGE_FILE_MACHINE_AMD64 => Some("x64"),
        IMAGE_FILE_MACHINE_ARM64 => Some("arm64"),
        IMAGE_FILE_MACHINE_ARM64EC => Some("arm64ec"),
        IMAGE_FILE_MACHINE_ARM64X => Some("arm64x"),
        IMAGE_FILE_MACHINE_CHPE_X86 => Some("chpe_x86"),
        _ => None,
    }
}

pub fn machine_value(machine: &str) -> Option<u16> {
    match machine.to_ascii_lowercase().as_str() {
        "x86" | "i386" => Some(IMAGE_FILE_MACHINE_I386),
        "x64" | "amd64" => Some(IMAGE_FILE_MACHINE_AMD64),
        "arm64" | "aarch64" => Some(IMAGE_FILE_MACHINE_ARM64),
        "arm64ec" => Some(IMAGE_FILE_MACHINE_ARM64EC),
        "arm64x" => Some(IMAGE_FILE_MACHINE_ARM64X),
        "chpe_x86" | "chpe-x86" | "chpe" => Some(IMAGE_FILE_MACHINE_CHPE_X86),
        _ => None,
    }
}

pub fn normalize_machine(machine: Option<&str>) -> Result<u16, FormatError> {
    match machine {
        None => Ok(IMAGE_FILE_MACHINE_AMD64),
        Some(machine) => machine_value(machine)
            .ok_or_else(|| FormatError::UnsupportedMachine(machine.to_string())),
    }
}

pub fn section_size(section: &SectionInfo) -> u32 {
    section.virtual_size.max(section.raw_size)
}

pub fn section_is_executable(section: &SectionInfo) -> bool {
    section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
}

pub fn section_summary(section: &SectionInfo) -> String {
    format!(
        "{}@0x{:x}/0x{:x}",
        section.name,
        section.virtual_address,
        section_size(section)
    )
}

pub fn section_name(data: &[u8], offset: usize) -> Option<String> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    let raw = &bytes[..end];

    if raw.is_empty() || raw.iter().any(|byte| *byte < 0x20 || *byte > 0x7e) {
        return None;
    }

    std::str::from_utf8(raw).ok().map(str::to_string)
}

pub fn is_common_section_name(name: &str) -> bool {
    COMMON_SECTION_NAMES
        .iter()
        .any(|common_name| *common_name == name.as_bytes())
}

pub fn parse_section_header(data: &[u8], offset: usize) -> Option<SectionInfo> {
    let name = section_name(data, offset)?;
    let virtual_size = read_u32(data, offset.checked_add(8)?)?;
    let virtual_address = read_u32(data, offset.checked_add(12)?)?;
    let raw_size = read_u32(data, offset.checked_add(16)?)?;
    let raw_offset = read_u32(data, offset.checked_add(20)?)?;
    let reloc_offset = read_u32(data, offset.checked_add(24)?)?;
    let line_offset = read_u32(data, offset.checked_add(28)?)?;
    let reloc_count = read_u16(data, offset.checked_add(32)?)?;
    let line_count = read_u16(data, offset.checked_add(34)?)?;
    let characteristics = read_u32(data, offset.checked_add(36)?)?;

    if virtual_size == 0 && raw_size == 0 {
        return None;
    }
    if virtual_address > 0x7fff_ffff || virtual_size > 0x4000_0000 || raw_size > 0x4000_0000 {
        return None;
    }
    if reloc_offset != 0 || line_offset != 0 || reloc_count != 0 || line_count != 0 {
        return None;
    }
    if characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE) == 0 {
        return None;
    }

    Some(SectionInfo {
        name,
        virtual_address,
        virtual_size,
        raw_offset,
        raw_size,
        characteristics,
    })
}

pub fn parse_section_table(data: &[u8], offset: usize, count: Option<usize>) -> Option<Vec<SectionInfo>> {
    if offset.checked_add(SECTION_HEADER_SIZE)? > data.len() {
        return None;
    }

    let max_count = count.unwrap_or(MAX_SECTIONS);
    let mut sections = Vec::new();

    for index in 0..max_count {
        let section_offset = offset.checked_add(index.checked_mul(SECTION_HEADER_SIZE)?)?;
        let Some(section) = parse_section_header(data, section_offset) else {
            break;
        };
        sections.push(section);
    }

    if count.is_some_and(|count| sections.len() != count) || sections.is_empty() {
        return None;
    }

    let mut has_executable = false;
    let mut last_rva = None;
    for section in &sections {
        if section_is_executable(section) {
            has_executable = true;
        }
        if last_rva.is_some_and(|last_rva| section.virtual_address < last_rva) {
            return None;
        }
        last_rva = Some(section.virtual_address);
    }

    has_executable.then_some(sections)
}

pub fn parse_file_header(data: &[u8], offset: usize) -> Option<FileHeaderInfo> {
    if offset.checked_add(20)? > data.len() {
        return None;
    }

    let machine = read_u16(data, offset)?;
    let machine_name = machine_name(machine)?;
    let section_count = read_u16(data, offset.checked_add(2)?)?;
    let optional_header_size = read_u16(data, offset.checked_add(16)?)?;
    let characteristics = read_u16(data, offset.checked_add(18)?)?;

    if section_count == 0 || section_count as usize > MAX_SECTIONS {
        return None;
    }
    if optional_header_size > 0x400 {
        return None;
    }

    let optional_header_offset = offset.checked_add(20)?;
    let optional_magic = read_u16(data, optional_header_offset)?;
    if optional_header_size != 0
        && !matches!(optional_magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC | IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return None;
    }

    let section_table_offset = optional_header_offset.checked_add(optional_header_size as usize)?;
    let sections = parse_section_table(data, section_table_offset, Some(section_count as usize))?;

    Some(FileHeaderInfo {
        machine,
        machine_name,
        section_count,
        optional_header_size,
        optional_magic,
        characteristics,
        is_dll: characteristics & IMAGE_FILE_DLL != 0,
        section_table_offset,
        sections,
    })
}

pub fn scan_header_artifacts(data: &[u8], chunk_base: u64, allocation_base: u64) -> Vec<HeaderArtifact> {
    let mut artifacts = Vec::new();

    artifacts.extend(find_mz_pe_artifacts(data, chunk_base, allocation_base));
    artifacts.extend(find_nt_header_artifacts(data, chunk_base, allocation_base));
    artifacts.extend(find_file_header_artifacts(data, chunk_base, allocation_base));
    artifacts.extend(find_section_table_artifacts(data, chunk_base, allocation_base));
    artifacts.sort_by(|left, right| right.score.cmp(&left.score).then(left.offset.cmp(&right.offset)));

    artifacts
}

pub fn image_size_from_sections(sections: &[SectionInfo], fallback_size: usize) -> Result<u32, FormatError> {
    let mut image_size = fallback_size;

    for section in sections {
        let section_end = (section.virtual_address as usize)
            .checked_add(section_size(section) as usize)
            .ok_or(FormatError::Overflow("computing PE image size from sections"))?;
        image_size = image_size.max(section_end);
    }

    align_up_usize(image_size, 0x1000, "aligning PE image size").and_then(|value| {
        u32::try_from(value).map_err(|_| FormatError::Overflow("checking PE image size"))
    })
}

pub fn first_executable_section_rva(sections: &[SectionInfo]) -> u32 {
    sections
        .iter()
        .find(|section| section_is_executable(section))
        .or_else(|| sections.first())
        .map(|section| section.virtual_address)
        .unwrap_or(0)
}

pub fn synthesize_mapped_image(
    raw_data: &[u8],
    image_base: u64,
    sections: &[SectionInfo],
    machine: Option<&str>,
    is_dll: bool,
    entry_point_rva: Option<u32>,
    image_size: Option<u32>,
) -> Result<SyntheticImage, FormatError> {
    if sections.is_empty() {
        return Err(FormatError::MissingSections);
    }

    let machine = normalize_machine(machine)?;
    let entry_point = entry_point_rva.unwrap_or_else(|| first_executable_section_rva(sections));
    let optional_header_size = synthetic_optional_header_size(machine);
    let e_lfanew = 0x80usize;
    let file_header_offset = e_lfanew + 4;
    let optional_header_offset = file_header_offset + 20;
    let section_table_offset = optional_header_offset + optional_header_size as usize;
    let size_of_headers = align_up_usize(
        section_table_offset
            .checked_add(sections.len().checked_mul(SECTION_HEADER_SIZE).ok_or(FormatError::Overflow("computing PE section table size"))?)
            .ok_or(FormatError::Overflow("computing PE header size"))?,
        0x200,
        "aligning PE headers",
    )?;
    let image_size = match image_size {
        Some(image_size) => image_size,
        None => image_size_from_sections(sections, raw_data.len())?,
    };
    let image_size = align_up_usize(image_size as usize, 0x1000, "aligning PE image size")?
        .max(size_of_headers);
    let image_size = u32::try_from(image_size)
        .map_err(|_| FormatError::Overflow("checking synthesized PE image size"))?;
    let size_of_headers = u32::try_from(size_of_headers)
        .map_err(|_| FormatError::Overflow("checking synthesized PE header size"))?;
    let mut data = raw_data.to_vec();

    if data.len() < image_size as usize {
        data.resize(image_size as usize, 0);
    }

    data[..size_of_headers as usize].fill(0);
    write_u16(&mut data, 0, IMAGE_DOS_SIGNATURE)?;
    write_u32(&mut data, 0x3c, e_lfanew as u32)?;
    write_u32(&mut data, e_lfanew, IMAGE_NT_SIGNATURE)?;
    write_u16(&mut data, file_header_offset, machine)?;
    write_u16(&mut data, file_header_offset + 2, sections.len() as u16)?;
    write_u16(&mut data, file_header_offset + 16, optional_header_size)?;
    write_u16(&mut data, file_header_offset + 18, synthetic_characteristics(machine, is_dll))?;
    write_synthetic_optional_header(
        &mut data,
        optional_header_offset,
        machine,
        image_base,
        image_size,
        entry_point,
        size_of_headers,
    )?;

    for (index, section) in sections.iter().enumerate() {
        write_synthetic_section_header(&mut data, section_table_offset + index * SECTION_HEADER_SIZE, section)?;
    }

    Ok(SyntheticImage {
        data,
        image_base,
        header_prefix: 0,
        entry_point,
        image_size,
    })
}

fn find_mz_pe_artifacts(data: &[u8], chunk_base: u64, allocation_base: u64) -> Vec<HeaderArtifact> {
    let mut artifacts = Vec::new();
    let mut offset = 0;

    while let Some(found) = find_bytes(data, b"MZ", offset) {
        offset = found;
        if offset.checked_add(0x40).is_some_and(|end| end <= data.len()) {
            if let Some(e_lfanew) = read_u32(data, offset + 0x3c) {
                if (0x40..=0x1000).contains(&e_lfanew) {
                    let pe_offset = offset + e_lfanew as usize;
                    if pe_offset.checked_add(4).is_some_and(|end| end <= data.len())
                        && data[pe_offset..pe_offset + 4] == IMAGE_NT_SIGNATURE.to_le_bytes()
                    {
                        if let Some(header) = parse_file_header(data, pe_offset + 4) {
                            artifacts.push(make_artifact(
                                HeaderArtifactKind::MzPe,
                                chunk_base,
                                offset,
                                allocation_base,
                                Some(header),
                                None,
                                Some(e_lfanew),
                            ));
                        }
                    }
                }
            }
        }
        offset += 2;
    }

    artifacts
}

fn find_nt_header_artifacts(data: &[u8], chunk_base: u64, allocation_base: u64) -> Vec<HeaderArtifact> {
    let mut artifacts = Vec::new();
    let mut offset = 0;

    while let Some(found) = find_bytes(data, &IMAGE_NT_SIGNATURE.to_le_bytes(), offset) {
        offset = found;
        if let Some(header) = parse_file_header(data, offset + 4) {
            artifacts.push(make_artifact(
                HeaderArtifactKind::NtHeaders,
                chunk_base,
                offset,
                allocation_base,
                Some(header),
                None,
                None,
            ));
        }
        offset += 4;
    }

    artifacts
}

fn find_file_header_artifacts(data: &[u8], chunk_base: u64, allocation_base: u64) -> Vec<HeaderArtifact> {
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();

    for machine in [IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64] {
        let signature = machine.to_le_bytes();
        let mut offset = 0;

        while let Some(found) = find_bytes(data, &signature, offset) {
            offset = found;
            if offset >= 4 && data[offset - 4..offset] == IMAGE_NT_SIGNATURE.to_le_bytes() {
                offset += 2;
                continue;
            }

            if let Some(header) = parse_file_header(data, offset) {
                if seen.insert(offset) {
                    artifacts.push(make_artifact(
                        HeaderArtifactKind::FileHeader,
                        chunk_base,
                        offset,
                        allocation_base,
                        Some(header),
                        None,
                        None,
                    ));
                }
            }
            offset += 2;
        }
    }

    artifacts
}

fn find_section_table_artifacts(data: &[u8], chunk_base: u64, allocation_base: u64) -> Vec<HeaderArtifact> {
    let mut artifacts = Vec::new();
    let mut seen = HashSet::new();

    for name in COMMON_SECTION_NAMES {
        let mut offset = 0;
        while let Some(found) = find_bytes(data, name, offset) {
            offset = found;
            let max_back = 8.min(offset / SECTION_HEADER_SIZE);

            for back in 0..=max_back {
                let table_offset = offset - back * SECTION_HEADER_SIZE;
                if !seen.insert(table_offset) {
                    continue;
                }

                if let Some(sections) = parse_section_table(data, table_offset, None) {
                    if sections.len() == 1 && !is_common_section_name(&sections[0].name) {
                        continue;
                    }

                    artifacts.push(make_artifact(
                        HeaderArtifactKind::SectionTable,
                        chunk_base,
                        table_offset,
                        allocation_base,
                        None,
                        Some(sections),
                        None,
                    ));
                }
            }
            offset += name.len();
        }
    }

    artifacts.sort_by_key(|artifact| artifact.address);

    let mut filtered: Vec<HeaderArtifact> = Vec::new();
    'artifact: for artifact in artifacts {
        for previous in &filtered {
            let previous_table_end = previous.address + (previous.sections.len() * SECTION_HEADER_SIZE) as u64;
            if artifact.address > previous.address && artifact.address < previous_table_end {
                continue 'artifact;
            }
        }

        filtered.push(artifact);
    }

    filtered
}

fn make_artifact(
    kind: HeaderArtifactKind,
    chunk_base: u64,
    offset: usize,
    allocation_base: u64,
    header: Option<FileHeaderInfo>,
    sections: Option<Vec<SectionInfo>>,
    e_lfanew: Option<u32>,
) -> HeaderArtifact {
    let sections = sections.unwrap_or_else(|| {
        header
            .as_ref()
            .map(|header| header.sections.clone())
            .unwrap_or_default()
    });
    let offset_from_allocation = (chunk_base + offset as u64).saturating_sub(allocation_base);
    let section_table_offset = header
        .as_ref()
        .map(|header| (chunk_base + header.section_table_offset as u64).saturating_sub(allocation_base))
        .or_else(|| (kind == HeaderArtifactKind::SectionTable).then_some(offset_from_allocation));

    HeaderArtifact {
        kind,
        address: chunk_base + offset as u64,
        offset: offset_from_allocation,
        score: artifact_base_score(kind, &sections),
        sections,
        machine: header.as_ref().map(|header| header.machine),
        machine_name: header.as_ref().map(|header| header.machine_name),
        is_dll: header.as_ref().map(|header| header.is_dll),
        section_table_offset,
        e_lfanew,
    }
}

fn artifact_base_score(kind: HeaderArtifactKind, sections: &[SectionInfo]) -> u32 {
    let mut score = match kind {
        HeaderArtifactKind::MzPe => 7,
        HeaderArtifactKind::NtHeaders => 5,
        HeaderArtifactKind::FileHeader => 4,
        HeaderArtifactKind::SectionTable => 3,
    };

    score += sections.len().min(4) as u32;
    score
}

fn synthetic_optional_header_size(machine: u16) -> u16 {
    if machine == IMAGE_FILE_MACHINE_I386 {
        0xe0
    } else {
        0xf0
    }
}

fn synthetic_optional_magic(machine: u16) -> u16 {
    if machine == IMAGE_FILE_MACHINE_I386 {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC
    } else {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }
}

fn synthetic_characteristics(machine: u16, is_dll: bool) -> u16 {
    let mut characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    if machine == IMAGE_FILE_MACHINE_I386 {
        characteristics |= IMAGE_FILE_32BIT_MACHINE;
    }
    if is_dll {
        characteristics |= IMAGE_FILE_DLL;
    }

    characteristics
}

fn write_synthetic_optional_header(
    data: &mut [u8],
    offset: usize,
    machine: u16,
    image_base: u64,
    image_size: u32,
    entry_point: u32,
    size_of_headers: u32,
) -> Result<(), FormatError> {
    let is_pe32 = machine == IMAGE_FILE_MACHINE_I386;

    write_u16(data, offset, synthetic_optional_magic(machine))?;
    write_byte(data, offset + 2, 14)?;
    write_u32(data, offset + 16, entry_point)?;
    write_u32(data, offset + 20, 0x1000)?;

    if is_pe32 {
        write_u32(data, offset + 24, 0x2000)?;
        write_u32(data, offset + 28, checked_u32(image_base, "writing PE32 image base")?)?;
    } else {
        write_u64(data, offset + 24, image_base)?;
    }

    write_u32(data, offset + 32, 0x1000)?;
    write_u32(data, offset + 36, 0x200)?;
    write_u16(data, offset + 40, 6)?;
    write_u16(data, offset + 42, 0)?;
    write_u16(data, offset + 48, 6)?;
    write_u16(data, offset + 50, 0)?;
    write_u32(data, offset + 56, image_size)?;
    write_u32(data, offset + 60, size_of_headers)?;
    write_u16(data, offset + 68, 2)?;
    write_u16(data, offset + 70, 0x8160)?;

    if is_pe32 {
        write_u32(data, offset + 72, 0x100000)?;
        write_u32(data, offset + 76, 0x1000)?;
        write_u32(data, offset + 80, 0x100000)?;
        write_u32(data, offset + 84, 0x1000)?;
        write_u32(data, offset + 92, 16)?;
    } else {
        write_u64(data, offset + 72, 0x100000)?;
        write_u64(data, offset + 80, 0x1000)?;
        write_u64(data, offset + 88, 0x100000)?;
        write_u64(data, offset + 96, 0x1000)?;
        write_u32(data, offset + 108, 16)?;
    }

    Ok(())
}

fn write_synthetic_section_header(
    data: &mut [u8],
    offset: usize,
    section: &SectionInfo,
) -> Result<(), FormatError> {
    let mut name = [0u8; 8];
    let name_bytes = section.name.as_bytes();
    let name_len = name_bytes.len().min(8);

    name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    write_bytes(data, offset, &name)?;
    write_u32(data, offset + 8, section.virtual_size)?;
    write_u32(data, offset + 12, section.virtual_address)?;
    write_u32(data, offset + 16, align_up_u32(section_size(section), 0x200, "aligning PE section raw size")?)?;
    write_u32(data, offset + 20, section.virtual_address)?;
    write_u32(data, offset + 36, section.characteristics)?;

    Ok(())
}

fn find_bytes(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    data.get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

fn write_byte(data: &mut [u8], offset: usize, value: u8) -> Result<(), FormatError> {
    *data.get_mut(offset).ok_or(FormatError::Overflow("writing synthesized PE byte"))? = value;
    Ok(())
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<(), FormatError> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<(), FormatError> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<(), FormatError> {
    write_bytes(data, offset, &value.to_le_bytes())
}

fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> Result<(), FormatError> {
    let end = offset
        .checked_add(value.len())
        .ok_or(FormatError::Overflow("writing synthesized PE data"))?;
    data.get_mut(offset..end)
        .ok_or(FormatError::Overflow("writing synthesized PE data"))?
        .copy_from_slice(value);
    Ok(())
}

fn checked_u32(value: u64, context: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::Overflow(context))
}

fn align_up_u32(value: u32, alignment: u32, context: &'static str) -> Result<u32, FormatError> {
    if alignment == 0 {
        return Err(FormatError::Overflow(context));
    }

    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(FormatError::Overflow(context))
}

fn align_up_usize(value: usize, alignment: usize, context: &'static str) -> Result<usize, FormatError> {
    if alignment == 0 {
        return Err(FormatError::Overflow(context));
    }

    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(FormatError::Overflow(context))
}

#[cfg(test)]
#[path = "tests/format.rs"]
mod tests;
