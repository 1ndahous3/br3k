use crate::pe::format::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE, PE_DIRECTORY_ENTRY_BASERELOC,
};
use crate::pe::image::{DataDirectory, Error as ImageError, Format, Image, SectionInfo};

use std::collections::BTreeMap;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

#[derive(Debug, thiserror::Error)]
pub enum RelocationError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("PE relocation table is missing")]
    TableMissing,
    #[error("relocation model does not contain any RVAs")]
    EmptyRelocationModel,
    #[error("relocation RVA 0x{rva:x} with pointer size {pointer_size} is outside image size 0x{image_size:x}")]
    RelocationRvaOutOfBounds {
        rva: u32,
        pointer_size: usize,
        image_size: u32,
    },
    #[error("invalid PE relocation block at directory offset 0x{offset:x}: block size is 0x{block_size:x}")]
    InvalidBlockSize { offset: usize, block_size: u32 },
    #[error("PE relocation block at directory offset 0x{offset:x} overflows directory size 0x{directory_size:x}")]
    BlockOutOfBounds {
        offset: usize,
        block_size: u32,
        directory_size: usize,
    },
    #[error("unsupported PE base relocation kind {raw_kind} at RVA 0x{rva:x}")]
    UnsupportedKind { rva: u32, raw_kind: u16 },
    #[error("relocation delta {delta} does not fit in i64")]
    DeltaOutOfRange { delta: i128 },
    #[error("rebased relocation value at RVA 0x{rva:x} is outside {bits}-bit range")]
    RelocationValueOutOfRange { rva: u32, bits: u8 },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

/// Decoded base-relocation type. Decoding a type does not imply that rebasing supports every architecture-specific form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum BaseRelocationKind {
    /// Padding entry; no relocation is applied.
    Absolute = 0,
    /// High 16-bit portion of a relocation.
    High = 1,
    /// Low 16-bit portion of a relocation.
    Low = 2,
    /// 32-bit absolute-address relocation.
    HighLow = 3,
    /// Paired high-part relocation with a signed adjustment.
    HighAdj = 4,
    /// 64-bit absolute-address relocation.
    Dir64 = 10,
    /// Raw relocation type is not represented by a recognized variant.
    Unknown = 0xffff,
}

impl BaseRelocationKind {
    pub fn from_raw(raw_kind: u16) -> Self {
        match raw_kind {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            10 => Self::Dir64,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseRelocationEntry {
    pub rva: u32,
    pub offset: u16,
    pub raw_kind: u16,
    pub kind: BaseRelocationKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseRelocationBlock {
    pub page_rva: u32,
    pub block_size: u32,
    pub entries: Vec<BaseRelocationEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationLayout {
    File,
    MappedImage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebaseResult {
    pub image: Vec<u8>,
    pub old_image_base: u64,
    pub new_image_base: u64,
    pub delta: i64,
    pub block_count: usize,
    pub entry_count: usize,
    pub applied_count: usize,
    pub skipped_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocationBuild {
    pub image: Vec<u8>,
    pub section_rva: u32,
    pub section_size: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub block_count: usize,
    pub entry_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocationCandidate {
    pub rva: u32,
    pub offset: usize,
    pub value: u64,
    pub target_rva: u32,
    pub section_name: Option<String>,
    pub target_section_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelocationDiscovery {
    pub image_base: u64,
    pub image_size: u32,
    pub pointer_size: usize,
    pub candidates: Vec<RelocationCandidate>,
}

impl RelocationDiscovery {
    pub fn rvas(&self) -> Vec<u32> {
        self.candidates
            .iter()
            .map(|candidate| candidate.rva)
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RelocationTable {
    data: Vec<u8>,
    block_count: usize,
    entry_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelocationScanRange {
    rva: u32,
    offset: usize,
    size: usize,
}

impl Image {
    pub fn base_relocations(&self) -> Result<Vec<BaseRelocationBlock>, RelocationError> {
        base_relocations_with_layout(self, RelocationLayout::File)
    }

    pub fn mapped_base_relocations(&self) -> Result<Vec<BaseRelocationBlock>, RelocationError> {
        base_relocations_with_layout(self, RelocationLayout::MappedImage)
    }

    pub fn rebase(&self, new_image_base: u64) -> Result<RebaseResult, RelocationError> {
        rebase_with_layout(self, new_image_base, RelocationLayout::File)
    }

    pub fn rebase_mapped(&self, new_image_base: u64) -> Result<RebaseResult, RelocationError> {
        rebase_with_layout(self, new_image_base, RelocationLayout::MappedImage)
    }

    pub fn build_relocation_table(&self, relocation_rvas: &[u32]) -> Result<Vec<u8>, RelocationError> {
        Ok(build_relocation_table(self, relocation_rvas)?.data)
    }

    pub fn add_relocations(
        &self,
        relocation_rvas: &[u32],
        section_name: &str,
    ) -> Result<RelocationBuild, RelocationError> {
        let table = build_relocation_table(self, relocation_rvas)?;
        let mut image = Image::parse(self.data().to_vec())?;
        let section = image.append_section_with_characteristics(
            section_name,
            table.data.len(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )?;
        image.write_bytes(section.raw_offset, &table.data)?;

        let directory_size = u32::try_from(table.data.len())
            .map_err(|_| RelocationError::Overflow("converting relocation table size to u32"))?;
        image.set_data_directory(PE_DIRECTORY_ENTRY_BASERELOC, section.virtual_address, directory_size)?;

        Ok(RelocationBuild {
            image: image.into_data(),
            section_rva: section.virtual_address,
            section_size: directory_size,
            directory_rva: section.virtual_address,
            directory_size,
            block_count: table.block_count,
            entry_count: table.entry_count,
        })
    }

    pub fn relocation_candidates(&self) -> Result<RelocationDiscovery, RelocationError> {
        discover_relocations_with_layout(self, RelocationLayout::File)
    }

    pub fn mapped_relocation_candidates(&self) -> Result<RelocationDiscovery, RelocationError> {
        discover_relocations_with_layout(self, RelocationLayout::MappedImage)
    }

    pub fn add_discovered_relocations(&self, section_name: &str) -> Result<RelocationBuild, RelocationError> {
        let discovery = self.relocation_candidates()?;

        self.add_relocations(&discovery.rvas(), section_name)
    }

    pub fn add_mapped_discovered_relocations(&self, section_name: &str) -> Result<RelocationBuild, RelocationError> {
        let discovery = self.mapped_relocation_candidates()?;

        self.add_relocations(&discovery.rvas(), section_name)
    }
}

pub fn base_relocations_with_layout(
    image: &Image,
    layout: RelocationLayout,
) -> Result<Vec<BaseRelocationBlock>, RelocationError> {
    let Some(directory) = relocation_directory(image)? else {
        return Ok(Vec::new());
    };
    let directory_data = read_directory_data(image, directory, layout)?;

    parse_relocation_blocks(&directory_data)
}

pub fn rebase_with_layout(
    image: &Image,
    new_image_base: u64,
    layout: RelocationLayout,
) -> Result<RebaseResult, RelocationError> {
    let old_image_base = match layout { RelocationLayout::File => image.image_base()?, RelocationLayout::MappedImage => image.address_base()? };
    let delta_i128 = i128::from(new_image_base) - i128::from(old_image_base);
    let delta = i64::try_from(delta_i128)
        .map_err(|_| RelocationError::DeltaOutOfRange { delta: delta_i128 })?;

    if delta == 0 {
        return Ok(RebaseResult {
            image: image.data().to_vec(),
            old_image_base,
            new_image_base,
            delta,
            block_count: 0,
            entry_count: 0,
            applied_count: 0,
            skipped_count: 0,
        });
    }

    let blocks = base_relocations_with_layout(image, layout)?;
    if blocks.is_empty() {
        return Err(RelocationError::TableMissing);
    }

    let mut output = image.clone();
    let mut entry_count = 0;
    let mut applied_count = 0;
    let mut skipped_count = 0;

    for block in &blocks {
        for entry in &block.entries {
            entry_count += 1;
            match entry.kind {
                BaseRelocationKind::Absolute => skipped_count += 1,
                BaseRelocationKind::HighLow => {
                    let offset = offset_for_rva(&output, entry.rva, 4, layout)?;
                    let value = output.read_u32(offset)?;
                    let updated = checked_add_u32(value, delta_i128, entry.rva)?;
                    output.write_u32(offset, updated)?;
                    applied_count += 1;
                }
                BaseRelocationKind::Dir64 => {
                    let offset = offset_for_rva(&output, entry.rva, 8, layout)?;
                    let value = output.read_u64(offset)?;
                    let updated = checked_add_u64(value, delta_i128, entry.rva)?;
                    output.write_pointer(offset, 8, updated)?;
                    applied_count += 1;
                }
                _ => {
                    return Err(RelocationError::UnsupportedKind {
                        rva: entry.rva,
                        raw_kind: entry.raw_kind,
                    });
                }
            }
        }
    }

    write_image_base(&mut output, new_image_base)?;

    Ok(RebaseResult {
        image: output.into_data(),
        old_image_base,
        new_image_base,
        delta,
        block_count: blocks.len(),
        entry_count,
        applied_count,
        skipped_count,
    })
}

fn build_relocation_table(
    image: &Image,
    relocation_rvas: &[u32],
) -> Result<RelocationTable, RelocationError> {
    let pointer_size = image.pointer_size();
    let image_size = image.image_size()?;
    let kind = match image.format() {
        Format::Pe32 => BaseRelocationKind::HighLow,
        Format::Pe64 => BaseRelocationKind::Dir64,
    };
    let raw_kind = kind as u16;
    let mut pages = BTreeMap::<u32, Vec<u16>>::new();

    for &rva in relocation_rvas {
        validate_relocation_rva(rva, pointer_size, image_size)?;

        let page_rva = rva & !0xfff;
        let offset = (rva - page_rva) as u16;
        pages.entry(page_rva).or_default().push(offset);
    }

    if pages.is_empty() {
        return Err(RelocationError::EmptyRelocationModel);
    }

    let mut data = Vec::new();
    let mut entry_count = 0usize;

    for (page_rva, offsets) in pages.iter_mut() {
        offsets.sort_unstable();
        offsets.dedup();
        entry_count = entry_count
            .checked_add(offsets.len())
            .ok_or(RelocationError::Overflow("counting synthetic relocations"))?;

        let needs_padding = offsets.len() % 2 != 0;
        let padded_entry_count = if needs_padding {
            offsets.len()
                .checked_add(1)
                .ok_or(RelocationError::Overflow("padding synthetic relocation block"))?
        } else {
            offsets.len()
        };
        let block_size = 8usize
            .checked_add(
                padded_entry_count
                    .checked_mul(2)
                    .ok_or(RelocationError::Overflow("sizing synthetic relocation block"))?,
            )
            .ok_or(RelocationError::Overflow("sizing synthetic relocation block"))?;
        let block_size_u32 = u32::try_from(block_size)
            .map_err(|_| RelocationError::Overflow("converting relocation block size to u32"))?;

        push_u32(&mut data, *page_rva);
        push_u32(&mut data, block_size_u32);
        for offset in offsets.iter() {
            push_u16(&mut data, (raw_kind << 12) | *offset);
        }
        if needs_padding {
            push_u16(&mut data, BaseRelocationKind::Absolute as u16);
        }
    }

    Ok(RelocationTable {
        block_count: pages.len(),
        entry_count,
        data,
    })
}

pub fn discover_relocations_with_layout(
    image: &Image,
    layout: RelocationLayout,
) -> Result<RelocationDiscovery, RelocationError> {
    let image_base = match layout { RelocationLayout::File => image.image_base()?, RelocationLayout::MappedImage => image.address_base()? };
    let image_size = image.image_size()?;
    let image_end = image_base
        .checked_add(image_size as u64)
        .ok_or(RelocationError::Overflow("computing PE image address range"))?;
    let pointer_size = image.pointer_size();
    let sections = image.sections()?;
    let mut candidates = Vec::new();

    for section in &sections {
        if !section_is_relocation_scan_candidate(section) {
            continue;
        }

        let Some(range) = relocation_scan_range(image, section, layout)? else {
            continue;
        };
        let mut offset = aligned_pointer_scan_start(range.offset, range.rva, pointer_size)?;
        let range_end = range
            .offset
            .checked_add(range.size)
            .ok_or(RelocationError::Overflow("scanning relocation candidates"))?;

        while offset.checked_add(pointer_size).is_some_and(|end| end <= range_end) {
            let rva = range
                .rva
                .checked_add(u32::try_from(offset - range.offset)
                    .map_err(|_| RelocationError::Overflow("computing relocation candidate RVA"))?)
                .ok_or(RelocationError::Overflow("computing relocation candidate RVA"))?;
            let value = read_pointer(image.data(), offset, pointer_size)?;

            if value >= image_base && value < image_end {
                let target_rva = u32::try_from(value - image_base)
                    .map_err(|_| RelocationError::Overflow("computing relocation target RVA"))?;

                candidates.push(RelocationCandidate {
                    rva,
                    offset,
                    value,
                    target_rva,
                    section_name: Some(section.name.clone()),
                    target_section_name: section_name_for_rva(&sections, target_rva),
                });
            }

            offset = offset
                .checked_add(pointer_size)
                .ok_or(RelocationError::Overflow("scanning relocation candidates"))?;
        }
    }

    candidates.sort_by_key(|candidate| candidate.rva);
    candidates.dedup_by_key(|candidate| candidate.rva);

    Ok(RelocationDiscovery {
        image_base,
        image_size,
        pointer_size,
        candidates,
    })
}

fn section_is_relocation_scan_candidate(section: &SectionInfo) -> bool {
    section.characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE) != 0
}

fn relocation_scan_range(
    image: &Image,
    section: &SectionInfo,
    layout: RelocationLayout,
) -> Result<Option<RelocationScanRange>, RelocationError> {
    let (rva, offset, requested_size) = match layout {
        RelocationLayout::File => {
            if section.raw_size == 0 {
                return Ok(None);
            }

            (section.virtual_address, section.raw_offset as usize, section.raw_size as usize)
        }
        RelocationLayout::MappedImage => {
            let section_size = crate::pe::format::section_size(section);
            if section_size == 0 {
                return Ok(None);
            }

            (section.virtual_address, section.virtual_address as usize, section_size as usize)
        }
    };

    if offset >= image.data().len() {
        return Ok(None);
    }

    let requested_end = offset
        .checked_add(requested_size)
        .ok_or(RelocationError::Overflow("sizing relocation scan range"))?;
    let end = requested_end.min(image.data().len());

    Ok(Some(RelocationScanRange {
        rva,
        offset,
        size: end - offset,
    }))
}

fn aligned_pointer_scan_start(
    offset: usize,
    rva: u32,
    pointer_size: usize,
) -> Result<usize, RelocationError> {
    let alignment = pointer_size as u32;
    let misalignment = rva % alignment;
    if misalignment == 0 {
        return Ok(offset);
    }

    offset
        .checked_add((alignment - misalignment) as usize)
        .ok_or(RelocationError::Overflow("aligning relocation scan range"))
}

fn read_pointer(
    data: &[u8],
    offset: usize,
    pointer_size: usize,
) -> Result<u64, RelocationError> {
    match pointer_size {
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(checked_range(data, offset, 4)?);
            Ok(u32::from_le_bytes(bytes) as u64)
        }
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(checked_range(data, offset, 8)?);
            Ok(u64::from_le_bytes(bytes))
        }
        _ => Err(RelocationError::Overflow("reading PE pointer with unsupported size")),
    }
}

fn section_name_for_rva(
    sections: &[SectionInfo],
    rva: u32,
) -> Option<String> {
    sections
        .iter()
        .find(|section| {
            let size = crate::pe::format::section_size(section);
            let end = section.virtual_address.saturating_add(size);

            rva >= section.virtual_address && rva < end
        })
        .map(|section| section.name.clone())
}

fn validate_relocation_rva(
    rva: u32,
    pointer_size: usize,
    image_size: u32,
) -> Result<(), RelocationError> {
    let end = rva
        .checked_add(pointer_size as u32)
        .ok_or(RelocationError::Overflow("checking relocation RVA"))?;
    if end > image_size {
        return Err(RelocationError::RelocationRvaOutOfBounds {
            rva,
            pointer_size,
            image_size,
        });
    }

    Ok(())
}

fn relocation_directory(image: &Image) -> Result<Option<DataDirectory>, RelocationError> {
    match image.data_directory(PE_DIRECTORY_ENTRY_BASERELOC) {
        Ok(directory) if directory.is_empty() => Ok(None),
        Ok(directory) => Ok(Some(directory)),
        Err(ImageError::DataDirectoryMissing { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_directory_data(
    image: &Image,
    directory: DataDirectory,
    layout: RelocationLayout,
) -> Result<Vec<u8>, RelocationError> {
    let size = directory.size as usize;
    match layout {
        RelocationLayout::File => Ok(image.read_bytes_rva(directory.virtual_address, size)?),
        RelocationLayout::MappedImage => Ok(image.read_mapped_bytes_rva(directory.virtual_address, size)?),
    }
}

fn parse_relocation_blocks(data: &[u8]) -> Result<Vec<BaseRelocationBlock>, RelocationError> {
    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let page_rva = read_u32(data, offset)?;
        let block_size = read_u32(data, offset + 4)?;
        if page_rva == 0 && block_size == 0 {
            break;
        }
        if block_size < 8 || (block_size - 8) % 2 != 0 {
            return Err(RelocationError::InvalidBlockSize { offset, block_size });
        }

        let block_size_usize = block_size as usize;
        let block_end = offset
            .checked_add(block_size_usize)
            .ok_or(RelocationError::Overflow("walking PE relocation blocks"))?;
        if block_end > data.len() {
            return Err(RelocationError::BlockOutOfBounds {
                offset,
                block_size,
                directory_size: data.len(),
            });
        }

        let mut entries = Vec::with_capacity((block_size_usize - 8) / 2);
        for entry_offset in (offset + 8..block_end).step_by(2) {
            let encoded = read_u16(data, entry_offset)?;
            let raw_kind = encoded >> 12;
            let entry_offset_in_page = encoded & 0x0fff;
            let rva = page_rva
                .checked_add(u32::from(entry_offset_in_page))
                .ok_or(RelocationError::Overflow("computing PE relocation entry RVA"))?;

            entries.push(BaseRelocationEntry {
                rva,
                offset: entry_offset_in_page,
                raw_kind,
                kind: BaseRelocationKind::from_raw(raw_kind),
            });
        }

        blocks.push(BaseRelocationBlock {
            page_rva,
            block_size,
            entries,
        });
        offset = block_end;
    }

    Ok(blocks)
}

fn offset_for_rva(
    image: &Image,
    rva: u32,
    size: usize,
    layout: RelocationLayout,
) -> Result<usize, RelocationError> {
    match layout {
        RelocationLayout::File => Ok(image.rva_to_file_offset(rva)?),
        RelocationLayout::MappedImage => {
            let offset = rva as usize;
            let end = offset
                .checked_add(size)
                .ok_or(RelocationError::Overflow("checking mapped relocation target"))?;

            if image.data().get(offset..end).is_none() {
                return Err(ImageError::OutOfBounds { offset, size }.into());
            }

            Ok(offset)
        }
    }
}

fn checked_add_u32(value: u32, delta: i128, rva: u32) -> Result<u32, RelocationError> {
    let updated = i128::from(value) + delta;
    u32::try_from(updated)
        .map_err(|_| RelocationError::RelocationValueOutOfRange { rva, bits: 32 })
}

fn checked_add_u64(value: u64, delta: i128, rva: u32) -> Result<u64, RelocationError> {
    let updated = i128::from(value) + delta;
    u64::try_from(updated)
        .map_err(|_| RelocationError::RelocationValueOutOfRange { rva, bits: 64 })
}

fn write_image_base(image: &mut Image, image_base: u64) -> Result<(), RelocationError> {
    match image.format() {
        Format::Pe32 => {
            let image_base = u32::try_from(image_base)
                .map_err(|_| RelocationError::RelocationValueOutOfRange { rva: 0, bits: 32 })?;
            image.write_u32(image.optional_header_offset() + 28, image_base)?;
        }
        Format::Pe64 => {
            image.write_pointer(image.optional_header_offset() + 24, 8, image_base)?;
        }
    }

    Ok(())
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, RelocationError> {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(checked_range(data, offset, 2)?);
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, RelocationError> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(checked_range(data, offset, 4)?);
    Ok(u32::from_le_bytes(bytes))
}

fn push_u16(data: &mut Vec<u8>, value: u16) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(data: &mut Vec<u8>, value: u32) {
    data.extend_from_slice(&value.to_le_bytes());
}

fn checked_range(
    data: &[u8],
    offset: usize,
    size: usize,
) -> Result<&[u8], RelocationError> {
    let end = offset
        .checked_add(size)
        .ok_or(RelocationError::Overflow("checking PE relocation range"))?;

    data.get(offset..end)
        .ok_or(RelocationError::BlockOutOfBounds {
            offset,
            block_size: size as u32,
            directory_size: data.len(),
        })
}

#[cfg(test)]
#[path = "tests/relocations.rs"]
mod tests;
