use crate::pe::format::{self, FormatError, SyntheticImage};
use crate::pe::image::SectionInfo;
use crate::sysapi::MemoryRegion;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};
use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

mod directories;
pub use directories::{DirectoryRecovery, DirectoryRecoveryStatus, DirectoryCheck, CheckStatus};

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Image(#[from] crate::pe::image::Error),
    #[error("invalid memory-region layout: {0}")]
    RegionLayout(&'static str),
    #[error("source optional header is missing, truncated, or incompatible")]
    OptionalHeader,
}

/// Source of section-layout evidence used for synthetic header reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum SectionSource {
    /// Sections came from surviving PE headers.
    Headers,
    /// Sections were supplied explicitly by the caller.
    Hints,
    /// Sections were inferred from memory-region boundaries and protections.
    MemoryRegions,
}

pub fn synthesize_from_regions(
    raw_data: &[u8],
    allocation_base: u64,
    regions: &[MemoryRegion],
    machine: &str,
    is_dll: bool,
    entry_point_rva: Option<u32>,
) -> Result<SyntheticImage, HeaderError> {
    let end = allocation_base.checked_add(raw_data.len() as u64)
        .ok_or(HeaderError::RegionLayout("allocation range overflow"))?;
    let mut regions = regions.iter().filter(|region| {
        region.is_committed() && region.allocation_base == allocation_base
            && region.base_address < end && region.end_address() > allocation_base
    }).collect::<Vec<_>>();
    regions.sort_by_key(|region| region.base_address);
    if regions.is_empty() || regions.len() > format::MAX_SECTIONS {
        return Err(HeaderError::RegionLayout("expected 1..96 committed regions"));
    }
    // Reserve whole pages before the original allocation. No captured bytes are used as header slack.
    // Lowering ImageBase by the same amount preserves the VA of every original byte.
    let header_prefix = ((0x188 + regions.len() * format::SECTION_HEADER_SIZE + 0xfff) & !0xfff) as u32;
    let image_base = allocation_base.checked_sub(header_prefix as u64)
        .ok_or(HeaderError::RegionLayout("no address space before allocation for headers"))?;
    let total = raw_data.len().checked_add(header_prefix as usize)
        .filter(|size| *size <= u32::MAX as usize - 0xfff)
        .ok_or(HeaderError::RegionLayout("image exceeds PE size limits"))?;
    let mut previous_end = allocation_base;
    let mut sections = Vec::new();
    for (index, region) in regions.iter().enumerate() {
        let start = region.base_address.max(allocation_base);
        let stop = region.end_address().min(end);
        if start < previous_end || (start - allocation_base) % 0x1000 != 0 {
            return Err(HeaderError::RegionLayout("overlapping or non-page-aligned regions"));
        }
        previous_end = stop;
        let virtual_address = (start - allocation_base) as u32 + header_prefix;
        let size = (stop - start) as u32;
        sections.push(SectionInfo {
            name: format!(".mem{index:02}"), virtual_address, virtual_size: size,
            raw_offset: virtual_address, raw_size: size,
            characteristics: region_characteristics(region.protect),
        });
    }
    let entry_point = match entry_point_rva.filter(|rva| *rva != 0) {
        Some(rva) if (rva as usize) < raw_data.len() => rva.checked_add(header_prefix)
            .ok_or(HeaderError::RegionLayout("entry point overflow"))?,
        Some(_) => return Err(HeaderError::RegionLayout("entry point outside allocation")),
        None => 0,
    };
    let mut data = vec![0; total];
    data[header_prefix as usize..].copy_from_slice(raw_data);
    let mut image = format::synthesize_mapped_image(
        &data, image_base, &sections, Some(machine), is_dll, Some(entry_point), Some(total as u32),
    )?;
    image.header_prefix = header_prefix;
    Ok(image)
}

fn region_characteristics(protect: u32) -> u32 {
    let protect = protect & 0xff;
    let mut flags = format::IMAGE_SCN_CNT_INITIALIZED_DATA;
    if matches!(protect, PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) {
        flags |= format::IMAGE_SCN_MEM_EXECUTE;
    }
    if matches!(protect, PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) {
        flags |= format::IMAGE_SCN_MEM_READ;
    }
    if matches!(protect, PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) {
        flags |= format::IMAGE_SCN_MEM_WRITE;
    }
    flags
}
