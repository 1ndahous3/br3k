use std::ops::Range;

use crate::pe::image::{Error, Image};
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Inferred storage layout of an embedded PE candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum EmbeddedImageLayout {
    /// Candidate bytes are consistent with file layout.
    File,
    /// Candidate bytes are consistent with mapped layout.
    Mapped,
    /// Evidence does not distinguish file and mapped interpretations.
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbeddedImage {
    pub offset: usize,
    pub file_size: usize,
    pub mapped_size: u32,
    pub machine: u16,
    pub layout: EmbeddedImageLayout,
    pub resource_backed: bool,
}

impl EmbeddedImage {
    pub fn excluded_from_parent(&self) -> bool {
        self.layout == EmbeddedImageLayout::File
    }
}

impl Image {
    pub fn embedded_images(&self) -> Result<Vec<EmbeddedImage>, Error> {
        scan(self, false)
    }

    pub fn mapped_embedded_images(&self) -> Result<Vec<EmbeddedImage>, Error> {
        scan(self, true)
    }
}

fn scan(image: &Image, mapped: bool) -> Result<Vec<EmbeddedImage>, Error> {
    let resources = if mapped { image.mapped_resource_data_entries() } else { image.resource_data_entries() };
    let resource_ranges = resources.unwrap_or_default().into_iter().filter_map(|entry| {
        let offset = if mapped { entry.data_rva as usize } else { image.rva_to_file_offset(entry.data_rva).ok()? };
        Some(offset..offset.checked_add(entry.size as usize)?)
    }).collect::<Vec<_>>();
    let mut candidates = Vec::new();
    let mut offset = image.size_of_headers() as usize;
    while offset.saturating_add(0x40) <= image.data().len() {
        let Some(relative) = image.data()[offset..].windows(2).position(|bytes| bytes == b"MZ") else { break };
        offset += relative;
        if let Some(candidate) = inspect(image.data(), offset, &resource_ranges) {
            // A confirmed embedded file owns its contents; nested files can be inspected separately.
            offset += if candidate.excluded_from_parent() { candidate.file_size } else { 2 };
            candidates.push(candidate);
        } else {
            offset += 2;
        }
    }
    Ok(candidates)
}

fn inspect(data: &[u8], offset: usize, resources: &[Range<usize>]) -> Option<EmbeddedImage> {
    let data = data.get(offset..)?;
    let nt = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let file_header = nt.checked_add(4)?;
    let file_data = data.get(file_header..file_header.checked_add(20)?)?;
    let optional_size = u16::from_le_bytes(file_data[16..18].try_into().ok()?) as usize;
    let count = u16::from_le_bytes(file_data[2..4].try_into().ok()?) as usize;
    if count == 0 || count > 96 { return None; }
    let header_end = file_header.checked_add(20)?.checked_add(optional_size)?.checked_add(count * 40)?;
    // Parse only headers; scanning repeated signatures must not clone the remaining parent image.
    let header = Image::parse(data.get(..header_end)?.to_vec()).ok()?;
    let headers_size = header.size_of_headers() as usize;
    let mapped_size = header.image_size().ok()?;
    if headers_size < header_end || headers_size > data.len() || mapped_size < headers_size as u32 { return None; }
    let sections = header.sections().ok()?;
    let mut file_size = headers_size;
    let mut raw_ranges = Vec::new();
    let mut virtual_ranges = Vec::new();
    for section in sections {
        let virtual_end = section.virtual_address.checked_add(section.virtual_size.max(section.raw_size))?;
        if section.virtual_address < headers_size as u32 || virtual_end > mapped_size { return None; }
        virtual_ranges.push(section.virtual_address..virtual_end);
        if section.raw_size != 0 {
            let start = section.raw_offset as usize;
            let end = start.checked_add(section.raw_size as usize)?;
            if start < headers_size { return None; }
            raw_ranges.push(start..end);
            file_size = file_size.max(end);
        }
    }
    raw_ranges.sort_by_key(|range| range.start);
    virtual_ranges.sort_by_key(|range| range.start);
    if raw_ranges.windows(2).any(|pair| pair[0].end > pair[1].start)
        || virtual_ranges.windows(2).any(|pair| pair[0].end > pair[1].start) { return None; }
    let file_fits = file_size <= data.len();
    let mapped_fits = mapped_size as usize <= data.len();
    let resource_backed = file_fits && resources.iter().any(|range| range.start == offset && file_size <= range.end - range.start);
    let layout = match (file_fits, mapped_fits, resource_backed) {
        (true, _, true) | (true, false, _) => EmbeddedImageLayout::File,
        (false, true, _) => EmbeddedImageLayout::Mapped,
        (true, true, _) => EmbeddedImageLayout::Ambiguous,
        _ => return None,
    };
    Some(EmbeddedImage { offset, file_size, mapped_size, machine: header.machine(), layout, resource_backed })
}

pub(crate) fn mapped_exclusions(data: &[u8]) -> Vec<Range<usize>> {
    Image::parse(data.to_vec()).ok().and_then(|image| image.mapped_embedded_images().ok())
        .unwrap_or_default().into_iter().filter(EmbeddedImage::excluded_from_parent)
        .map(|image| image.offset..image.offset + image.file_size).collect()
}

pub(crate) fn intersects(ranges: &[Range<usize>], offset: usize, size: usize) -> bool {
    ranges.iter().any(|range| offset < range.end && offset.saturating_add(size) > range.start)
}

pub(crate) fn included_ranges(range: Range<usize>, excluded: &[Range<usize>]) -> Vec<Range<usize>> {
    let mut result = Vec::new();
    let mut start = range.start;
    for skip in excluded {
        if skip.end <= start || skip.start >= range.end { continue; }
        if start < skip.start { result.push(start..skip.start.min(range.end)); }
        start = start.max(skip.end);
    }
    if start < range.end { result.push(start..range.end); }
    result
}
