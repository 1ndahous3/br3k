use super::*;
use crate::pe::embedded;
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

const MAX_SCAN_BYTES: usize = 64 * 1024 * 1024;
const MAX_CANDIDATES: usize = 128;
const MAX_CANDIDATE_DESCRIPTORS: usize = 256;

/// Outcome and source of delay-import recovery analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum DelayImportRecoveryStatus {
    /// Usable delay imports were found through the declared directory.
    Declared,
    /// A candidate directory was found by bounded scanning.
    Discovered,
    /// No usable delay-import candidate was found.
    NotFound,
    /// Multiple candidates remain; no unique directory was selected.
    Ambiguous,
    /// Scanning reached a configured safety bound.
    ScanLimit,
    /// Recovery evidence came from a validated reference image.
    FromSource,
    /// Image structure prevented reliable delay-import recovery.
    InvalidImage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayImportCandidate {
    pub directory_rva: u32,
    pub directory_size: u32,
    pub descriptors: Vec<DelayImportDescriptor>,
    source: Option<SourceDescriptors>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceDescriptors {
    data: Vec<u8>,
    machine: u16,
    timestamp: u32,
    image_size: u32,
}

#[derive(Clone, Debug)]
pub struct DelayImportRecovery {
    pub status: DelayImportRecoveryStatus,
    pub candidates: Vec<DelayImportCandidate>,
    pub scanned_bytes: usize,
    pub diagnostic: Option<String>,
}

impl DelayImportRecovery {
    pub fn selected(&self) -> Option<&DelayImportCandidate> {
        if matches!(self.status, DelayImportRecoveryStatus::Declared | DelayImportRecoveryStatus::Discovered | DelayImportRecoveryStatus::FromSource) {
            self.candidates.first()
        } else {
            None
        }
    }
}

impl Image {
    pub fn recover_delay_imports_from(&self, source: &Image) -> Result<DelayImportRecovery, DelayImportError> {
        recover_from(self, DelayImportLayout::File, source)
    }

    pub fn recover_mapped_delay_imports_from(&self, source: &Image) -> Result<DelayImportRecovery, DelayImportError> {
        recover_from(self, DelayImportLayout::MappedImage, source)
    }

    pub fn recover_delay_imports(&self) -> Result<DelayImportRecovery, DelayImportError> {
        recover(self, DelayImportLayout::File)
    }

    pub fn recover_mapped_delay_imports(&self) -> Result<DelayImportRecovery, DelayImportError> {
        recover(self, DelayImportLayout::MappedImage)
    }

    pub fn restore_delay_imports(&self, recovery: &DelayImportRecovery) -> Result<Vec<u8>, DelayImportError> {
        restore(self, recovery, DelayImportLayout::File)
    }

    pub fn restore_mapped_delay_imports(&self, recovery: &DelayImportRecovery) -> Result<Vec<u8>, DelayImportError> {
        restore(self, recovery, DelayImportLayout::MappedImage)
    }
}

fn restore(image: &Image, recovery: &DelayImportRecovery, layout: DelayImportLayout) -> Result<Vec<u8>, DelayImportError> {
    let candidate = recovery.selected().ok_or(DelayImportError::NoUniqueCandidate)?;
    let directory = DataDirectory { virtual_address: candidate.directory_rva, size: candidate.directory_size };
    let mut restored = Image::parse(image.data().to_vec())?;
    if let Some(source) = &candidate.source {
        if source.machine != image.machine() || source.timestamp != image.time_date_stamp()? || source.image_size != image.image_size()? {
            return Err(DelayImportError::SourceMismatch);
        }
        let previous = read_rva_bytes(image, directory.virtual_address, source.data.len(), layout)?;
        if previous != source.data && previous.iter().any(|byte| *byte != 0) { return Err(DelayImportError::SourceMismatch); }
        let offset = match layout {
            DelayImportLayout::File => restored.rva_to_file_offset(directory.virtual_address)?,
            DelayImportLayout::MappedImage => directory.virtual_address as usize,
        };
        restored.write_bytes(offset, &source.data)?;
    }
    let descriptors = read_directory(&restored, layout, directory)?;
    if descriptors != candidate.descriptors { return Err(DelayImportError::NoUniqueCandidate); }
    restored.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, candidate.directory_rva, candidate.directory_size)?;
    Ok(restored.into_data())
}

fn recover(image: &Image, layout: DelayImportLayout) -> Result<DelayImportRecovery, DelayImportError> {
    let mut report = DelayImportRecovery {
        status: DelayImportRecoveryStatus::NotFound, candidates: Vec::new(), scanned_bytes: 0, diagnostic: None,
    };
    match delay_import_directory(image).and_then(|directory| {
        directory.map(|directory| read_directory(image, layout, directory).map(|descriptors| DelayImportCandidate {
            directory_rva: directory.virtual_address, directory_size: directory.size, descriptors, source: None,
        })).transpose()
    }) {
        Ok(Some(candidate)) if !candidate.descriptors.is_empty() => {
            report.status = DelayImportRecoveryStatus::Declared;
            report.candidates.push(candidate);
            return Ok(report);
        }
        Ok(_) => {}
        Err(error) => report.diagnostic = Some(error.to_string()),
    }
    let excluded = match layout {
        DelayImportLayout::MappedImage => embedded::mapped_exclusions(image.data()),
        DelayImportLayout::File => image.embedded_images()?.into_iter().map(|item| item.offset..item.offset + item.file_size).collect(),
    };
    let mut sections = image.sections()?;
    sections.sort_by_key(|section| section.virtual_address);
    let mut scanned_end = 0u64;
    let mut incomplete = false;
    for section in sections {
        let (offset, size) = match layout {
            DelayImportLayout::File => (section.raw_offset as usize, section.raw_size as usize),
            DelayImportLayout::MappedImage => (section.virtual_address as usize, section.virtual_size.max(section.raw_size) as usize),
        };
        let Some(available) = image.data().get(offset..) else { incomplete = true; continue };
        let length = size.min(available.len()).min(image.image_size()?.saturating_sub(section.virtual_address) as usize);
        incomplete |= length < size;
        let length = length.min(MAX_SCAN_BYTES - report.scanned_bytes);
        let mut index = (4 - section.virtual_address as usize % 4) % 4;
        while index + DELAY_IMPORT_DESCRIPTOR_SIZE <= length {
            let rva = section.virtual_address as u64 + index as u64;
            if rva >= scanned_end && rva % 4 == 0 && !embedded::intersects(&excluded, offset + index, DELAY_IMPORT_DESCRIPTOR_SIZE) {
                if let Some(candidate) = candidate_at(image, layout, rva as u32, &available[index..length]) {
                    // Reject a candidate whose complete descriptor run intersects an embedded image.
                    if !embedded::intersects(&excluded, offset + index, candidate.directory_size as usize) {
                        index += candidate.directory_size as usize;
                        scanned_end = rva + candidate.directory_size as u64;
                        report.candidates.push(candidate);
                        if report.candidates.len() == MAX_CANDIDATES {
                            report.scanned_bytes += index;
                            report.status = DelayImportRecoveryStatus::ScanLimit;
                            return Ok(report);
                        }
                        continue;
                    }
                }
            }
            index += 4;
        }
        report.scanned_bytes += length;
        if length < size.min(available.len()) && report.scanned_bytes == MAX_SCAN_BYTES {
            report.status = DelayImportRecoveryStatus::ScanLimit;
            return Ok(report);
        }
    }
    report.status = if incomplete { DelayImportRecoveryStatus::ScanLimit } else { match report.candidates.len() {
        0 => DelayImportRecoveryStatus::NotFound,
        1 => DelayImportRecoveryStatus::Discovered,
        _ => DelayImportRecoveryStatus::Ambiguous,
    }};
    Ok(report)
}

fn candidate_at(image: &Image, layout: DelayImportLayout, rva: u32, available: &[u8]) -> Option<DelayImportCandidate> {
    let mut descriptors = Vec::new();
    for (index, bytes) in available.chunks_exact(DELAY_IMPORT_DESCRIPTOR_SIZE).take(MAX_CANDIDATE_DESCRIPTORS + 1).enumerate() {
        if bytes.iter().all(|byte| *byte == 0) {
            return (!descriptors.is_empty()).then_some(DelayImportCandidate {
                directory_rva: rva, directory_size: ((index + 1) * DELAY_IMPORT_DESCRIPTOR_SIZE) as u32, descriptors,
                source: None,
            });
        }
        if index == MAX_CANDIDATE_DESCRIPTORS || read_u32(bytes, 0).ok()? > 1 { return None; }
        if [4, 8, 12, 16].iter().any(|offset| read_u32(bytes, *offset).ok() == Some(0)) { return None; }
        let descriptor_rva = rva.checked_add((index * DELAY_IMPORT_DESCRIPTOR_SIZE) as u32)?;
        let descriptor = read_descriptor(image, bytes, index, descriptor_rva, layout).ok()?;
        let name = descriptor.dll_name.as_deref()?;
        if name.is_empty() || name.len() > 260 || !name.is_ascii() || !name.to_ascii_lowercase().ends_with(".dll")
            || name.bytes().any(|byte| byte <= b' ' || matches!(byte, b'/' | b'\\' | b':')) { return None; }
        if descriptor.imports.is_empty() { return None; }
        for function in &descriptor.imports {
            if function.name.as_ref().is_some_and(|name| name.is_empty() || !name.is_ascii() || name.bytes().any(|byte| byte <= b' ')) { return None; }
        }
        let pointer_size = image.pointer_size();
        let table_size = (descriptor.imports.len() + 1).checked_mul(pointer_size)?;
        let iat = descriptor.import_address_table_rva?;
        let int = descriptor.import_name_table_rva?;
        if iat == int { return None; }
        let handle = descriptor.module_handle_rva?;
        let mut ranges = vec![handle..handle.checked_add(pointer_size as u32)?];
        for table in [Some(iat), Some(int), descriptor.bound_import_address_table_rva, descriptor.unload_information_table_rva].into_iter().flatten() {
            let data = read_rva_bytes(image, table, table_size, layout).ok()?;
            if data[data.len() - pointer_size..].iter().any(|byte| *byte != 0) { return None; }
            if table == iat && data[..data.len() - pointer_size].chunks_exact(pointer_size).any(|entry| entry.iter().all(|byte| *byte == 0)) {
                return None;
            }
            ranges.push(table..table.checked_add(table_size as u32)?);
        }
        ranges.sort_by_key(|range| range.start);
        if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) { return None; }
        for range in ranges {
            if range.start < image.size_of_headers() { return None; }
            read_rva_bytes(image, range.start, (range.end - range.start) as usize, layout).ok()?;
        }
        descriptors.push(descriptor);
    }
    None
}

fn recover_from(image: &Image, layout: DelayImportLayout, source: &Image) -> Result<DelayImportRecovery, DelayImportError> {
    let mut report = recover(image, layout)?;
    if report.status != DelayImportRecoveryStatus::NotFound { return Ok(report); }
    let Some(directory) = delay_import_directory(source)? else { return Ok(report) };
    let timestamp = source.time_date_stamp()?;
    if matches!(timestamp, 0 | u32::MAX) || timestamp != image.time_date_stamp()? || source.machine() != image.machine()
        || source.image_size()? != image.image_size()? { return Err(DelayImportError::SourceMismatch); }
    let descriptors = source.delay_imports()?;
    if descriptors.is_empty() { return Ok(report); }
    if descriptors.iter().any(|descriptor| !descriptor.rva_based) && source.image_base()? != image.image_base()? {
        return Err(DelayImportError::SourceMismatch);
    }
    let size = (descriptors.len() + 1).checked_mul(DELAY_IMPORT_DESCRIPTOR_SIZE).ok_or(DelayImportError::SourceMismatch)?;
    if directory.virtual_address < image.size_of_headers() { return Err(DelayImportError::SourceMismatch); }
    let previous = read_rva_bytes(image, directory.virtual_address, size, layout)?;
    if previous.iter().any(|byte| *byte != 0) { return Err(DelayImportError::SourceMismatch); }
    let table = read_rva_bytes(source, directory.virtual_address, size, DelayImportLayout::File)?;
    let mut staged = Image::parse(image.data().to_vec())?;
    let offset = match layout {
        DelayImportLayout::File => staged.rva_to_file_offset(directory.virtual_address)?,
        DelayImportLayout::MappedImage => directory.virtual_address as usize,
    };
    staged.write_bytes(offset, &table)?;
    let mut candidate = candidate_at(&staged, layout, directory.virtual_address, &table).ok_or(DelayImportError::SourceMismatch)?;
    if candidate.descriptors != descriptors { return Err(DelayImportError::SourceMismatch); }
    candidate.source = Some(SourceDescriptors { data: table, machine: image.machine(), timestamp, image_size: image.image_size()? });
    report.status = DelayImportRecoveryStatus::FromSource;
    report.candidates = vec![candidate];
    Ok(report)
}
