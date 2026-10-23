use super::{fnv1a64, DiagnosticsError};
use crate::pe::format;
use crate::pe::image::{Error as ImageError, Image, SectionInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompareOptions {
    pub normalize_runtime_directories: bool,
}

impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            normalize_runtime_directories: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionComparison {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub executable: bool,
    pub mapped_hash: Option<u64>,
    pub disk_hash: Option<u64>,
    pub mapped_error: Option<String>,
    pub disk_error: Option<String>,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageComparison {
    pub sections: Vec<SectionComparison>,
}

impl ImageComparison {
    pub fn changed_count(&self) -> usize {
        self.sections
            .iter()
            .filter(|section| section.changed)
            .count()
    }

    pub fn changed_executable_count(&self) -> usize {
        self.sections
            .iter()
            .filter(|section| section.changed && section.executable)
            .count()
    }

    pub fn changed_section_names(&self) -> Vec<String> {
        self.sections
            .iter()
            .filter(|section| section.changed)
            .map(|section| section.name.clone())
            .collect()
    }

    pub fn changed_executable_section_names(&self) -> Vec<String> {
        self.sections
            .iter()
            .filter(|section| section.changed && section.executable)
            .map(|section| section.name.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteChangeOptions {
    pub normalize_runtime_directories: bool,
    pub executable_only: bool,
    pub max_ranges: usize,
    pub sample_size: usize,
}

impl Default for ByteChangeOptions {
    fn default() -> Self {
        Self {
            normalize_runtime_directories: true,
            executable_only: false,
            max_ranges: 256,
            sample_size: 16,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionByteChange {
    pub section_name: String,
    pub section_rva: u32,
    pub executable: bool,
    pub rva: u32,
    pub offset: u32,
    pub size: u32,
    pub mapped_hash: u64,
    pub disk_hash: u64,
    pub mapped_sample: Vec<u8>,
    pub disk_sample: Vec<u8>,
    pub sample_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageByteChanges {
    pub ranges: Vec<SectionByteChange>,
    pub compared_section_count: usize,
    pub changed_section_count: usize,
    pub changed_byte_count: usize,
    pub truncated: bool,
}

impl ImageByteChanges {
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }
}

pub fn compare_mapped_to_disk(
    mapped_data: &[u8],
    disk_data: &[u8],
    options: CompareOptions,
) -> Result<ImageComparison, DiagnosticsError> {
    let mapped_image = Image::parse(mapped_data.to_vec())?;
    let disk_image = Image::parse(disk_data.to_vec())?;
    compare_images(&mapped_image, &disk_image, options)
}

pub fn compare_images(mapped_image: &Image, disk_image: &Image, options: CompareOptions) -> Result<ImageComparison, DiagnosticsError> {
    let sections = mapped_image.sections()?;
    let mut comparisons = Vec::new();

    for section in sections {
        let size = format::section_size(&section);
        let mapped = section_mapped_bytes(&mapped_image, &section, size, options);
        let disk = section_file_bytes(&disk_image, &section, size, options);

        let changed = match (&mapped, &disk) {
            (Ok(mapped), Ok(disk)) => mapped != disk,
            _ => false,
        };

        comparisons.push(SectionComparison {
            name: section.name.clone(),
            rva: section.virtual_address,
            size,
            executable: format::section_is_executable(&section),
            mapped_hash: mapped.as_ref().ok().map(|data| fnv1a64(data)),
            disk_hash: disk.as_ref().ok().map(|data| fnv1a64(data)),
            mapped_error: mapped.err().map(|error| error.to_string()),
            disk_error: disk.err().map(|error| error.to_string()),
            changed,
        });
    }

    Ok(ImageComparison {
        sections: comparisons,
    })
}

pub fn section_byte_changes(
    mapped_data: &[u8],
    disk_data: &[u8],
    options: ByteChangeOptions,
) -> Result<ImageByteChanges, DiagnosticsError> {
    let mapped_image = Image::parse(mapped_data.to_vec())?;
    let disk_image = Image::parse(disk_data.to_vec())?;
    byte_changes_images(&mapped_image, &disk_image, options)
}

pub(super) fn byte_changes_images(mapped_image: &Image, disk_image: &Image, options: ByteChangeOptions) -> Result<ImageByteChanges, DiagnosticsError> {
    let sections = mapped_image.sections()?;
    let compare_options = CompareOptions {
        normalize_runtime_directories: options.normalize_runtime_directories,
    };
    let mut ranges = Vec::new();
    let mut compared_section_count = 0usize;
    let mut changed_section_count = 0usize;
    let mut changed_byte_count = 0usize;
    let mut truncated = false;

    for section in sections {
        let executable = format::section_is_executable(&section);
        if options.executable_only && !executable {
            continue;
        }

        let size = format::section_size(&section);
        let mapped = section_mapped_bytes(mapped_image, &section, size, compare_options)?;
        let disk = section_file_bytes(disk_image, &section, size, compare_options)?;
        let len = mapped.len().min(disk.len());
        let mut cursor = 0usize;
        let mut section_changed = false;
        compared_section_count += 1;

        while cursor < len {
            if mapped[cursor] == disk[cursor] {
                cursor += 1;
                continue;
            }

            let start = cursor;
            while cursor < len && mapped[cursor] != disk[cursor] {
                cursor += 1;
            }

            let end = cursor;
            section_changed = true;
            changed_byte_count += end - start;
            if ranges.len() >= options.max_ranges {
                truncated = true;
                continue;
            }

            ranges.push(section_byte_change(
                &section,
                executable,
                start,
                &mapped[start..end],
                &disk[start..end],
                options.sample_size,
            )?);
        }

        if section_changed {
            changed_section_count += 1;
        }
    }

    Ok(ImageByteChanges {
        ranges,
        compared_section_count,
        changed_section_count,
        changed_byte_count,
        truncated,
    })
}

fn section_mapped_bytes(
    image: &Image,
    section: &SectionInfo,
    size: u32,
    options: CompareOptions,
) -> Result<Vec<u8>, ImageError> {
    let mut data = image.read_mapped_bytes_rva(section.virtual_address, size as usize)?;
    if options.normalize_runtime_directories {
        normalize_runtime_directory_bytes(image, section, &mut data);
    }

    Ok(data)
}

fn section_file_bytes(
    image: &Image,
    section: &SectionInfo,
    size: u32,
    options: CompareOptions,
) -> Result<Vec<u8>, ImageError> {
    let sections = image.sections()?;
    let mut matching = sections.iter().filter(|candidate| candidate.virtual_address == section.virtual_address);
    let source_section = matching.next().ok_or(ImageError::RvaNotMapped { rva: section.virtual_address })?;
    if matching.next().is_some() || source_section.virtual_size != section.virtual_size {
        return Err(ImageError::RvaNotMapped { rva: section.virtual_address });
    }
    let mut data = vec![0u8; size as usize];
    let source_size = (source_section.raw_size as usize).min(data.len());

    if source_size != 0 {
        let source_offset = source_section.raw_offset as usize;
        let source = image.data()
            .get(source_offset..source_offset + source_size)
            .ok_or(ImageError::OutOfBounds {
                offset: source_offset,
                size: source_size,
            })?;

        data[..source.len()].copy_from_slice(source);
    }

    if options.normalize_runtime_directories {
        normalize_runtime_directory_bytes(image, section, &mut data);
    }

    Ok(data)
}

fn section_byte_change(
    section: &SectionInfo,
    executable: bool,
    offset: usize,
    mapped: &[u8],
    disk: &[u8],
    sample_size: usize,
) -> Result<SectionByteChange, DiagnosticsError> {
    let offset_u32 = u32::try_from(offset)
        .map_err(|_| DiagnosticsError::Overflow("converting changed byte offset"))?;
    let size = u32::try_from(mapped.len())
        .map_err(|_| DiagnosticsError::Overflow("converting changed byte size"))?;
    let rva = section
        .virtual_address
        .checked_add(offset_u32)
        .ok_or(DiagnosticsError::Overflow("computing changed byte RVA"))?;
    let sample_len = sample_size.min(mapped.len());

    Ok(SectionByteChange {
        section_name: section.name.clone(),
        section_rva: section.virtual_address,
        executable,
        rva,
        offset: offset_u32,
        size,
        mapped_hash: fnv1a64(mapped),
        disk_hash: fnv1a64(disk),
        mapped_sample: mapped[..sample_len].to_vec(),
        disk_sample: disk[..sample_len].to_vec(),
        sample_truncated: sample_len < mapped.len(),
    })
}

fn normalize_runtime_directory_bytes(image: &Image, section: &SectionInfo, data: &mut [u8]) {
    for index in [
        format::PE_DIRECTORY_ENTRY_IMPORT,
        format::PE_DIRECTORY_ENTRY_IAT,
        format::PE_DIRECTORY_ENTRY_BOUND_IMPORT,
        format::PE_DIRECTORY_ENTRY_DELAY_IMPORT,
        format::PE_DIRECTORY_ENTRY_LOAD_CONFIG,
    ] {
        let Ok(directory) = image.data_directory(index) else {
            continue;
        };
        if directory.is_empty() {
            continue;
        }

        zero_rva_intersection(
            data,
            section.virtual_address,
            directory.virtual_address,
            directory.size,
        );
    }
}

fn zero_rva_intersection(data: &mut [u8], base_rva: u32, target_rva: u32, target_size: u32) {
    let section_start = base_rva as u64;
    let section_end = section_start.saturating_add(data.len() as u64);
    let target_start = target_rva as u64;
    let target_end = target_start.saturating_add(target_size as u64);
    let start = section_start.max(target_start);
    let end = section_end.min(target_end);

    if end <= start {
        return;
    }

    let start = (start - section_start) as usize;
    let end = (end - section_start) as usize;
    data[start..end].fill(0);
}
