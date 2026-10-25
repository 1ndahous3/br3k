use crate::pe::format::PE_DIRECTORY_ENTRY_BOUND_IMPORT;
use crate::pe::image::{DataDirectory, Error as ImageError, Image};

mod validation;
pub use validation::{BoundImportCheck, BoundImportKind, BoundImportStatus};

const RECORD_SIZE: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum BoundImportError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error(transparent)]
    Import(#[from] crate::pe::imports::ImportError),
    #[error("invalid bound-import directory at RVA 0x{rva:x} with size 0x{size:x}")]
    InvalidDirectory { rva: u32, size: u32 },
    #[error("truncated bound-import record at directory offset 0x{offset:x}")]
    TruncatedRecord { offset: usize },
    #[error("bound-import descriptor at directory offset 0x{offset:x} declares {count} forwarder references outside the directory")]
    TruncatedForwarders { offset: usize, count: u16 },
    #[error("bound-import directory has no null descriptor terminator")]
    MissingTerminator,
    #[error("bound-import module name offset 0x{offset:x} is outside the directory")]
    InvalidNameOffset { offset: u16 },
    #[error("bound-import module name at directory offset 0x{offset:x} overlaps descriptor or forwarder records")]
    NameOverlapsRecords { offset: u16 },
    #[error("unterminated bound-import module name at directory offset 0x{offset:x}")]
    UnterminatedName { offset: u16 },
    #[error("bound-import module name at directory offset 0x{offset:x} is empty or not ASCII")]
    InvalidName { offset: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundForwarderRef {
    pub rva: u32,
    pub module_name_offset: u16,
    pub dll_name: String,
    pub time_date_stamp: u32,
    pub reserved: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundImportDescriptor {
    pub descriptor_rva: u32,
    pub module_name_offset: u16,
    pub dll_name: String,
    pub time_date_stamp: u32,
    pub forwarders: Vec<BoundForwarderRef>,
}

#[derive(Clone, Copy)]
enum Layout {
    File,
    MappedImage,
}

impl Image {
    pub fn bound_imports(&self) -> Result<Vec<BoundImportDescriptor>, BoundImportError> {
        read_bound_imports(self, Layout::File)
    }

    pub fn mapped_bound_imports(&self) -> Result<Vec<BoundImportDescriptor>, BoundImportError> {
        read_bound_imports(self, Layout::MappedImage)
    }
}

fn read_bound_imports(image: &Image, layout: Layout) -> Result<Vec<BoundImportDescriptor>, BoundImportError> {
    let directory = match image.data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        Ok(directory) => directory,
        Err(ImageError::DataDirectoryMissing { .. }) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if directory.virtual_address == 0 && directory.size == 0 {
        return Ok(Vec::new());
    }

    let end = directory.virtual_address.checked_add(directory.size);
    let image_size = image.image_size()?;
    if directory.is_empty() || end.is_none_or(|end| end > image_size) {
        return Err(BoundImportError::InvalidDirectory { rva: directory.virtual_address, size: directory.size });
    }

    let data = read_directory(image, directory, layout)?;
    let mut descriptors = Vec::new();
    let mut offset = 0;
    let mut first_name_offset: Option<u16> = None;

    loop {
        if let Some(name_offset) = first_name_offset.filter(|name_offset| (*name_offset as usize) < offset) {
            return Err(BoundImportError::NameOverlapsRecords { offset: name_offset });
        }
        if offset == data.len() || first_name_offset.is_some_and(|name_offset| offset == name_offset as usize) {
            return Err(BoundImportError::MissingTerminator);
        }
        let record = read_record(&data, offset)?;
        if record.iter().all(|byte| *byte == 0) {
            if let Some(name_offset) = first_name_offset.filter(|name_offset| (*name_offset as usize) < offset + RECORD_SIZE) {
                return Err(BoundImportError::NameOverlapsRecords { offset: name_offset });
            }
            return Ok(descriptors);
        }

        let time_date_stamp = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
        let module_name_offset = u16::from_le_bytes([record[4], record[5]]);
        let count = u16::from_le_bytes([record[6], record[7]]);
        let descriptor_rva = directory.virtual_address + offset as u32;
        let forwarder_start = offset + RECORD_SIZE;
        let forwarder_size = count as usize * RECORD_SIZE;
        if forwarder_size > data.len() - forwarder_start {
            return Err(BoundImportError::TruncatedForwarders { offset, count });
        }

        let dll_name = read_name(&data, module_name_offset)?;
        first_name_offset = Some(first_name_offset.unwrap_or(module_name_offset).min(module_name_offset));
        let mut forwarders = Vec::new();
        offset = forwarder_start;
        for _ in 0..count {
            let record = read_record(&data, offset)?;
            let name_offset = u16::from_le_bytes([record[4], record[5]]);
            forwarders.push(BoundForwarderRef {
                rva: directory.virtual_address + offset as u32,
                module_name_offset: name_offset,
                dll_name: read_name(&data, name_offset)?,
                time_date_stamp: u32::from_le_bytes([record[0], record[1], record[2], record[3]]),
                reserved: u16::from_le_bytes([record[6], record[7]]),
            });
            first_name_offset = Some(first_name_offset.unwrap_or(name_offset).min(name_offset));
            offset += RECORD_SIZE;
        }

        descriptors.push(BoundImportDescriptor {
            descriptor_rva,
            module_name_offset,
            dll_name,
            time_date_stamp,
            forwarders,
        });
    }
}

fn read_directory(image: &Image, directory: DataDirectory, layout: Layout) -> Result<Vec<u8>, ImageError> {
    if matches!(layout, Layout::MappedImage) {
        return image.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize);
    }

    // Walk file-backed spans so a directory cannot consume a section's virtual tail or file overlay.
    let sections = image.sections()?;
    let mut data = Vec::new();
    let mut rva = directory.virtual_address;
    let end = rva + directory.size;
    while rva < end {
        let available = if rva < image.size_of_headers() {
            image.size_of_headers() - rva
        } else {
            sections.iter().find_map(|section| {
                let delta = rva.checked_sub(section.virtual_address)?;
                (delta < section.raw_size).then(|| section.raw_size - delta)
            }).ok_or(ImageError::RvaNotMapped { rva })?
        };
        let size = available.min(end - rva);
        data.extend_from_slice(&image.read_bytes_rva(rva, size as usize)?);
        rva += size;
    }
    Ok(data)
}

fn read_record(data: &[u8], offset: usize) -> Result<&[u8; RECORD_SIZE], BoundImportError> {
    offset.checked_add(RECORD_SIZE)
        .and_then(|end| data.get(offset..end))
        .and_then(|record| record.try_into().ok())
        .ok_or(BoundImportError::TruncatedRecord { offset })
}

fn read_name(data: &[u8], offset: u16) -> Result<String, BoundImportError> {
    let data = data.get(offset as usize..).filter(|data| !data.is_empty())
        .ok_or(BoundImportError::InvalidNameOffset { offset })?;
    let end = data.iter().position(|byte| *byte == 0)
        .ok_or(BoundImportError::UnterminatedName { offset })?;
    if end == 0 || !data[..end].is_ascii() {
        return Err(BoundImportError::InvalidName { offset });
    }
    String::from_utf8(data[..end].to_vec()).map_err(|_| BoundImportError::InvalidName { offset })
}

#[cfg(test)]
#[path = "tests/bound_imports/mod.rs"]
mod tests;
