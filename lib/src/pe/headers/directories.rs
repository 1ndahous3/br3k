use super::HeaderError;
use crate::pe::format::*;
use crate::pe::image::{DataDirectory, Image};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

mod validate;
mod exceptions;
mod metadata;

#[cfg(test)]
#[path = "../tests/headers/directories.rs"]
mod tests;

/// Outcome of salvaging a data-directory entry from surviving header evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum DirectoryRecoveryStatus {
    /// Directory metadata passed supported checks and was restored.
    Restored,
    /// Directory contents or range failed validation.
    Invalid,
    /// Directory format has no supported salvage validation.
    Unsupported,
    /// Directory refers to file-only data that cannot be recovered from a mapped capture.
    FileOnly,
    /// Directory range conflicts with the reconstructed header area.
    HeaderOverlap,
}

#[derive(Clone, Debug)]
pub struct DirectoryRecovery {
    pub index: usize,
    pub directory: DataDirectory,
    pub status: DirectoryRecoveryStatus,
    pub error: Option<String>,
}

impl Image {
    // The destination must have the same RVA layout as the captured allocation.
    // The source needs only a surviving COFF/optional header, not signatures or a section table.
    pub fn salvage_directories(&mut self, source: &[u8], file_header_offset: usize) -> Result<Vec<DirectoryRecovery>, HeaderError> {
        let file_end = file_header_offset.checked_add(20).ok_or(HeaderError::OptionalHeader)?;
        let header = source.get(file_header_offset..file_end).ok_or(HeaderError::OptionalHeader)?;
        let machine = u16::from_le_bytes(header[..2].try_into().unwrap());
        let size = u16::from_le_bytes(header[16..18].try_into().unwrap()) as usize;
        let optional_end = file_end.checked_add(size).ok_or(HeaderError::OptionalHeader)?;
        let optional = source.get(file_end..optional_end.min(source.len())).ok_or(HeaderError::OptionalHeader)?;
        let magic = read_u16(optional, 0).ok_or(HeaderError::OptionalHeader)?;
        if machine != self.machine() || magic != if self.pointer_size() == 4 { IMAGE_NT_OPTIONAL_HDR32_MAGIC } else { IMAGE_NT_OPTIONAL_HDR64_MAGIC } {
            return Err(HeaderError::OptionalHeader);
        }
        let start = if self.pointer_size() == 4 { 96 } else { 112 };
        let count = read_u32(optional, start - 4).ok_or(HeaderError::OptionalHeader)?.min(16) as usize;
        let image_size = self.image_size()?;
        let mut result = Vec::new();
        for index in 0..count {
            let offset = start + index * 8;
            let Some(rva) = read_u32(optional, offset) else { break };
            let Some(size) = read_u32(optional, offset + 4) else { break };
            if rva == 0 && size == 0 { continue; }
            let directory = DataDirectory { virtual_address: rva, size };
            let mut record = DirectoryRecovery { index, directory, status: DirectoryRecoveryStatus::Invalid, error: None };
            let end = rva.checked_add(size);
            if index == PE_DIRECTORY_ENTRY_SECURITY {
                record.status = DirectoryRecoveryStatus::FileOnly;
            } else if rva == 0 || size == 0 || end.is_none_or(|end| end as usize > self.data().len() || end > image_size) {
                record.error = Some("Directory is outside the captured image".to_string());
            } else if rva < self.size_of_headers() {
                record.status = DirectoryRecoveryStatus::HeaderOverlap;
            } else {
                let previous = self.data_directory(index)?;
                self.set_data_directory(index, rva, size)?;
                match validate_directory(self, index) {
                    Ok(()) => record.status = DirectoryRecoveryStatus::Restored,
                    Err(error) => {
                        self.set_data_directory(index, previous.virtual_address, previous.size)?;
                        if matches!(error, validate::ValidationError::Unsupported(_)) {
                            record.status = DirectoryRecoveryStatus::Unsupported;
                        }
                        record.error = Some(error.to_string());
                    }
                }
            }
            result.push(record);
        }
        Ok(result)
    }
}

fn validate_directory(image: &Image, index: usize) -> Result<(), validate::ValidationError> {
    let parsed = match index {
        PE_DIRECTORY_ENTRY_EXPORT => Image::from_mapped_shared(image.shared_data(), image.address_base()?, image.missing_ranges().to_vec())
            .map_err(crate::pe::exports::ExportError::from).and_then(|image| image.exports()).map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_IMPORT => image.mapped_imports().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_RESOURCE => image.mapped_resource_data_entries().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_BASERELOC => image.mapped_base_relocations().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_TLS => image.mapped_tls_directory().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_DELAY_IMPORT => image.mapped_delay_imports().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_BOUND_IMPORT => image.mapped_bound_imports().map(|_| ()).map_err(|error| error.to_string()),
        PE_DIRECTORY_ENTRY_EXCEPTION => return exceptions::validate(image),
        PE_DIRECTORY_ENTRY_LOAD_CONFIG => return metadata::load_config(image),
        PE_DIRECTORY_ENTRY_COM_DESCRIPTOR => return metadata::clr(image),
        PE_DIRECTORY_ENTRY_DEBUG => return metadata::debug(image),
        PE_DIRECTORY_ENTRY_IAT => {
            let directory = image.data_directory(index)?;
            if directory.size as usize % image.pointer_size() != 0 {
                return Err(validate::ValidationError::Invalid("IAT size is not a multiple of pointer size"));
            }
            Ok(())
        }
        _ => return Err(validate::ValidationError::Unsupported("No structural validator for this directory")),
    };
    parsed.map_err(validate::ValidationError::Parser)
}

/// Bounded structural validation status for a data directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum CheckStatus {
    /// Directory has no declared address or size.
    Absent,
    /// Directory passed the implemented structural checks; not a loader certification.
    Valid,
    /// Directory failed a supported structural check.
    Invalid,
    /// The directory or its format is not supported by the validator.
    Unsupported,
    /// The directory requires file-only interpretation rather than mapped-memory validation.
    FileOnly,
}

#[derive(Clone, Debug)]
pub struct DirectoryCheck {
    pub index: usize,
    pub status: CheckStatus,
    pub message: Option<String>,
}

impl Image {
    pub fn check_directory(&self, index: usize) -> Result<DirectoryCheck, crate::pe::image::Error> {
        let directory = self.data_directory(index)?;
        let mut result = DirectoryCheck { index, status: CheckStatus::Valid, message: None };
        if directory.is_empty() { result.status = CheckStatus::Absent; return Ok(result); }
        if index == PE_DIRECTORY_ENTRY_SECURITY { result.status = CheckStatus::FileOnly; return Ok(result); }
        let mapped = self.to_mapped()?;
        if let Err(error) = validate_directory(&mapped, index) {
            result.status = if matches!(error, validate::ValidationError::Unsupported(_)) { CheckStatus::Unsupported } else { CheckStatus::Invalid };
            result.message = Some(error.to_string());
        }
        Ok(result)
    }
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}
