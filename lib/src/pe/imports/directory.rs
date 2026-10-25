use super::types::*;
use super::util::{
    checked_mul, read_iat_pointer, validate_pointer_size, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_IMPORT_DESCRIPTOR_SIZE, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64,
};

use crate::pe::image::{DataDirectory, Image};
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

pub const MAX_IMPORT_DESCRIPTORS: usize = 4096;
pub const MAX_IMPORTS_PER_DESCRIPTOR: usize = 16384;
pub const MAX_IMPORT_NAME: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportDirectoryLayout {
    File,
    MappedImage,
}

/// Interpretation of the thunk table used to parse one import descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportLookupKind {
    /// Names and ordinals were read from OriginalFirstThunk.
    OriginalFirstThunk,
    /// Names and ordinals were read from FirstThunk because no separate lookup table was available.
    FirstThunk,
    /// FirstThunk contains file binding addresses rather than import-name entries.
    BoundAddresses,
    /// FirstThunk contains addresses resolved in a mapped image.
    ResolvedAddresses,
}

impl ImportLookupKind {
    fn has_names(self) -> bool {
        matches!(self, Self::OriginalFirstThunk | Self::FirstThunk)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub index: usize,
    pub descriptor_rva: u32,
    pub original_first_thunk_rva: Option<u32>,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub dll_name_rva: Option<u32>,
    pub dll_name: Option<String>,
    pub first_thunk_rva: Option<u32>,
    pub lookup_kind: ImportLookupKind,
    pub imports: Vec<ImportDescriptorFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportDescriptorFunction {
    pub index: usize,
    pub import_lookup_table_rva: u32,
    pub import_address_table_rva: Option<u32>,
    pub raw_lookup_value: u64,
    pub raw_address_value: Option<u64>,
    pub name_rva: Option<u32>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

impl ImportDescriptor {
    pub fn import_count(&self) -> usize {
        self.imports.len()
    }
}

impl Image {
    pub fn imports(&self) -> Result<Vec<ImportDescriptor>, ImportError> {
        imports_with_layout(self, ImportDirectoryLayout::File)
    }

    pub fn mapped_imports(&self) -> Result<Vec<ImportDescriptor>, ImportError> {
        imports_with_layout(self, ImportDirectoryLayout::MappedImage)
    }
}

pub fn imports_with_layout(
    image: &Image,
    layout: ImportDirectoryLayout,
) -> Result<Vec<ImportDescriptor>, ImportError> {
    read_descriptors(image, layout, true)
}

pub(crate) fn import_headers_with_layout(image: &Image, layout: ImportDirectoryLayout) -> Result<Vec<ImportDescriptor>, ImportError> {
    read_descriptors(image, layout, false)
}

fn read_descriptors(image: &Image, layout: ImportDirectoryLayout, read_functions: bool) -> Result<Vec<ImportDescriptor>, ImportError> {
    let Some(directory) = import_directory(image)? else {
        return Ok(Vec::new());
    };

    let directory_data = read_rva_bytes(image, directory.virtual_address, directory.size as usize, layout)?;
    let mut descriptors = Vec::new();

    for (index, descriptor_data) in directory_data
        .chunks_exact(IMAGE_IMPORT_DESCRIPTOR_SIZE)
        .take(MAX_IMPORT_DESCRIPTORS)
        .enumerate()
    {
        if descriptor_data.iter().all(|byte| *byte == 0) {
            return Ok(descriptors);
        }

        let descriptor_rva = directory
            .virtual_address
            .checked_add(
                u32::try_from(index * IMAGE_IMPORT_DESCRIPTOR_SIZE)
                    .map_err(|_| ImportError::Overflow("computing import descriptor RVA"))?,
            )
            .ok_or(ImportError::Overflow("computing import descriptor RVA"))?;
        let original_first_thunk = read_u32(descriptor_data, 0)?;
        let time_date_stamp = read_u32(descriptor_data, 4)?;
        let forwarder_chain = read_u32(descriptor_data, 8)?;
        let name_rva = read_u32(descriptor_data, 12)?;
        let first_thunk = read_u32(descriptor_data, 16)?;
        let lookup_table_rva = nonzero_rva(original_first_thunk).or_else(|| nonzero_rva(first_thunk));
        let dll_name_rva = nonzero_rva(name_rva);
        let first_thunk_rva = nonzero_rva(first_thunk);
        let lookup_kind = if original_first_thunk != 0 { ImportLookupKind::OriginalFirstThunk }
            else if matches!(layout, ImportDirectoryLayout::MappedImage) { ImportLookupKind::ResolvedAddresses }
            else if time_date_stamp != 0 { ImportLookupKind::BoundAddresses }
            else { ImportLookupKind::FirstThunk };
        let dll_name = match dll_name_rva {
            Some(rva) => Some(read_cstr_rva(image, rva, layout)?),
            None => None,
        };
        let imports = match lookup_table_rva {
            Some(rva) if read_functions => read_import_functions(image, index, rva, first_thunk_rva, lookup_kind, layout)?,
            _ => Vec::new(),
        };

        descriptors.push(ImportDescriptor {
            index,
            descriptor_rva,
            original_first_thunk_rva: nonzero_rva(original_first_thunk),
            time_date_stamp,
            forwarder_chain,
            dll_name_rva,
            dll_name,
            first_thunk_rva,
            lookup_kind,
            imports,
        });
    }

    Err(ImportError::ImportDescriptorTableTooLong {
        limit: MAX_IMPORT_DESCRIPTORS,
    })
}

fn read_import_functions(
    image: &Image,
    descriptor_index: usize,
    lookup_table_rva: u32,
    first_thunk_rva: Option<u32>,
    lookup_kind: ImportLookupKind,
    layout: ImportDirectoryLayout,
) -> Result<Vec<ImportDescriptorFunction>, ImportError> {
    let pointer_size = image.pointer_size();
    validate_pointer_size(pointer_size)?;

    let mut functions = Vec::new();
    for index in 0..MAX_IMPORTS_PER_DESCRIPTOR {
        let thunk_offset = checked_mul_u32(index, pointer_size, "walking import thunk table")?;
        let import_lookup_table_rva = lookup_table_rva
            .checked_add(thunk_offset)
            .ok_or(ImportError::Overflow("walking import thunk table"))?;
        let raw_lookup_value = read_pointer_rva(image, import_lookup_table_rva, pointer_size, layout)?;
        if raw_lookup_value == 0 {
            return Ok(functions);
        }

        let import_address_table_rva = first_thunk_rva
            .map(|rva| rva.checked_add(thunk_offset).ok_or(ImportError::Overflow("walking import address table")))
            .transpose()?;
        let raw_address_value = import_address_table_rva
            .map(|rva| read_pointer_rva(image, rva, pointer_size, layout))
            .transpose()?;
        let (name_rva, hint, name, ordinal) = if lookup_kind.has_names() {
            import_function_target(image, raw_lookup_value, pointer_size, layout)?
        } else {
            (None, None, None, None)
        };

        functions.push(ImportDescriptorFunction {
            index,
            import_lookup_table_rva,
            import_address_table_rva,
            raw_lookup_value,
            raw_address_value,
            name_rva,
            hint,
            name,
            ordinal,
        });
    }

    Err(ImportError::ImportThunkTableTooLong {
        descriptor_index,
        limit: MAX_IMPORTS_PER_DESCRIPTOR,
    })
}

fn import_function_target(
    image: &Image,
    raw_lookup_value: u64,
    pointer_size: usize,
    layout: ImportDirectoryLayout,
) -> Result<(Option<u32>, Option<u16>, Option<String>, Option<u16>), ImportError> {
    if raw_lookup_value & ordinal_flag(pointer_size)? != 0 {
        return Ok((None, None, None, Some(raw_lookup_value as u16)));
    }

    let name_rva = match u32::try_from(raw_lookup_value) {
        Ok(0) => return Ok((None, None, None, None)),
        Ok(rva) => rva,
        Err(_) => return Ok((None, None, None, None)),
    };
    let hint = read_u16_rva(image, name_rva, layout)?;
    let name = read_cstr_rva(
        image,
        name_rva
            .checked_add(2)
            .ok_or(ImportError::Overflow("locating import name"))?,
        layout,
    )?;

    Ok((Some(name_rva), Some(hint), Some(name), None))
}

fn import_directory(image: &Image) -> Result<Option<DataDirectory>, ImportError> {
    let directory = image
        .data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });

    Ok((!directory.is_empty()).then_some(directory))
}

fn nonzero_rva(rva: u32) -> Option<u32> {
    (rva != 0).then_some(rva)
}

fn ordinal_flag(pointer_size: usize) -> Result<u64, ImportError> {
    match pointer_size {
        4 => Ok(IMAGE_ORDINAL_FLAG32),
        8 => Ok(IMAGE_ORDINAL_FLAG64),
        _ => Err(ImportError::InvalidPointerSize(pointer_size)),
    }
}

fn read_pointer_rva(
    image: &Image,
    rva: u32,
    pointer_size: usize,
    layout: ImportDirectoryLayout,
) -> Result<u64, ImportError> {
    let bytes = read_rva_bytes(image, rva, pointer_size, layout)?;
    read_iat_pointer(&bytes, pointer_size)
}

fn read_u16_rva(
    image: &Image,
    rva: u32,
    layout: ImportDirectoryLayout,
) -> Result<u16, ImportError> {
    let bytes = read_rva_bytes(image, rva, 2, layout)?;
    Ok(u16::from_le_bytes(bytes.as_slice().try_into().unwrap()))
}

fn read_cstr_rva(
    image: &Image,
    rva: u32,
    layout: ImportDirectoryLayout,
) -> Result<String, ImportError> {
    let mut bytes = Vec::new();

    for index in 0..MAX_IMPORT_NAME {
        let byte_rva = rva
            .checked_add(
                u32::try_from(index)
                    .map_err(|_| ImportError::Overflow("walking import string"))?,
            )
            .ok_or(ImportError::Overflow("walking import string"))?;
        let byte = read_rva_bytes(image, byte_rva, 1, layout)?[0];
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }

        bytes.push(byte);
    }

    Err(ImportError::UnterminatedString { rva })
}

fn read_rva_bytes(
    image: &Image,
    rva: u32,
    size: usize,
    layout: ImportDirectoryLayout,
) -> Result<Vec<u8>, ImportError> {
    match layout {
        ImportDirectoryLayout::File => Ok(image.read_bytes_rva(rva, size)?),
        ImportDirectoryLayout::MappedImage => Ok(image.read_mapped_bytes_rva(rva, size)?),
    }
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ImportError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(ImportError::Overflow("reading import descriptor"))?;

    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn checked_mul_u32(
    lhs: usize,
    rhs: usize,
    operation: &'static str,
) -> Result<u32, ImportError> {
    let value = checked_mul(lhs, rhs, operation)?;

    u32::try_from(value).map_err(|_| ImportError::Overflow(operation))
}

#[cfg(test)]
#[path = "../tests/imports/directory.rs"]
mod tests;
