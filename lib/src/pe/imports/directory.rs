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
mod tests {
    use super::*;

    const PE_OFFSET: usize = 0x80;
    const FILE_HEADER_OFFSET: usize = PE_OFFSET + 4;
    const OPTIONAL_HEADER_OFFSET: usize = FILE_HEADER_OFFSET + 20;
    const SECTION_TABLE_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 0xe0;
    const IMPORT_DIRECTORY_RVA: u32 = 0x1100;
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = SECTION_RVA as usize;

    #[test]
    fn reads_import_descriptors_from_file_layout() {
        let data = pe32_with_imports();
        let image = Image::parse(data).unwrap();
        let descriptors = image.imports().unwrap();

        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].dll_name.as_deref(), Some("kernel32.dll"));
        assert_eq!(descriptors[0].original_first_thunk_rva, Some(0x1200));
        assert_eq!(descriptors[0].first_thunk_rva, Some(0x1300));
        assert_eq!(descriptors[0].import_count(), 2);
        assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
        assert_eq!(descriptors[0].imports[0].hint, Some(7));
        assert_eq!(descriptors[0].imports[0].import_address_table_rva, Some(0x1300));
        assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0x1250));
        assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
        assert_eq!(descriptors[0].imports[1].raw_lookup_value, IMAGE_ORDINAL_FLAG32 | 0x123);
    }

    #[test]
    fn reads_import_address_values_from_mapped_layout() {
        let mut data = pe32_with_imports();
        put_u32(&mut data, 0x1300, 0x7700_1000);
        put_u32(&mut data, 0x1304, 0x7700_2000);

        let image = Image::parse(data).unwrap();
        let descriptors = image.mapped_imports().unwrap();

        assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
        assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0x7700_1000));
        assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
        assert_eq!(descriptors[0].imports[1].raw_address_value, Some(0x7700_2000));
    }

    #[test]
    fn missing_lookup_table_preserves_bound_and_mapped_addresses() {
        for timestamp in [0, 0x12345678, u32::MAX] {
            let mut data = pe32_with_imports();
            put_u32(&mut data, 0x1100, 0);
            put_u32(&mut data, 0x1104, timestamp);
            // One VA looks like an ordinal; the other happens to equal a valid name RVA.
            put_u32(&mut data, 0x1300, 0xf7001000);
            put_u32(&mut data, 0x1304, 0x1250);
            let image = Image::parse(data).unwrap();
            let mut checks = vec![(image.mapped_imports().unwrap(), ImportLookupKind::ResolvedAddresses)];
            if timestamp != 0 {
                let file = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
                checks.push((file.imports().unwrap(), ImportLookupKind::BoundAddresses));
            }
            for (descriptors, kind) in checks {
                assert_eq!(descriptors[0].lookup_kind, kind);
                assert_eq!(descriptors[0].imports[0].raw_lookup_value, 0xf7001000);
                for function in &descriptors[0].imports {
                    assert_eq!(function.name_rva, None);
                    assert_eq!(function.hint, None);
                    assert_eq!(function.name, None);
                    assert_eq!(function.ordinal, None);
                    assert_eq!(function.raw_address_value, Some(function.raw_lookup_value));
                }
            }
        }
    }

    #[test]
    fn unbound_file_without_original_first_thunk_still_reads_names_and_ordinals() {
        let mut data = pe32_with_imports();
        put_u32(&mut data, 0x1100, 0);
        let mut image = Image::parse(data).unwrap();
        let descriptors = image.imports().unwrap();
        assert_eq!(descriptors[0].lookup_kind, ImportLookupKind::FirstThunk);
        assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
        assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
        image.write_u32(0x1300, 0x7fff1000).unwrap();
        assert!(image.imports().is_err());
    }

    #[test]
    fn bound_image_uses_original_lookup_table_when_present() {
        for timestamp in [0x12345678, u32::MAX] {
            let mut data = pe32_with_imports();
            put_u32(&mut data, 0x1104, timestamp);
            put_u32(&mut data, 0x1300, 0xf7001000);
            put_u32(&mut data, 0x1304, 0xf7002000);
            let image = Image::parse(data).unwrap();
            for descriptors in [image.imports().unwrap(), image.mapped_imports().unwrap()] {
                assert_eq!(descriptors[0].lookup_kind, ImportLookupKind::OriginalFirstThunk);
                assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
                assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
                assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0xf7001000));
            }
        }
    }

    fn pe32_with_imports() -> Vec<u8> {
        let mut data = vec![0u8; 0x3000];
        put_u16(&mut data, 0, 0x5a4d);
        put_u32(&mut data, 0x3c, PE_OFFSET as u32);
        put_u32(&mut data, PE_OFFSET, 0x0000_4550);
        put_u16(&mut data, FILE_HEADER_OFFSET, 0x014c);
        put_u16(&mut data, FILE_HEADER_OFFSET + 2, 1);
        put_u16(&mut data, FILE_HEADER_OFFSET + 16, 0xe0);
        put_u16(&mut data, OPTIONAL_HEADER_OFFSET, 0x10b);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 28, 0x400000);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 36, 0x200);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 56, 0x3000);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 60, 0x200);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 92, 16);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 96 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, IMPORT_DIRECTORY_RVA);
        put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 100 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, 0x40);
        put_section_header(&mut data, SECTION_TABLE_OFFSET, ".idata", 0x2000, SECTION_RVA, 0x2000, SECTION_OFFSET as u32, 0x4000_0040);

        put_u32(&mut data, 0x1100, 0x1200);
        put_u32(&mut data, 0x1104, 0);
        put_u32(&mut data, 0x1108, 0);
        put_u32(&mut data, 0x110c, 0x1240);
        put_u32(&mut data, 0x1110, 0x1300);
        put_u32(&mut data, 0x1200, 0x1250);
        put_u32(&mut data, 0x1204, (IMAGE_ORDINAL_FLAG32 | 0x123) as u32);
        put_u32(&mut data, 0x1208, 0);
        put_u32(&mut data, 0x1300, 0x1250);
        put_u32(&mut data, 0x1304, (IMAGE_ORDINAL_FLAG32 | 0x123) as u32);
        put_u32(&mut data, 0x1308, 0);
        write_cstr(&mut data, 0x1240, "kernel32.dll");
        put_u16(&mut data, 0x1250, 7);
        write_cstr(&mut data, 0x1252, "LoadLibraryA");

        data
    }

    fn put_section_header(
        data: &mut [u8],
        offset: usize,
        name: &str,
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_offset: u32,
        characteristics: u32,
    ) {
        data[offset..offset + 8].fill(0);
        data[offset..offset + name.len()].copy_from_slice(name.as_bytes());
        put_u32(data, offset + 8, virtual_size);
        put_u32(data, offset + 12, virtual_address);
        put_u32(data, offset + 16, raw_size);
        put_u32(data, offset + 20, raw_offset);
        put_u32(data, offset + 36, characteristics);
    }

    fn write_cstr(data: &mut [u8], offset: usize, value: &str) {
        data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        data[offset + value.len()] = 0;
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
