use crate::pe::format::{
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    PE_DIRECTORY_ENTRY_DELAY_IMPORT,
};
use crate::pe::image::{DataDirectory, Error as ImageError, Image};

mod recovery;
pub use recovery::{DelayImportCandidate, DelayImportRecovery, DelayImportRecoveryStatus};

pub const DELAY_IMPORT_DESCRIPTOR_SIZE: usize = 32;
pub const MAX_DELAY_IMPORTS_PER_DESCRIPTOR: usize = 4096;
pub const MAX_DELAY_IMPORT_NAME: usize = 4096;

const DELAY_IMPORT_ATTRIBUTES_RVA_BASED: u32 = 1;
const IMAGE_ORDINAL_FLAG32: u64 = 0x8000_0000;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

#[derive(Debug, thiserror::Error)]
pub enum DelayImportError {
    #[error("delay-import directory has no null descriptor terminator within the declared range or validation limit")]
    MissingTerminator,
    #[error("invalid delay-import descriptor at RVA 0x{rva:x}: {reason}")]
    InvalidDescriptor { rva: u32, reason: &'static str },
    #[error("delay-import recovery has no unique, complete candidate")]
    NoUniqueCandidate,
    #[error("source image does not match the destination, or erased delay-import metadata cannot be verified")]
    SourceMismatch,
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("delay-import VA 0x{address:x} is below image base 0x{image_base:x}")]
    AddressBeforeImage { address: u64, image_base: u64 },
    #[error("delay-import model does not contain any descriptors")]
    EmptyDelayImportModel,
    #[error("delay-import descriptor {descriptor_index} has no DLL name")]
    MissingDllName { descriptor_index: usize },
    #[error("delay-import descriptor {descriptor_index} function {function_index} has no name or ordinal")]
    MissingFunctionTarget {
        descriptor_index: usize,
        function_index: usize,
    },
    #[error("delay-import name contains an interior NUL byte: {0}")]
    NameContainsNul(String),
    #[error("delay-import descriptor {descriptor_index} has no null thunk terminator within {limit} entries")]
    ImportTableTooLong {
        descriptor_index: usize,
        limit: usize,
    },
    #[error("unterminated delay-import string at RVA 0x{rva:x}")]
    UnterminatedString { rva: u32 },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DelayImportLayout {
    File,
    MappedImage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayImportFunction {
    pub index: usize,
    pub import_name_table_rva: u32,
    pub import_address_table_rva: Option<u32>,
    pub raw_value: u64,
    pub name_rva: Option<u32>,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayImportDescriptor {
    pub index: usize,
    pub descriptor_rva: u32,
    pub attributes: u32,
    pub rva_based: bool,
    pub dll_name_rva: Option<u32>,
    pub dll_name: Option<String>,
    pub module_handle_rva: Option<u32>,
    pub import_address_table_rva: Option<u32>,
    pub import_name_table_rva: Option<u32>,
    pub bound_import_address_table_rva: Option<u32>,
    pub unload_information_table_rva: Option<u32>,
    pub time_date_stamp: u32,
    pub imports: Vec<DelayImportFunction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelayImportRebuild {
    pub image: Vec<u8>,
    pub section_rva: u32,
    pub section_size: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub descriptor_count: usize,
    pub import_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DelayImportSection {
    size: usize,
    directory_size: u32,
    descriptor_count: usize,
    import_count: usize,
    pointer_size: usize,
    descriptors: Vec<DelayImportDescriptor>,
    layouts: Vec<DelayImportDescriptorLayout>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DelayImportDescriptorLayout {
    descriptor_offset: usize,
    dll_name_offset: usize,
    module_handle_offset: usize,
    iat_offset: usize,
    int_offset: usize,
    unload_iat_offset: Option<usize>,
    time_date_stamp: u32,
    imports: Vec<DelayImportThunkLayout>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DelayImportThunkLayout {
    name_offset: Option<usize>,
    hint: Option<u16>,
    name: Option<String>,
    ordinal: Option<u16>,
}

impl DelayImportDescriptor {
    pub fn import_count(&self) -> usize {
        self.imports.len()
    }
}

impl Image {
    pub fn delay_imports(&self) -> Result<Vec<DelayImportDescriptor>, DelayImportError> {
        delay_imports_with_layout(self, DelayImportLayout::File)
    }

    pub fn mapped_delay_imports(&self) -> Result<Vec<DelayImportDescriptor>, DelayImportError> {
        delay_imports_with_layout(self, DelayImportLayout::MappedImage)
    }

    pub fn rebuild_delay_imports(
        &self,
        descriptors: &[DelayImportDescriptor],
        section_name: &str,
    ) -> Result<DelayImportRebuild, DelayImportError> {
        let section_data = build_delay_import_section(self, descriptors)?;
        let mut image = Image::parse(self.data().to_vec())?;
        let section = image.append_section_with_characteristics(
            section_name,
            section_data.size,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )?;
        let data = section_data.data(section.virtual_address)?;

        image.write_bytes(section.raw_offset, &data)?;
        image.set_data_directory(
            PE_DIRECTORY_ENTRY_DELAY_IMPORT,
            section.virtual_address,
            section_data.directory_size,
        )?;

        let section_size = u32::try_from(section_data.size)
            .map_err(|_| DelayImportError::Overflow("converting delay-import section size to u32"))?;

        Ok(DelayImportRebuild {
            image: image.into_data(),
            section_rva: section.virtual_address,
            section_size,
            directory_rva: section.virtual_address,
            directory_size: section_data.directory_size,
            descriptor_count: section_data.descriptor_count,
            import_count: section_data.import_count,
        })
    }
}

impl DelayImportSection {
    fn data(&self, section_rva: u32) -> Result<Vec<u8>, DelayImportError> {
        let mut data = vec![0u8; self.size];
        write_delay_import_section_data(
            &mut data,
            section_rva,
            &self.descriptors,
            &self.layouts,
            self.pointer_size,
        )?;

        Ok(data)
    }
}

pub fn delay_imports_with_layout(image: &Image, layout: DelayImportLayout) -> Result<Vec<DelayImportDescriptor>, DelayImportError> {
    let Some(directory) = delay_import_directory(image)? else { return Ok(Vec::new()) };
    read_directory(image, layout, directory)
}

fn read_directory(image: &Image, layout: DelayImportLayout, directory: DataDirectory) -> Result<Vec<DelayImportDescriptor>, DelayImportError> {
    let data = read_rva_bytes(image, directory.virtual_address, directory.size as usize, layout)?;
    let mut descriptors = Vec::new();
    for (index, record) in data.chunks_exact(DELAY_IMPORT_DESCRIPTOR_SIZE).take(4096).enumerate() {
        if record.iter().all(|byte| *byte == 0) { return Ok(descriptors); }
        let rva = directory.virtual_address.checked_add((index * DELAY_IMPORT_DESCRIPTOR_SIZE) as u32)
            .ok_or(DelayImportError::Overflow("walking delay-import descriptors"))?;
        descriptors.push(read_descriptor(image, record, index, rva, layout)?);
    }
    Err(DelayImportError::MissingTerminator)
}

fn read_descriptor(image: &Image, descriptor_data: &[u8], index: usize, descriptor_rva: u32, layout: DelayImportLayout) -> Result<DelayImportDescriptor, DelayImportError> {
    let attributes = read_u32(descriptor_data, 0)?;
    if attributes & !1 != 0 {
        return Err(DelayImportError::InvalidDescriptor { rva: descriptor_rva, reason: "reserved attribute bits are set" });
    }
    let rva_based = attributes & DELAY_IMPORT_ATTRIBUTES_RVA_BASED != 0;
    let raw_dll_name = read_u32(descriptor_data, 4)?;
    let raw_module_handle = read_u32(descriptor_data, 8)?;
    let raw_iat = read_u32(descriptor_data, 12)?;
    let raw_int = read_u32(descriptor_data, 16)?;
    let raw_bound_iat = read_u32(descriptor_data, 20)?;
    let raw_unload_iat = read_u32(descriptor_data, 24)?;
    let time_date_stamp = read_u32(descriptor_data, 28)?;

    let dll_name_rva = normalize_descriptor_rva(image, raw_dll_name, rva_based)?;
    let module_handle_rva = normalize_descriptor_rva(image, raw_module_handle, rva_based)?;
    let import_address_table_rva = normalize_descriptor_rva(image, raw_iat, rva_based)?;
    let import_name_table_rva = normalize_descriptor_rva(image, raw_int, rva_based)?;
    let bound_import_address_table_rva = normalize_descriptor_rva(image, raw_bound_iat, rva_based)?;
    let unload_information_table_rva = normalize_descriptor_rva(image, raw_unload_iat, rva_based)?;
    let dll_name = match dll_name_rva {
        Some(rva) => Some(read_cstr_rva(image, rva, layout)?),
        None => None,
    };
    let imports = match import_name_table_rva {
        Some(int_rva) => read_delay_import_functions(
            image,
            index,
            int_rva,
            import_address_table_rva,
            rva_based,
            layout,
        )?,
        None => Vec::new(),
    };

    Ok(DelayImportDescriptor {
        index,
        descriptor_rva,
        attributes,
        rva_based,
        dll_name_rva,
        dll_name,
        module_handle_rva,
        import_address_table_rva,
        import_name_table_rva,
        bound_import_address_table_rva,
        unload_information_table_rva,
        time_date_stamp,
        imports,
    })
}

fn build_delay_import_section(
    image: &Image,
    descriptors: &[DelayImportDescriptor],
) -> Result<DelayImportSection, DelayImportError> {
    if descriptors.is_empty() {
        return Err(DelayImportError::EmptyDelayImportModel);
    }

    let pointer_size = image.pointer_size();
    let directory_size = checked_mul_usize(
        descriptors.len() + 1,
        DELAY_IMPORT_DESCRIPTOR_SIZE,
        "sizing delay-import descriptor table",
    )?;
    let mut cursor = directory_size;
    let mut layouts = Vec::with_capacity(descriptors.len());
    let mut import_count = 0usize;

    for descriptor in descriptors {
        let dll_name = descriptor
            .dll_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .ok_or(DelayImportError::MissingDllName { descriptor_index: descriptor.index })?;
        validate_cstr(dll_name)?;

        let dll_name_offset = cursor;
        cursor = checked_add_usize(cursor, cstr_size(dll_name)?, "placing delay-import DLL name")?;
        cursor = align_up_usize(cursor, pointer_size)?;

        let module_handle_offset = cursor;
        cursor = checked_add_usize(cursor, pointer_size, "placing delay-import module handle slot")?;
        cursor = align_up_usize(cursor, pointer_size)?;

        let iat_offset = cursor;
        cursor = checked_add_usize(cursor, thunk_table_size(descriptor.imports.len(), pointer_size)?, "placing delay IAT")?;
        cursor = align_up_usize(cursor, pointer_size)?;

        let int_offset = cursor;
        cursor = checked_add_usize(cursor, thunk_table_size(descriptor.imports.len(), pointer_size)?, "placing delay INT")?;

        let unload_iat_offset = if descriptor.unload_information_table_rva.is_some() {
            cursor = align_up_usize(cursor, pointer_size)?;
            let offset = cursor;
            cursor = checked_add_usize(cursor, thunk_table_size(descriptor.imports.len(), pointer_size)?, "placing delay unload IAT")?;
            Some(offset)
        } else {
            None
        };

        let mut imports = Vec::with_capacity(descriptor.imports.len());
        for function in &descriptor.imports {
            let name_offset = match function.name.as_deref() {
                Some(name) if !name.is_empty() => {
                    validate_cstr(name)?;
                    cursor = align_up_usize(cursor, 2)?;
                    let offset = cursor;
                    cursor = checked_add_usize(cursor, hint_name_size(name)?, "placing delay-import hint/name")?;
                    Some(offset)
                }
                _ if function.ordinal.is_some() => None,
                _ => {
                    return Err(DelayImportError::MissingFunctionTarget {
                        descriptor_index: descriptor.index,
                        function_index: function.index,
                    });
                }
            };

            imports.push(DelayImportThunkLayout {
                name_offset,
                hint: function.hint,
                name: function.name.clone(),
                ordinal: function.ordinal,
            });
        }

        import_count = import_count
            .checked_add(descriptor.imports.len())
            .ok_or(DelayImportError::Overflow("counting delay imports"))?;

        layouts.push(DelayImportDescriptorLayout {
            descriptor_offset: layouts.len() * DELAY_IMPORT_DESCRIPTOR_SIZE,
            dll_name_offset,
            module_handle_offset,
            iat_offset,
            int_offset,
            unload_iat_offset,
            time_date_stamp: descriptor.time_date_stamp,
            imports,
        });
    }

    Ok(DelayImportSection {
        size: align_up_usize(cursor, pointer_size)?,
        directory_size: u32::try_from(directory_size)
            .map_err(|_| DelayImportError::Overflow("converting delay-import directory size to u32"))?,
        descriptor_count: descriptors.len(),
        import_count,
        pointer_size,
        descriptors: descriptors.to_vec(),
        layouts,
    })
}

fn write_delay_import_section_data(
    data: &mut [u8],
    section_rva: u32,
    descriptors: &[DelayImportDescriptor],
    layouts: &[DelayImportDescriptorLayout],
    pointer_size: usize,
) -> Result<(), DelayImportError> {
    for (descriptor, layout) in descriptors.iter().zip(layouts) {
        write_cstr(data, layout.dll_name_offset, descriptor.dll_name.as_deref().unwrap_or_default())?;
        write_descriptor(data, section_rva, layout)?;
        write_thunk_table(data, section_rva, layout.iat_offset, &layout.imports, pointer_size)?;
        write_thunk_table(data, section_rva, layout.int_offset, &layout.imports, pointer_size)?;

        if let Some(unload_iat_offset) = layout.unload_iat_offset {
            write_thunk_table(data, section_rva, unload_iat_offset, &layout.imports, pointer_size)?;
        }

        for function in &layout.imports {
            if let (Some(name_offset), Some(name)) = (function.name_offset, function.name.as_deref()) {
                write_u16_at(data, name_offset, function.hint.unwrap_or(0))?;
                write_cstr(data, name_offset + 2, name)?;
            }
        }
    }

    Ok(())
}

fn write_descriptor(
    data: &mut [u8],
    section_rva: u32,
    layout: &DelayImportDescriptorLayout,
) -> Result<(), DelayImportError> {
    write_u32_at(data, layout.descriptor_offset, DELAY_IMPORT_ATTRIBUTES_RVA_BASED)?;
    write_u32_at(data, layout.descriptor_offset + 4, rva_from_offset(section_rva, layout.dll_name_offset)?)?;
    write_u32_at(data, layout.descriptor_offset + 8, rva_from_offset(section_rva, layout.module_handle_offset)?)?;
    write_u32_at(data, layout.descriptor_offset + 12, rva_from_offset(section_rva, layout.iat_offset)?)?;
    write_u32_at(data, layout.descriptor_offset + 16, rva_from_offset(section_rva, layout.int_offset)?)?;
    write_u32_at(data, layout.descriptor_offset + 20, 0)?;
    write_u32_at(
        data,
        layout.descriptor_offset + 24,
        layout
            .unload_iat_offset
            .map(|offset| rva_from_offset(section_rva, offset))
            .transpose()?
            .unwrap_or(0),
    )?;
    write_u32_at(data, layout.descriptor_offset + 28, if layout.unload_iat_offset.is_some() {
        layout.time_date_stamp
    } else {
        0
    })
}

fn write_thunk_table(
    data: &mut [u8],
    section_rva: u32,
    table_offset: usize,
    imports: &[DelayImportThunkLayout],
    pointer_size: usize,
) -> Result<(), DelayImportError> {
    for (index, function) in imports.iter().enumerate() {
        let entry_offset = table_offset
            .checked_add(index * pointer_size)
            .ok_or(DelayImportError::Overflow("writing delay-import thunk table"))?;
        let value = match function.ordinal {
            Some(ordinal) => ordinal_flag(pointer_size) | u64::from(ordinal),
            None => rva_from_offset(section_rva, function.name_offset.unwrap_or_default())? as u64,
        };

        write_pointer_at(data, entry_offset, pointer_size, value)?;
    }

    Ok(())
}

fn thunk_table_size(import_count: usize, pointer_size: usize) -> Result<usize, DelayImportError> {
    checked_mul_usize(
        import_count
            .checked_add(1)
            .ok_or(DelayImportError::Overflow("sizing delay-import thunk table"))?,
        pointer_size,
        "sizing delay-import thunk table",
    )
}

fn hint_name_size(name: &str) -> Result<usize, DelayImportError> {
    checked_add_usize(2, cstr_size(name)?, "sizing delay-import hint/name")
}

fn cstr_size(value: &str) -> Result<usize, DelayImportError> {
    checked_add_usize(value.as_bytes().len(), 1, "sizing delay-import string")
}

fn validate_cstr(value: &str) -> Result<(), DelayImportError> {
    if value.as_bytes().contains(&0) {
        return Err(DelayImportError::NameContainsNul(value.to_string()));
    }

    Ok(())
}

fn rva_from_offset(section_rva: u32, offset: usize) -> Result<u32, DelayImportError> {
    section_rva
        .checked_add(
            u32::try_from(offset)
                .map_err(|_| DelayImportError::Overflow("converting delay-import offset to RVA"))?,
        )
        .ok_or(DelayImportError::Overflow("computing delay-import RVA"))
}

fn write_cstr(
    data: &mut [u8],
    offset: usize,
    value: &str,
) -> Result<(), DelayImportError> {
    checked_range_mut(data, offset, value.as_bytes().len())?
        .copy_from_slice(value.as_bytes());
    let terminator_offset = checked_add_usize(
        offset,
        value.as_bytes().len(),
        "writing delay-import string terminator",
    )?;
    checked_range_mut(data, terminator_offset, 1)?[0] = 0;

    Ok(())
}

fn write_pointer_at(
    data: &mut [u8],
    offset: usize,
    pointer_size: usize,
    value: u64,
) -> Result<(), DelayImportError> {
    match pointer_size {
        4 => {
            let value = u32::try_from(value)
                .map_err(|_| DelayImportError::Overflow("writing 32-bit delay-import pointer"))?;
            write_u32_at(data, offset, value)
        }
        8 => {
            checked_range_mut(data, offset, 8)?
                .copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        _ => Err(DelayImportError::Overflow("writing unsupported delay-import pointer size")),
    }
}

fn write_u16_at(
    data: &mut [u8],
    offset: usize,
    value: u16,
) -> Result<(), DelayImportError> {
    checked_range_mut(data, offset, 2)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_at(
    data: &mut [u8],
    offset: usize,
    value: u32,
) -> Result<(), DelayImportError> {
    checked_range_mut(data, offset, 4)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_up_usize(value: usize, alignment: usize) -> Result<usize, DelayImportError> {
    if alignment == 0 {
        return Err(DelayImportError::Overflow("aligning delay-import data"));
    }

    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(DelayImportError::Overflow("aligning delay-import data"))
}

fn checked_add_usize(
    lhs: usize,
    rhs: usize,
    action: &'static str,
) -> Result<usize, DelayImportError> {
    lhs.checked_add(rhs).ok_or(DelayImportError::Overflow(action))
}

fn checked_mul_usize(
    lhs: usize,
    rhs: usize,
    action: &'static str,
) -> Result<usize, DelayImportError> {
    lhs.checked_mul(rhs).ok_or(DelayImportError::Overflow(action))
}

fn delay_import_directory(image: &Image) -> Result<Option<DataDirectory>, DelayImportError> {
    match image.data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        Ok(directory) if directory.virtual_address == 0 && directory.size == 0 => Ok(None),
        Ok(directory) if directory.is_empty() => Err(DelayImportError::InvalidDescriptor { rva: directory.virtual_address, reason: "partial directory entry" }),
        Ok(directory) => Ok(Some(directory)),
        Err(ImageError::DataDirectoryMissing { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_delay_import_functions(
    image: &Image,
    descriptor_index: usize,
    import_name_table_rva: u32,
    import_address_table_rva: Option<u32>,
    rva_based: bool,
    layout: DelayImportLayout,
) -> Result<Vec<DelayImportFunction>, DelayImportError> {
    let pointer_size = image.pointer_size();
    let ordinal_flag = ordinal_flag(pointer_size);
    let mut functions = Vec::new();

    for index in 0..MAX_DELAY_IMPORTS_PER_DESCRIPTOR {
        let entry_offset = index
            .checked_mul(pointer_size)
            .ok_or(DelayImportError::Overflow("walking delay-import thunk table"))?;
        let int_entry_rva = import_name_table_rva
            .checked_add(
                u32::try_from(entry_offset)
                    .map_err(|_| DelayImportError::Overflow("converting delay-import thunk offset to RVA"))?,
            )
            .ok_or(DelayImportError::Overflow("walking delay-import thunk table"))?;
        let raw_value = read_pointer_rva(image, int_entry_rva, pointer_size, layout)?;
        if raw_value == 0 {
            return Ok(functions);
        }

        let import_address_table_rva = import_address_table_rva
            .map(|rva| {
                rva.checked_add(
                    u32::try_from(entry_offset)
                        .map_err(|_| DelayImportError::Overflow("converting delay-import IAT offset to RVA"))?,
                )
                .ok_or(DelayImportError::Overflow("walking delay-import IAT table"))
            })
            .transpose()?;

        let (name_rva, hint, name, ordinal) = if raw_value & ordinal_flag != 0 {
            if raw_value & !(ordinal_flag | 0xffff) != 0 {
                return Err(DelayImportError::InvalidDescriptor { rva: int_entry_rva, reason: "reserved ordinal bits are set" });
            }
            (None, None, None, Some((raw_value & 0xffff) as u16))
        } else {
            let name_rva = normalize_thunk_rva(image, raw_value, rva_based)?;
            let hint = read_u16_rva(image, name_rva, layout)?;
            let name = read_cstr_rva(image, name_rva.checked_add(2).ok_or(DelayImportError::Overflow("locating delay-import name"))?, layout)?;
            (Some(name_rva), Some(hint), Some(name), None)
        };

        functions.push(DelayImportFunction {
            index,
            import_name_table_rva: int_entry_rva,
            import_address_table_rva,
            raw_value,
            name_rva,
            hint,
            name,
            ordinal,
        });
    }

    Err(DelayImportError::ImportTableTooLong {
        descriptor_index,
        limit: MAX_DELAY_IMPORTS_PER_DESCRIPTOR,
    })
}

fn normalize_descriptor_rva(
    image: &Image,
    raw_value: u32,
    rva_based: bool,
) -> Result<Option<u32>, DelayImportError> {
    if raw_value == 0 {
        return Ok(None);
    }

    if rva_based {
        Ok(Some(raw_value))
    } else {
        Ok(Some(va_to_rva_checked(image, raw_value as u64)?))
    }
}

fn normalize_thunk_rva(
    image: &Image,
    raw_value: u64,
    rva_based: bool,
) -> Result<u32, DelayImportError> {
    if rva_based {
        u32::try_from(raw_value)
            .map_err(|_| DelayImportError::Overflow("converting delay-import thunk value to RVA"))
    } else {
        va_to_rva_checked(image, raw_value)
    }
}

fn va_to_rva_checked(image: &Image, address: u64) -> Result<u32, DelayImportError> {
    let image_base = image.image_base()?;
    if address < image_base {
        return Err(DelayImportError::AddressBeforeImage { address, image_base });
    }

    u32::try_from(address - image_base)
        .map_err(|_| DelayImportError::Overflow("converting delay-import VA to RVA"))
}

fn read_pointer_rva(
    image: &Image,
    rva: u32,
    pointer_size: usize,
    layout: DelayImportLayout,
) -> Result<u64, DelayImportError> {
    let data = read_rva_bytes(image, rva, pointer_size, layout)?;
    read_pointer(&data, 0, pointer_size)
}

fn read_u16_rva(
    image: &Image,
    rva: u32,
    layout: DelayImportLayout,
) -> Result<u16, DelayImportError> {
    let data = read_rva_bytes(image, rva, 2, layout)?;
    read_u16(&data, 0)
}

fn read_cstr_rva(
    image: &Image,
    rva: u32,
    layout: DelayImportLayout,
) -> Result<String, DelayImportError> {
    let mut bytes = Vec::new();

    for index in 0..MAX_DELAY_IMPORT_NAME {
        let byte_rva = rva
            .checked_add(
                u32::try_from(index)
                    .map_err(|_| DelayImportError::Overflow("walking delay-import string"))?,
            )
            .ok_or(DelayImportError::Overflow("walking delay-import string"))?;
        let byte = read_rva_bytes(image, byte_rva, 1, layout)?[0];
        if byte == 0 {
            return Ok(String::from_utf8_lossy(&bytes).into_owned());
        }

        bytes.push(byte);
    }

    Err(DelayImportError::UnterminatedString { rva })
}

fn read_rva_bytes(
    image: &Image,
    rva: u32,
    size: usize,
    layout: DelayImportLayout,
) -> Result<Vec<u8>, DelayImportError> {
    match layout {
        DelayImportLayout::File => Ok(image.read_bytes_rva(rva, size)?),
        DelayImportLayout::MappedImage => Ok(image.read_mapped_bytes_rva(rva, size)?),
    }
}

fn ordinal_flag(pointer_size: usize) -> u64 {
    match pointer_size {
        4 => IMAGE_ORDINAL_FLAG32,
        8 => IMAGE_ORDINAL_FLAG64,
        _ => 0,
    }
}

fn read_pointer(data: &[u8], offset: usize, pointer_size: usize) -> Result<u64, DelayImportError> {
    match pointer_size {
        4 => Ok(read_u32(data, offset)? as u64),
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(checked_range(data, offset, 8)?);
            Ok(u64::from_le_bytes(bytes))
        }
        _ => Err(DelayImportError::Overflow("reading delay-import pointer with unsupported size")),
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, DelayImportError> {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(checked_range(data, offset, 2)?);
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, DelayImportError> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(checked_range(data, offset, 4)?);
    Ok(u32::from_le_bytes(bytes))
}

fn checked_range(data: &[u8], offset: usize, size: usize) -> Result<&[u8], DelayImportError> {
    let end = offset
        .checked_add(size)
        .ok_or(DelayImportError::Overflow("checking delay-import range"))?;

    data.get(offset..end)
        .ok_or_else(|| ImageError::OutOfBounds { offset, size }.into())
}

fn checked_range_mut(
    data: &mut [u8],
    offset: usize,
    size: usize,
) -> Result<&mut [u8], DelayImportError> {
    let end = offset
        .checked_add(size)
        .ok_or(DelayImportError::Overflow("checking delay-import range"))?;

    data.get_mut(offset..end)
        .ok_or_else(|| ImageError::OutOfBounds { offset, size }.into())
}

#[cfg(test)]
#[path = "tests/delay_imports/mod.rs"]
mod tests;
