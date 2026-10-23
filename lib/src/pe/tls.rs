use crate::pe::format::PE_DIRECTORY_ENTRY_TLS;
use crate::pe::image::{DataDirectory, Error as ImageError, Format, Image};

pub const MAX_TLS_CALLBACKS: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("PE TLS directory size 0x{size:x} is smaller than expected size 0x{expected:x}")]
    DirectoryTooSmall { size: u32, expected: usize },
    #[error("PE TLS callback table VA 0x{address:x} is below image base 0x{image_base:x}")]
    AddressBeforeImage { address: u64, image_base: u64 },
    #[error("PE TLS callback table has no null terminator within {limit} entries")]
    CallbackTableTooLong { limit: usize },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsLayout {
    File,
    MappedImage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCallback {
    pub index: usize,
    pub address: u64,
    pub rva: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsDirectory {
    pub rva: u32,
    pub size: u32,
    pub start_raw_data: u64,
    pub end_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub callbacks: Vec<TlsCallback>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSanitizeResult {
    pub image: Vec<u8>,
    pub directory_present: bool,
    pub callback_count: usize,
    pub cleared_callbacks: bool,
    pub cleared_directory: bool,
}

#[derive(Clone, Copy, Debug)]
struct TlsOffsets {
    pointer_size: usize,
    directory_size: usize,
    start_raw_data: usize,
    end_raw_data: usize,
    address_of_index: usize,
    address_of_callbacks: usize,
    size_of_zero_fill: usize,
    characteristics: usize,
}

impl Image {
    pub fn tls_directory(&self) -> Result<Option<TlsDirectory>, TlsError> {
        tls_directory_with_layout(self, TlsLayout::File)
    }

    pub fn mapped_tls_directory(&self) -> Result<Option<TlsDirectory>, TlsError> {
        tls_directory_with_layout(self, TlsLayout::MappedImage)
    }

    pub fn clear_tls_callbacks(&self) -> Result<TlsSanitizeResult, TlsError> {
        clear_tls_callbacks_with_layout(self, TlsLayout::File)
    }

    pub fn clear_mapped_tls_callbacks(&self) -> Result<TlsSanitizeResult, TlsError> {
        clear_tls_callbacks_with_layout(self, TlsLayout::MappedImage)
    }

    pub fn clear_tls_directory(&self) -> Result<TlsSanitizeResult, TlsError> {
        clear_tls_directory(self)
    }
}

pub fn tls_directory_with_layout(
    image: &Image,
    layout: TlsLayout,
) -> Result<Option<TlsDirectory>, TlsError> {
    let Some(directory) = tls_data_directory(image)? else {
        return Ok(None);
    };
    let offsets = tls_offsets(image.format());
    ensure_directory_size(directory, offsets)?;
    let directory_data = read_rva_bytes(image, directory.virtual_address, offsets.directory_size, layout)?;

    let start_raw_data = read_pointer(&directory_data, offsets.start_raw_data, offsets.pointer_size)?;
    let end_raw_data = read_pointer(&directory_data, offsets.end_raw_data, offsets.pointer_size)?;
    let address_of_index = read_pointer(&directory_data, offsets.address_of_index, offsets.pointer_size)?;
    let address_of_callbacks = read_pointer(
        &directory_data,
        offsets.address_of_callbacks,
        offsets.pointer_size,
    )?;
    let size_of_zero_fill = read_u32(&directory_data, offsets.size_of_zero_fill)?;
    let characteristics = read_u32(&directory_data, offsets.characteristics)?;
    let callbacks = read_tls_callbacks(image, address_of_callbacks, layout)?;

    Ok(Some(TlsDirectory {
        rva: directory.virtual_address,
        size: directory.size,
        start_raw_data,
        end_raw_data,
        address_of_index,
        address_of_callbacks,
        size_of_zero_fill,
        characteristics,
        callbacks,
    }))
}

pub fn clear_tls_callbacks_with_layout(
    image: &Image,
    layout: TlsLayout,
) -> Result<TlsSanitizeResult, TlsError> {
    let Some(directory) = tls_data_directory(image)? else {
        return Ok(TlsSanitizeResult {
            image: image.data().to_vec(),
            directory_present: false,
            callback_count: 0,
            cleared_callbacks: false,
            cleared_directory: false,
        });
    };

    let offsets = tls_offsets(image.format());
    ensure_directory_size(directory, offsets)?;
    let callback_count = tls_directory_with_layout(image, layout)
        .ok()
        .flatten()
        .map(|directory| directory.callbacks.len())
        .unwrap_or(0);
    let mut output = Image::parse(image.data().to_vec())?;
    let callbacks_rva = directory
        .virtual_address
        .checked_add(offsets.address_of_callbacks as u32)
        .ok_or(TlsError::Overflow("locating TLS callback pointer field"))?;
    let callbacks_offset = offset_for_rva(&output, callbacks_rva, offsets.pointer_size, layout)?;

    output.write_pointer(callbacks_offset, offsets.pointer_size, 0)?;

    Ok(TlsSanitizeResult {
        image: output.into_data(),
        directory_present: true,
        callback_count,
        cleared_callbacks: true,
        cleared_directory: false,
    })
}

pub fn clear_tls_directory(image: &Image) -> Result<TlsSanitizeResult, TlsError> {
    let directory_present = tls_data_directory(image)?.is_some();
    let callback_count = image
        .tls_directory()
        .ok()
        .flatten()
        .map(|directory| directory.callbacks.len())
        .unwrap_or(0);
    let mut output = Image::parse(image.data().to_vec())?;

    output.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_TLS)?;

    Ok(TlsSanitizeResult {
        image: output.into_data(),
        directory_present,
        callback_count,
        cleared_callbacks: false,
        cleared_directory: directory_present,
    })
}

fn tls_data_directory(image: &Image) -> Result<Option<DataDirectory>, TlsError> {
    match image.data_directory(PE_DIRECTORY_ENTRY_TLS) {
        Ok(directory) if directory.is_empty() => Ok(None),
        Ok(directory) => Ok(Some(directory)),
        Err(ImageError::DataDirectoryMissing { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn tls_offsets(format: Format) -> TlsOffsets {
    match format {
        Format::Pe32 => TlsOffsets {
            pointer_size: 4,
            directory_size: 24,
            start_raw_data: 0,
            end_raw_data: 4,
            address_of_index: 8,
            address_of_callbacks: 12,
            size_of_zero_fill: 16,
            characteristics: 20,
        },
        Format::Pe64 => TlsOffsets {
            pointer_size: 8,
            directory_size: 40,
            start_raw_data: 0,
            end_raw_data: 8,
            address_of_index: 16,
            address_of_callbacks: 24,
            size_of_zero_fill: 32,
            characteristics: 36,
        },
    }
}

fn ensure_directory_size(
    directory: DataDirectory,
    offsets: TlsOffsets,
) -> Result<(), TlsError> {
    if (directory.size as usize) < offsets.directory_size {
        return Err(TlsError::DirectoryTooSmall {
            size: directory.size,
            expected: offsets.directory_size,
        });
    }

    Ok(())
}

fn read_tls_callbacks(
    image: &Image,
    callbacks_va: u64,
    layout: TlsLayout,
) -> Result<Vec<TlsCallback>, TlsError> {
    if callbacks_va == 0 {
        return Ok(Vec::new());
    }

    let pointer_size = image.pointer_size();
    let table_rva = va_to_rva_checked(image, callbacks_va)?;
    let mut callbacks = Vec::new();

    for index in 0..MAX_TLS_CALLBACKS {
        let byte_offset = index
            .checked_mul(pointer_size)
            .ok_or(TlsError::Overflow("walking TLS callback table"))?;
        let rva = table_rva
            .checked_add(
                u32::try_from(byte_offset)
                    .map_err(|_| TlsError::Overflow("converting TLS callback offset to RVA"))?,
            )
            .ok_or(TlsError::Overflow("walking TLS callback table"))?;
        let data = read_rva_bytes(image, rva, pointer_size, layout)?;
        let address = read_pointer(&data, 0, pointer_size)?;
        if address == 0 {
            return Ok(callbacks);
        }

        callbacks.push(TlsCallback {
            index,
            address,
            rva: va_to_rva(image, address),
        });
    }

    Err(TlsError::CallbackTableTooLong {
        limit: MAX_TLS_CALLBACKS,
    })
}

fn va_to_rva_checked(image: &Image, address: u64) -> Result<u32, TlsError> {
    let image_base = image.address_base()?;
    if address < image_base {
        return Err(TlsError::AddressBeforeImage { address, image_base });
    }

    u32::try_from(address - image_base)
        .map_err(|_| TlsError::Overflow("converting TLS VA to RVA"))
}

fn va_to_rva(image: &Image, address: u64) -> Option<u32> {
    va_to_rva_checked(image, address).ok()
}

fn read_rva_bytes(
    image: &Image,
    rva: u32,
    size: usize,
    layout: TlsLayout,
) -> Result<Vec<u8>, TlsError> {
    match layout {
        TlsLayout::File => Ok(image.read_bytes_rva(rva, size)?),
        TlsLayout::MappedImage => Ok(image.read_mapped_bytes_rva(rva, size)?),
    }
}

fn offset_for_rva(
    image: &Image,
    rva: u32,
    size: usize,
    layout: TlsLayout,
) -> Result<usize, TlsError> {
    match layout {
        TlsLayout::File => Ok(image.rva_to_file_offset(rva)?),
        TlsLayout::MappedImage => {
            let offset = rva as usize;
            let end = offset
                .checked_add(size)
                .ok_or(TlsError::Overflow("checking mapped TLS offset"))?;

            if image.data().get(offset..end).is_none() {
                return Err(ImageError::OutOfBounds { offset, size }.into());
            }

            Ok(offset)
        }
    }
}

fn read_pointer(data: &[u8], offset: usize, pointer_size: usize) -> Result<u64, TlsError> {
    match pointer_size {
        4 => Ok(read_u32(data, offset)? as u64),
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(checked_range(data, offset, 8)?);
            Ok(u64::from_le_bytes(bytes))
        }
        _ => Err(TlsError::Overflow("reading PE pointer with unsupported size")),
    }
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, TlsError> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(checked_range(data, offset, 4)?);
    Ok(u32::from_le_bytes(bytes))
}

fn checked_range(data: &[u8], offset: usize, size: usize) -> Result<&[u8], TlsError> {
    let end = offset
        .checked_add(size)
        .ok_or(TlsError::Overflow("checking TLS directory range"))?;

    data.get(offset..end)
        .ok_or_else(|| ImageError::OutOfBounds { offset, size }.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pe64_tls_callbacks() {
        let image = Image::parse(test_pe64_with_tls()).unwrap();
        let tls = image.tls_directory().unwrap().unwrap();

        assert_eq!(tls.rva, 0x2000);
        assert_eq!(tls.address_of_callbacks, 0x180002040);
        assert_eq!(tls.callbacks.len(), 1);
        assert_eq!(tls.callbacks[0].index, 0);
        assert_eq!(tls.callbacks[0].address, 0x180001234);
        assert_eq!(tls.callbacks[0].rva, Some(0x1234));
    }

    #[test]
    fn clears_pe64_tls_callbacks() {
        let image = Image::parse(test_pe64_with_tls()).unwrap();

        let result = image.clear_tls_callbacks().unwrap();
        let fixed = Image::parse(result.image).unwrap();
        let fixed_tls = fixed.tls_directory().unwrap().unwrap();

        assert!(result.directory_present);
        assert_eq!(result.callback_count, 1);
        assert!(result.cleared_callbacks);
        assert_eq!(fixed_tls.address_of_callbacks, 0);
        assert!(fixed_tls.callbacks.is_empty());
    }

    #[test]
    fn clears_pe64_tls_directory() {
        let image = Image::parse(test_pe64_with_tls()).unwrap();

        let result = image.clear_tls_directory().unwrap();
        let fixed = Image::parse(result.image).unwrap();

        assert!(result.directory_present);
        assert_eq!(result.callback_count, 1);
        assert!(result.cleared_directory);
        assert!(fixed.tls_directory().unwrap().is_none());
    }

    fn test_pe64_with_tls() -> Vec<u8> {
        let mut data = vec![0u8; 0x600];

        write_u16(&mut data, 0, 0x5a4d);
        write_u32(&mut data, 0x3c, 0x80);
        write_u32(&mut data, 0x80, 0x4550);

        let file_header = 0x84;
        write_u16(&mut data, file_header, 0x8664);
        write_u16(&mut data, file_header + 2, 2);
        write_u16(&mut data, file_header + 16, 0xf0);

        let optional = 0x98;
        write_u16(&mut data, optional, 0x20b);
        write_u32(&mut data, optional + 16, 0x1000);
        write_u64(&mut data, optional + 24, 0x180000000);
        write_u32(&mut data, optional + 32, 0x1000);
        write_u32(&mut data, optional + 36, 0x200);
        write_u32(&mut data, optional + 56, 0x3000);
        write_u32(&mut data, optional + 60, 0x200);
        write_u32(&mut data, optional + 108, 16);

        let tls_directory = optional + 112 + PE_DIRECTORY_ENTRY_TLS * 8;
        write_u32(&mut data, tls_directory, 0x2000);
        write_u32(&mut data, tls_directory + 4, 40);

        let sections = optional + 0xf0;
        write_section(&mut data, sections, b".text", 0x1000, 0x1000, 0x200, 0x200, 0x60000020);
        write_section(&mut data, sections + 40, b".rdata", 0x1000, 0x2000, 0x200, 0x400, 0x40000040);

        write_u64(&mut data, 0x400 + 24, 0x180002040);
        write_u64(&mut data, 0x400 + 0x40, 0x180001234);
        write_u64(&mut data, 0x400 + 0x48, 0);

        data
    }

    fn write_section(
        data: &mut [u8],
        offset: usize,
        name: &[u8],
        virtual_size: u32,
        virtual_address: u32,
        raw_size: u32,
        raw_offset: u32,
        characteristics: u32,
    ) {
        data[offset..offset + name.len()].copy_from_slice(name);
        write_u32(data, offset + 8, virtual_size);
        write_u32(data, offset + 12, virtual_address);
        write_u32(data, offset + 16, raw_size);
        write_u32(data, offset + 20, raw_offset);
        write_u32(data, offset + 36, characteristics);
    }

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
