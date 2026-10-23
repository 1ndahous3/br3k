use super::rebuild::ImportThunkLayout;
use super::types::*;

pub(super) fn read_iat_pointer(chunk: &[u8], pointer_size: usize) -> Result<u64, ImportError> {
    match pointer_size {
        4 => {
            let bytes: [u8; 4] = chunk
                .try_into()
                .map_err(|_| ImportError::InvalidPointerSize(pointer_size))?;
            Ok(u32::from_le_bytes(bytes) as u64)
        }
        8 => {
            let bytes: [u8; 8] = chunk
                .try_into()
                .map_err(|_| ImportError::InvalidPointerSize(pointer_size))?;
            Ok(u64::from_le_bytes(bytes))
        }
        _ => Err(ImportError::InvalidPointerSize(pointer_size)),
    }
}

pub(super) fn is_zero_pointer_at(data: &[u8], offset: usize, pointer_size: usize) -> Result<bool, ImportError> {
    if offset + pointer_size > data.len() {
        return Ok(false);
    }

    Ok(read_iat_pointer(&data[offset..offset + pointer_size], pointer_size)? == 0)
}

pub(super) fn validate_pointer_size(pointer_size: usize) -> Result<(), ImportError> {
    match pointer_size {
        4 | 8 => Ok(()),
        _ => Err(ImportError::InvalidPointerSize(pointer_size)),
    }
}

pub(super) fn thunk_count(first_thunk: u32, last_thunk: u32, pointer_size: u32) -> Result<u32, ImportError> {
    let span = last_thunk
        .checked_sub(first_thunk)
        .ok_or(ImportError::Overflow("computing import module thunk count"))?;

    span.checked_div(pointer_size)
        .and_then(|span| span.checked_add(1))
        .ok_or(ImportError::Overflow("computing import module thunk count"))
}

pub(super) fn validate_import_target(target: &ImportTarget) -> Result<(), ImportError> {
    match target {
        ImportTarget::Name { name, .. } => validate_cstr(name),
        ImportTarget::Ordinal(_) => Ok(()),
        ImportTarget::Unknown(_) => Ok(()),
    }
}

pub(super) fn validate_cstr(value: &str) -> Result<(), ImportError> {
    if value.as_bytes().contains(&0) {
        return Err(ImportError::NameContainsNul(value.to_string()));
    }

    Ok(())
}

pub(super) fn thunk_value(
    thunk: &ImportThunkLayout,
    base_rva: u32,
    pointer_size: usize,
) -> Result<u64, ImportError> {
    match &thunk.target {
        ImportTarget::Name { .. } => {
            let name_offset = thunk
                .import_name_offset
                .ok_or(ImportError::MissingFunctionTarget)?;
            Ok(rva_from_offset(base_rva, name_offset)? as u64)
        }
        ImportTarget::Ordinal(ordinal) if pointer_size == 4 => Ok(IMAGE_ORDINAL_FLAG32 | *ordinal as u64),
        ImportTarget::Ordinal(ordinal) => Ok(IMAGE_ORDINAL_FLAG64 | *ordinal as u64),
        ImportTarget::Unknown(address) => Err(ImportError::UnresolvedImportTarget(*address)),
    }
}

pub(super) fn rva_from_offset(base_rva: u32, offset: usize) -> Result<u32, ImportError> {
    let offset = u32::try_from(offset)
        .map_err(|_| ImportError::Overflow("converting import offset to RVA"))?;
    base_rva
        .checked_add(offset)
        .ok_or(ImportError::Overflow("computing import RVA"))
}

pub(super) fn write_cstr(blob: &mut [u8], offset: usize, value: &str) -> Result<(), ImportError> {
    let bytes = value.as_bytes();
    let range = checked_range(blob.len(), offset, bytes.len() + 1, "writing C string")?;
    blob[range.start..range.start + bytes.len()].copy_from_slice(bytes);
    blob[range.end - 1] = 0;
    Ok(())
}

pub(super) fn write_u16(blob: &mut [u8], offset: usize, value: u16) -> Result<(), ImportError> {
    write_bytes(blob, offset, &value.to_le_bytes())
}

pub(super) fn write_u32(blob: &mut [u8], offset: usize, value: u32) -> Result<(), ImportError> {
    write_bytes(blob, offset, &value.to_le_bytes())
}

pub(super) fn write_pointer(
    blob: &mut [u8],
    offset: usize,
    pointer_size: usize,
    value: u64,
) -> Result<(), ImportError> {
    match pointer_size {
        4 => {
            let value = u32::try_from(value)
                .map_err(|_| ImportError::Overflow("writing 32-bit import thunk"))?;
            write_bytes(blob, offset, &value.to_le_bytes())
        }
        8 => write_bytes(blob, offset, &value.to_le_bytes()),
        _ => Err(ImportError::Overflow("writing import thunk with unsupported pointer size")),
    }
}

pub(super) fn write_bytes(blob: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), ImportError> {
    let range = checked_range(blob.len(), offset, bytes.len(), "writing import blob")?;
    blob[range].copy_from_slice(bytes);
    Ok(())
}

pub(super) fn checked_range(
    len: usize,
    offset: usize,
    size: usize,
    operation: &'static str,
) -> Result<std::ops::Range<usize>, ImportError> {
    let end = checked_add(offset, size, operation)?;
    if end > len {
        return Err(ImportError::Overflow(operation));
    }

    Ok(offset..end)
}

pub(super) fn checked_add(a: usize, b: usize, operation: &'static str) -> Result<usize, ImportError> {
    a.checked_add(b).ok_or(ImportError::Overflow(operation))
}

pub(super) fn checked_mul(a: usize, b: usize, operation: &'static str) -> Result<usize, ImportError> {
    a.checked_mul(b).ok_or(ImportError::Overflow(operation))
}

pub(super) fn align_2(value: usize) -> Result<usize, ImportError> {
    value
        .checked_add(1)
        .map(|value| value & !1)
        .ok_or(ImportError::Overflow("aligning import blob"))
}

pub(super) const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub(super) const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub(super) const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub(super) const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub(super) const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = 20;
pub(super) const IMAGE_ORDINAL_FLAG32: u64 = 0x8000_0000;
pub(super) const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;
pub(super) const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub(super) const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub(super) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub(super) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub(super) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub(super) const IAT_SCAN_MAX_GAP_POINTERS: usize = 16;
pub(super) const ARM64_NOP: u32 = 0xd503_201f;
