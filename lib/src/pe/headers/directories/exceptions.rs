use super::validate::{u32_at, Reader, ValidationError};
use crate::pe::format::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, PE_DIRECTORY_ENTRY_EXCEPTION};
use crate::pe::image::Image;
use std::collections::BTreeSet;

pub(super) fn validate(image: &Image) -> Result<(), ValidationError> {
    let reader = Reader { image };
    if image.data_directory(PE_DIRECTORY_ENTRY_EXCEPTION)?.virtual_address % 4 != 0 {
        return Err(ValidationError::Invalid("Unaligned runtime-function table"));
    }
    let data = reader.directory(PE_DIRECTORY_ENTRY_EXCEPTION)?;
    let stride = match image.machine() {
        IMAGE_FILE_MACHINE_AMD64 => 12,
        IMAGE_FILE_MACHINE_ARM64 => 8,
        _ => return Err(ValidationError::Unsupported("Exception directory format is not x64 or ARM64; x86 SafeSEH belongs to load config")),
    };
    if data.is_empty() || data.len() % stride != 0 {
        return Err(ValidationError::Invalid("Partial runtime-function record"));
    }
    let mut previous_end = 0;
    for record in data.chunks_exact(stride) {
        let begin = u32_at(record, 0);
        let end = if stride == 12 {
            let end = u32_at(record, 4);
            reader.code(begin, end.checked_sub(begin).ok_or(ValidationError::Invalid("Inverted runtime-function range"))?)?;
            x64_unwind(&reader, u32_at(record, 8))?;
            end
        } else {
            if begin % 4 != 0 { return Err(ValidationError::Invalid("Unaligned ARM64 function address")); }
            let length = arm64_unwind(&reader, u32_at(record, 4))?;
            reader.code(begin, length)?;
            begin.checked_add(length).ok_or(ValidationError::Invalid("Runtime-function range overflow"))?
        };
        if begin < previous_end { return Err(ValidationError::Invalid("Runtime-function ranges are unsorted or overlap")); }
        previous_end = end;
    }
    Ok(())
}

fn x64_unwind(reader: &Reader, mut rva: u32) -> Result<(), ValidationError> {
    let mut visited = BTreeSet::new();
    for _ in 0..32 {
        if rva % 4 != 0 || !visited.insert(rva) { return Err(ValidationError::Invalid("Unaligned or cyclic x64 unwind record")); }
        let header = reader.bytes(rva, 4)?;
        if !matches!(header[0] & 7, 1 | 2) { return Err(ValidationError::Unsupported("Unsupported x64 unwind version")); }
        let flags = header[0] >> 3;
        if flags & !7 != 0 || flags & 4 != 0 && flags & 3 != 0 {
            return Err(ValidationError::Invalid("Invalid x64 unwind flags"));
        }
        let size = 4 + ((header[2] as usize + 1) & !1) * 2;
        let tail_size = if flags & 4 != 0 { 12 } else if flags & 3 != 0 { 4 } else { 0 };
        let record = reader.bytes(rva, size + tail_size)?;
        if flags & 4 != 0 {
            let begin = u32_at(record, size);
            let end = u32_at(record, size + 4);
            reader.code(begin, end.checked_sub(begin).ok_or(ValidationError::Invalid("Inverted chained function range"))?)?;
            rva = u32_at(record, size + 8);
        } else {
            if flags & 3 != 0 { reader.code(u32_at(record, size), 1)?; }
            return Ok(());
        }
    }
    Err(ValidationError::Invalid("x64 unwind chain exceeds validation limit"))
}

fn arm64_unwind(reader: &Reader, value: u32) -> Result<u32, ValidationError> {
    match value & 3 {
        1 | 2 => {
            if (value >> 16) & 15 > 10 { return Err(ValidationError::Invalid("Invalid ARM64 packed integer-register count")); }
            return Ok(((value >> 2) & 0x7ff) * 4);
        }
        3 => return Err(ValidationError::Invalid("Reserved ARM64 packed-unwind flag")),
        _ => {}
    }
    let header = reader.u32(value)?;
    let length = (header & 0x3ffff) * 4;
    if (header >> 18) & 3 != 0 { return Err(ValidationError::Unsupported("Unsupported ARM64 xdata version")); }
    let mut scopes = (header >> 22) & 31;
    let mut words = header >> 27;
    let mut size = 4;
    if scopes == 0 && words == 0 {
        let extension = reader.bytes(value, 8)?;
        let extension = u32_at(extension, 4);
        if extension >> 24 != 0 { return Err(ValidationError::Invalid("Reserved ARM64 xdata extension bits")); }
        scopes = extension & 0xffff;
        words = (extension >> 16) & 255;
        size = 8;
    }
    let single_epilog = header & (1 << 21) != 0;
    if words == 0 || single_epilog && scopes >= words * 4 { return Err(ValidationError::Invalid("Invalid ARM64 unwind-code span")); }
    let scope_count = if single_epilog { 0 } else { scopes as usize };
    let handler_size = if header & (1 << 20) != 0 { 4 } else { 0 };
    let record = reader.bytes(value, size + scope_count * 4 + words as usize * 4 + handler_size)?;
    for scope in record[size..size + scope_count * 4].chunks_exact(4) {
        let scope = u32_at(scope, 0);
        if scope & 0x003c0000 != 0 || (scope & 0x3ffff) * 4 >= length || scope >> 22 >= words * 4 {
            return Err(ValidationError::Invalid("Invalid ARM64 epilog scope"));
        }
    }
    if handler_size != 0 { reader.code(u32_at(record, record.len() - 4), 4)?; }
    Ok(length)
}
