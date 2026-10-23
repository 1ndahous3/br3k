use super::validate::{u32_at, Reader, ValidationError};
use crate::pe::format::*;
use crate::pe::image::Image;
use std::collections::BTreeSet;

pub(super) fn debug(image: &Image) -> Result<(), ValidationError> {
    let reader = Reader { image };
    let data = reader.directory(PE_DIRECTORY_ENTRY_DEBUG)?;
    if data.is_empty() || data.len() % 28 != 0 { return Err(ValidationError::Invalid("Partial debug-directory record")); }
    for record in data.chunks_exact(28) {
        let size = u32_at(record, 16) as usize;
        let rva = u32_at(record, 20);
        if size == 0 { continue; }
        if rva == 0 { return Err(ValidationError::Unsupported("Debug payload is file-only")); }
        let payload = reader.bytes(rva, size)?;
        if u32_at(record, 12) == 2 {
            let prefix = match payload.get(..4) {
                Some(b"RSDS") => 24,
                Some(b"NB10") => 16,
                _ => return Err(ValidationError::Unsupported("Unknown CodeView payload format")),
            };
            if !payload.get(prefix..).is_some_and(|name| name.contains(&0)) {
                return Err(ValidationError::Invalid("Truncated CodeView record or unterminated PDB name"));
            }
        }
    }
    Ok(())
}

pub(super) fn clr(image: &Image) -> Result<(), ValidationError> {
    let reader = Reader { image };
    let header = reader.directory(PE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
    if header.len() < 72 || u32_at(header, 0) < 72 || u32_at(header, 0) as usize > header.len() {
        return Err(ValidationError::Invalid("Truncated CLR header"));
    }
    if u32_at(header, 0) != 72 { return Err(ValidationError::Unsupported("Unknown CLR header extension")); }
    for offset in [8, 24, 32, 40, 48, 56, 64] {
        let rva = u32_at(header, offset);
        let size = u32_at(header, offset + 4) as usize;
        if offset != 8 && rva == 0 && size == 0 { continue; }
        if size == 0 { return Err(ValidationError::Invalid("Empty CLR subdirectory")); }
        let bytes = reader.bytes(rva, size)?;
        if offset == 8 { metadata_streams(bytes)?; }
        if offset == 48 {
            if size % 8 != 0 { return Err(ValidationError::Invalid("Partial CLR vtable-fixup record")); }
            for fixup in bytes.chunks_exact(8) {
                let flags = u16::from_le_bytes(fixup[6..8].try_into().unwrap());
                let stride = match flags & 3 {
                    1 => 4,
                    2 => 8,
                    _ => return Err(ValidationError::Invalid("Invalid CLR vtable slot width")),
                };
                let count = u16::from_le_bytes(fixup[4..6].try_into().unwrap()) as usize;
                reader.bytes(u32_at(fixup, 0), count * stride)?;
            }
        }
    }
    if u32_at(header, 16) & 0x10 != 0 { reader.code(u32_at(header, 20), 1)?; }
    Ok(())
}

fn metadata_streams(data: &[u8]) -> Result<(), ValidationError> {
    let invalid = ValidationError::Invalid("Malformed CLR metadata root or stream directory");
    if data.len() < 20 || &data[..4] != b"BSJB" { return Err(invalid); }
    let version_size = u32_at(data, 12) as usize;
    let version_end = 16usize.checked_add(version_size).filter(|end| *end <= data.len()).ok_or(invalid)?;
    if version_size == 0 || !data[16..version_end].contains(&0) { return Err(ValidationError::Invalid("Unterminated CLR metadata version")); }
    let mut cursor = version_end.checked_add(3).map(|end| end & !3).ok_or(ValidationError::Invalid("CLR metadata offset overflow"))?;
    let prefix = data.get(cursor..cursor + 4).ok_or(ValidationError::Invalid("Truncated CLR stream count"))?;
    let count = u16::from_le_bytes(prefix[2..4].try_into().unwrap()) as usize;
    cursor += 4;
    let mut names = BTreeSet::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        let header = data.get(cursor..cursor + 8).ok_or(ValidationError::Invalid("Truncated CLR stream header"))?;
        let offset = u32_at(header, 0) as usize;
        let size = u32_at(header, 4) as usize;
        let end = offset.checked_add(size).filter(|end| *end <= data.len()).ok_or(ValidationError::Invalid("CLR stream exceeds metadata root"))?;
        cursor += 8;
        let name = data.get(cursor..).ok_or(ValidationError::Invalid("Missing CLR stream name"))?;
        let length = name.iter().take(32).position(|byte| *byte == 0).ok_or(ValidationError::Invalid("Unterminated CLR stream name"))?;
        if length == 0 || !name[..length].is_ascii() || !names.insert(name[..length].to_vec()) {
            return Err(ValidationError::Invalid("Empty, duplicate, or non-ASCII CLR stream name"));
        }
        cursor += (length + 1 + 3) & !3;
        if size != 0 { ranges.push(offset..end); }
    }
    if !names.contains(b"#~".as_slice()) && !names.contains(b"#-".as_slice()) {
        return Err(ValidationError::Invalid("CLR metadata has no table stream"));
    }
    ranges.sort_by_key(|range| range.start);
    for range in ranges {
        if range.start < cursor { return Err(ValidationError::Invalid("CLR streams overlap headers or one another")); }
        cursor = range.end;
    }
    Ok(())
}

pub(super) fn load_config(image: &Image) -> Result<(), ValidationError> {
    let reader = Reader { image };
    let data = reader.directory(PE_DIRECTORY_ENTRY_LOAD_CONFIG)?;
    if data.len() < 12 || u32_at(data, 0) < 12 || u32_at(data, 0) as usize > data.len() {
        return Err(ValidationError::Invalid("Truncated load-config structure"));
    }
    let size = u32_at(data, 0) as usize;
    let known_size = if image.pointer_size() == 4 { 0xc0 } else { 0x140 };
    if size > known_size { return Err(ValidationError::Unsupported("Unknown load-config extension")); }
    let info = crate::pe::diagnostics::load_config_info(image, true);
    // These fields address in-image pointer slots, not the possibly external values stored in them.
    for address in [info.security_cookie, info.guard_cf_check_function_pointer, info.guard_cf_dispatch_function_pointer,
        info.guard_rf_failure_routine_function_pointer, info.guard_rf_verify_stack_pointer_function_pointer,
        info.guard_xfg_check_function_pointer, info.guard_xfg_dispatch_function_pointer, info.guard_xfg_table_dispatch_function_pointer,
        info.cast_guard_os_determined_failure_mode, info.guard_memcpy_function_pointer].into_iter().flatten().filter(|address| *address != 0) {
        reader.bytes(reader.va(address)?, image.pointer_size())?;
    }
    let stride = info.guard_cf_function_table_entry_size().unwrap_or(4) as usize;
    for (table, count, stride, executable) in [
        (info.se_handler_table, info.se_handler_count, 4, true),
        (info.guard_cf_function_table, info.guard_cf_function_count, stride, true),
        (info.guard_address_taken_iat_entry_table, info.guard_address_taken_iat_entry_count, 4, false),
        (info.guard_long_jump_target_table, info.guard_long_jump_target_count, 4, true),
        (info.guard_eh_continuation_table, info.guard_eh_continuation_count, 4, true),
    ] {
        let address = table.unwrap_or(0);
        let count = count.unwrap_or(0);
        if address == 0 && count == 0 { continue; }
        if address == 0 || count == 0 { return Err(ValidationError::Invalid("Incomplete load-config table/count pair")); }
        let length = count.checked_mul(stride as u64).and_then(|length| usize::try_from(length).ok())
            .ok_or(ValidationError::Invalid("Load-config table size overflow"))?;
        let entries = reader.bytes(reader.va(address)?, length)?;
        let mut previous = 0;
        for entry in entries.chunks_exact(stride) {
            let rva = u32_at(entry, 0);
            if rva < previous { return Err(ValidationError::Invalid("Unsorted load-config table")); }
            previous = rva;
            if executable { reader.code(rva, 1)?; } else { reader.bytes(rva, image.pointer_size())?; }
        }
    }
    if let Some(address) = info.guard_rf_failure_routine.filter(|value| *value != 0) { reader.code(reader.va(address)?, 1)?; }
    if [info.dynamic_value_reloc_table, info.chpe_metadata_pointer, info.enclave_configuration_pointer, info.volatile_metadata_pointer]
        .into_iter().flatten().any(|value| value != 0)
        || info.dynamic_value_reloc_table_section.unwrap_or(0) != 0 || info.dynamic_value_reloc_table_offset.unwrap_or(0) != 0
        || info.hot_patch_table_offset.unwrap_or(0) != 0 {
        return Err(ValidationError::Unsupported("Load config references specialized dynamic-relocation, hybrid, enclave, volatile, or hotpatch metadata"));
    }
    Ok(())
}
