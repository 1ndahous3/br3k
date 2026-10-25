use super::*;

pub(super) fn export_table() -> ExportTable {
    ExportTable {
        module_name: "kernel32.dll".to_string(),
        image_base: 0x1000,
        image_size: 0x100,
        time_date_stamp: None,
        symbols: vec![
            ExportSymbol {
                module_name: "kernel32.dll".to_string(),
                name: Some("Target".to_string()),
                names: vec!["Target".to_string()],
                ordinal: 1,
                rva: 0x10,
                address: 0x1010,
                forwarder: None,
            },
            ExportSymbol {
                module_name: "kernel32.dll".to_string(),
                name: Some("Next".to_string()),
                names: vec!["Next".to_string()],
                ordinal: 2,
                rva: 0x30,
                address: 0x1030,
                forwarder: None,
            },
        ],
    }
}

pub(super) fn dll_export_table() -> ExportTable {
    ExportTable {
        module_name: "user32.dll".to_string(),
        image_base: 0x7000,
        image_size: 0x100,
        time_date_stamp: None,
        symbols: vec![ExportSymbol {
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            names: vec!["MessageBoxW".to_string()],
            ordinal: 10,
            rva: 0x10,
            address: 0x7010,
            forwarder: None,
        }],
    }
}

pub(super) fn forwarded_kernel32_export_table() -> ExportTable {
    ExportTable {
        module_name: "kernel32.dll".to_string(),
        image_base: 0x10000,
        image_size: 0x1000,
        time_date_stamp: None,
        symbols: vec![ExportSymbol {
            module_name: "kernel32.dll".to_string(),
            name: Some("HeapAlloc".to_string()),
            names: vec!["HeapAlloc".to_string()],
            ordinal: 20,
            rva: 0x500,
            address: 0x10500,
            forwarder: Some("ntdll.RtlAllocateHeap".to_string()),
        }],
    }
}

pub(super) fn ntdll_export_table() -> ExportTable {
    ExportTable {
        module_name: "ntdll.dll".to_string(),
        image_base: 0x7000,
        image_size: 0x100,
        time_date_stamp: None,
        symbols: vec![ExportSymbol {
            module_name: "ntdll.dll".to_string(),
            name: Some("RtlAllocateHeap".to_string()),
            names: vec!["RtlAllocateHeap".to_string()],
            ordinal: 30,
            rva: 0x10,
            address: 0x7010,
            forwarder: None,
        }],
    }
}

pub(super) fn pe32_file_image_with_import_adjacent_directories() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    let nt_header_offset = 0x80usize;
    let file_header_offset = nt_header_offset + 4;
    let optional_header_offset = file_header_offset + 20;
    let section_table_offset = optional_header_offset + 0xe0;
    let data_directory_offset = optional_header_offset + 96;

    write_test_u16(&mut data, 0, 0x5a4d);
    write_test_u32(&mut data, 0x3c, nt_header_offset as u32);
    write_test_u32(&mut data, nt_header_offset, 0x0000_4550);
    write_test_u16(&mut data, file_header_offset, IMAGE_FILE_MACHINE_I386);
    write_test_u16(&mut data, file_header_offset + 2, 1);
    write_test_u16(&mut data, file_header_offset + 16, 0xe0);
    write_test_u16(&mut data, optional_header_offset, 0x10b);
    write_test_u32(&mut data, optional_header_offset + 28, 0x400000);
    write_test_u32(&mut data, optional_header_offset + 32, 0x1000);
    write_test_u32(&mut data, optional_header_offset + 36, 0x200);
    write_test_u32(&mut data, optional_header_offset + 56, 0x2000);
    write_test_u32(&mut data, optional_header_offset + 60, 0x200);
    write_test_u32(&mut data, optional_header_offset + 92, 16);
    write_test_data_directory(&mut data, data_directory_offset, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0x1111, 0x22);
    write_test_data_directory(&mut data, data_directory_offset, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x2222, 0x33);

    data[section_table_offset..section_table_offset + 5].copy_from_slice(b".text");
    write_test_u32(&mut data, section_table_offset + 8, 0x200);
    write_test_u32(&mut data, section_table_offset + 12, 0x1000);
    write_test_u32(&mut data, section_table_offset + 16, 0x200);
    write_test_u32(&mut data, section_table_offset + 20, 0x200);
    write_test_u32(&mut data, section_table_offset + 36, IMAGE_SCN_MEM_EXECUTE);

    data
}

pub(super) fn write_test_data_directory(data: &mut [u8], base: usize, index: usize, rva: u32, size: u32) {
    let offset = base + index * 8;
    write_test_u32(data, offset, rva);
    write_test_u32(data, offset + 4, size);
}

pub(super) fn write_test_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_test_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_test_i32(data: &mut [u8], offset: usize, value: i32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_test_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn read_test_i32(data: &[u8]) -> i32 {
    i32::from_le_bytes(data.try_into().unwrap())
}

pub(super) fn read_test_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes(data.try_into().unwrap())
}

pub(super) fn read_test_u64(data: &[u8]) -> u64 {
    u64::from_le_bytes(data.try_into().unwrap())
}

pub(super) fn mapped_pe_image(machine: u16, pointer_size: usize) -> Vec<u8> {
    let mut data = vec![0u8; 0x3000];
    let image_base = 0x400000u64;
    let nt_header_offset = 0x80usize;
    let file_header_offset = nt_header_offset + 4;
    let optional_header_offset = file_header_offset + 20;
    let optional_header_size = if pointer_size == 8 { 0xf0 } else { 0xe0 };
    let section_table_offset = optional_header_offset + optional_header_size;

    write_test_u16(&mut data, 0, 0x5a4d);
    write_test_u32(&mut data, 0x3c, nt_header_offset as u32);
    write_test_u32(&mut data, nt_header_offset, 0x0000_4550);
    write_test_u16(&mut data, file_header_offset, machine);
    write_test_u16(&mut data, file_header_offset + 2, 1);
    write_test_u16(&mut data, file_header_offset + 16, optional_header_size as u16);
    write_test_u16(&mut data, optional_header_offset, if pointer_size == 8 { 0x20b } else { 0x10b });
    write_test_u32(&mut data, optional_header_offset + 32, 0x1000);
    write_test_u32(&mut data, optional_header_offset + 36, 0x200);
    write_test_u32(&mut data, optional_header_offset + 56, 0x3000);
    write_test_u32(&mut data, optional_header_offset + 60, 0x200);
    if pointer_size == 8 {
        write_test_u64(&mut data, optional_header_offset + 24, image_base);
        write_test_u32(&mut data, optional_header_offset + 108, 16);
    } else {
        write_test_u32(&mut data, optional_header_offset + 28, image_base as u32);
        write_test_u32(&mut data, optional_header_offset + 92, 16);
    }

    data[section_table_offset..section_table_offset + 5].copy_from_slice(b".text");
    write_test_u32(&mut data, section_table_offset + 8, 0x1000);
    write_test_u32(&mut data, section_table_offset + 12, 0x1000);
    write_test_u32(&mut data, section_table_offset + 16, 0x1000);
    write_test_u32(&mut data, section_table_offset + 20, 0x1000);
    write_test_u32(&mut data, section_table_offset + 36, IMAGE_SCN_MEM_EXECUTE);

    data
}

pub(super) fn write_x86_rel32_branch(data: &mut [u8], rva: usize, opcode: u8, source_address: u64, target_address: u64) {
    let displacement = target_address as i64 - source_address as i64 - 5;
    data[rva] = opcode;
    write_test_i32(data, rva + 1, i32::try_from(displacement).unwrap());
}

pub(super) fn write_arm64_branch(data: &mut [u8], rva: usize, opcode: u32, source_address: u64, target_address: u64) {
    let displacement = target_address as i64 - source_address as i64;
    assert_eq!(displacement % 4, 0);
    write_test_u32(data, rva, opcode | (((displacement / 4) as i32 as u32) & ARM64_BRANCH_IMM26_MASK));
}

pub(super) fn write_arm64_conditional_branch(data: &mut [u8], rva: usize, source_address: u64, target_address: u64) {
    let displacement = target_address as i64 - source_address as i64;
    assert_eq!(displacement % 4, 0);
    let imm19 = ((displacement / 4) as i32 as u32) & 0x7ffff;

    write_test_u32(data, rva, 0x5400_0000 | (imm19 << 5));
}

pub(super) fn write_arm64_adrp(data: &mut [u8], rva: usize, register: u32, source_address: u64, target_address: u64) {
    let source_page = source_address & !0xfff;
    let target_page = target_address & !0xfff;
    let displacement = target_page as i64 - source_page as i64;
    assert_eq!(displacement % 0x1000, 0);
    let imm21 = ((displacement / 0x1000) as i32 as u32) & 0x1f_ffff;

    write_test_u32(
        data,
        rva,
        ARM64_ADRP_OPCODE | ((imm21 & 0x3) << 29) | ((imm21 >> 2) << 5) | register,
    );
}

pub(super) fn write_arm64_add_immediate_64(data: &mut [u8], rva: usize, register: u32, immediate: u32) {
    assert!(immediate < 0x1000);
    write_test_u32(data, rva, 0x9100_0000 | (immediate << 10) | (register << 5) | register);
}

pub(super) fn import_model() -> ImportModel {
    let mut model = ImportModel::default();
    model.add_module("user32.dll", 0x1000, 1).unwrap();
    model
        .add_function(
            "user32.dll",
            0x1000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "MessageBoxW".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
}

pub(super) fn message_box_code_reference(reference_rva: u32, kind: ImportCodeReferenceKind) -> ImportCodeReference {
    ImportCodeReference {
        reference_rva,
        kind,
        target_address: 0x7010,
        export_address: 0x7010,
        iat_rva: None,
        module_name: "user32.dll".to_string(),
        name: Some("MessageBoxW".to_string()),
        ordinal: 10,
    }
}

pub(super) fn message_box_iat_code_reference(reference_rva: u32, iat_rva: u32, kind: ImportCodeReferenceKind) -> ImportCodeReference {
    let mut reference = message_box_code_reference(reference_rva, kind);
    reference.iat_rva = Some(iat_rva);
    reference
}

pub(super) fn recover_single_iat_pointer(address: u64, address_resolve_mode: ImportAddressResolveMode) -> (ImportModel, usize) {
    let mut model = ImportModel::default();
    let exports = export_table();
    let iat_data = address.to_le_bytes();
    let recovered = recover_iat(&mut model, 0x2000, &iat_data, 8, address_resolve_mode, &[&exports]).unwrap();

    (model, recovered)
}

pub(super) fn resolve_options(mode: ImportAddressResolveMode) -> ImportAddressResolveOptions {
    ImportAddressResolveOptions {
        mode,
        resolve_forwarders: false,
        api_set_map: None,
    }
}

pub(super) fn trace_options(start_rva: u32) -> ImportCodeTraceOptions {
    ImportCodeTraceOptions {
        start_rva,
        max_blocks: 8,
        max_bytes: 0x100,
        follow_calls: true,
    }
}

pub(super) fn address_resolver<'a>(
    exports: &'a [&'a ExportTable],
    mode: ImportAddressResolveMode,
) -> ImportAddressResolver {
    ImportAddressResolver::new(exports, resolve_options(mode))
}
