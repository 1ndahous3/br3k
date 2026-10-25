use super::*;

#[test]
fn rebuild_imports_clears_bound_import_directory_by_default() {
    let options = RebuildImportsOptions {
        section_name: ".idata".to_string(),
        write_mode: ImportWriteMode::NewIat,
        ..Default::default()
    };
    let rebuilt = rebuild_imports(&pe32_file_image_with_import_adjacent_directories(), &import_model(), options).unwrap();
    let image = Image::parse(rebuilt).unwrap();
    let bound = image.data_directory(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT).unwrap();
    let delay = image.data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).unwrap();

    assert_eq!(bound.virtual_address, 0);
    assert_eq!(bound.size, 0);
    assert_eq!(delay.virtual_address, 0x2222);
    assert_eq!(delay.size, 0x33);
}

#[test]
fn rebuild_imports_can_clear_delay_import_directory() {
    let options = RebuildImportsOptions {
        section_name: ".idata".to_string(),
        write_mode: ImportWriteMode::NewIat,
        clear_delay_imports: true,
        ..Default::default()
    };
    let rebuilt = rebuild_imports(&pe32_file_image_with_import_adjacent_directories(), &import_model(), options).unwrap();
    let image = Image::parse(rebuilt).unwrap();
    let delay = image.data_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).unwrap();

    assert_eq!(delay.virtual_address, 0);
    assert_eq!(delay.size, 0);
}

#[test]
fn rebuild_imports_can_write_named_imports_by_ordinal() {
    let mut model = ImportModel::default();
    model.add_module("user32.dll", 0x1000, 1).unwrap();
    model
        .add_function(
            "user32.dll",
            0x1000,
            ImportTarget::Name {
                hint: 0,
                ordinal: Some(10),
                name: "MessageBoxW".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    let options = RebuildImportsOptions {
        section_name: ".idata".to_string(),
        write_mode: ImportWriteMode::NewIat,
        import_by_ordinal: true,
        ..Default::default()
    };

    let rebuilt = rebuild_imports(&pe32_file_image_with_import_adjacent_directories(), &model, options).unwrap();
    let image = Image::parse(rebuilt).unwrap();
    let import_directory = image.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).unwrap();
    let original_first_thunk = image.read_u32_rva(import_directory.virtual_address).unwrap();
    let import_lookup_value = image.read_u32_rva(original_first_thunk).unwrap();

    assert_eq!(import_lookup_value as u64, IMAGE_ORDINAL_FLAG32 | 10);
}

#[test]
fn rebuild_imports_can_patch_x86_direct_calls_via_import_stub() {
    let mut image_data = pe32_file_image_with_import_adjacent_directories();
    let image_base = 0x400000u64;
    let reference_rva = 0x1000u32;
    let reference_offset = 0x200usize;

    write_x86_rel32_branch(
        &mut image_data,
        reference_offset,
        0xe8,
        image_base + reference_rva as u64,
        0x7010,
    );

    let report = rebuild_imports_with_report(
        &image_data,
        &ImportModel::default(),
        RebuildImportsOptions {
            section_name: ".br3kiat".to_string(),
            write_mode: ImportWriteMode::NewIat,
            code_references: vec![message_box_code_reference(reference_rva, ImportCodeReferenceKind::DirectCall)],
            ..Default::default()
        },
    )
    .unwrap();
    let rebuilt = Image::parse(report.image.clone()).unwrap();
    let patched_offset = rebuilt.rva_to_file_offset(reference_rva).unwrap();
    let stub_rva = report.code_stub_section_rva.unwrap();
    let displacement = read_test_i32(&report.image[patched_offset + 1..patched_offset + 5]);
    let patched_target = (image_base + reference_rva as u64 + 5).wrapping_add(displacement as i64 as u64);
    let stub_offset = rebuilt.rva_to_file_offset(stub_rva).unwrap();
    let stub_iat_va = read_test_u32(&report.image[stub_offset + 2..stub_offset + 6]);

    assert_eq!(report.direct_imports_added, 1);
    assert_eq!(report.patchable_code_references, 1);
    assert_eq!(report.patched_code_references, 1);
    assert_eq!(report.image[patched_offset], 0xe8);
    assert_eq!(patched_target, image_base + stub_rva as u64);
    assert_eq!(&report.image[stub_offset..stub_offset + 2], &[0xff, 0x25]);
    assert_eq!(stub_iat_va as u64, image_base + report.iat_rva as u64);
}

#[test]
fn rebuild_imports_can_patch_x64_direct_calls_via_rip_relative_import_stub() {
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);
    let image_base = 0x400000u64;
    let reference_rva = 0x1000u32;

    write_x86_rel32_branch(
        &mut image_data,
        reference_rva as usize,
        0xe8,
        image_base + reference_rva as u64,
        0x7010,
    );

    let report = rebuild_imports_with_report(
        &image_data,
        &ImportModel::default(),
        RebuildImportsOptions {
            section_name: ".br3kiat".to_string(),
            write_mode: ImportWriteMode::NewIat,
            code_references: vec![message_box_code_reference(reference_rva, ImportCodeReferenceKind::DirectCall)],
            ..Default::default()
        },
    )
    .unwrap();
    let rebuilt = Image::parse(report.image.clone()).unwrap();
    let patched_offset = rebuilt.rva_to_file_offset(reference_rva).unwrap();
    let stub_rva = report.code_stub_section_rva.unwrap();
    let displacement = read_test_i32(&report.image[patched_offset + 1..patched_offset + 5]);
    let patched_target = (image_base + reference_rva as u64 + 5).wrapping_add(displacement as i64 as u64);
    let stub_offset = rebuilt.rva_to_file_offset(stub_rva).unwrap();
    let stub_displacement = read_test_i32(&report.image[stub_offset + 2..stub_offset + 6]);
    let stub_target = (image_base + stub_rva as u64 + 6).wrapping_add(stub_displacement as i64 as u64);

    assert_eq!(report.direct_imports_added, 1);
    assert_eq!(report.patchable_code_references, 1);
    assert_eq!(report.patched_code_references, 1);
    assert_eq!(report.image[patched_offset], 0xe8);
    assert_eq!(patched_target, image_base + stub_rva as u64);
    assert_eq!(&report.image[stub_offset..stub_offset + 2], &[0xff, 0x25]);
    assert_eq!(stub_target, image_base + report.iat_rva as u64);
}

#[test]
fn rebuild_imports_can_patch_arm64_direct_calls_via_literal_import_stub() {
    let image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);
    let image_base = 0x400000u64;
    let reference_rva = 0x1000u32;

    let report = rebuild_imports_with_report(
        &image_data,
        &ImportModel::default(),
        RebuildImportsOptions {
            section_name: ".br3kiat".to_string(),
            write_mode: ImportWriteMode::NewIat,
            code_references: vec![message_box_code_reference(reference_rva, ImportCodeReferenceKind::DirectCall)],
            ..Default::default()
        },
    )
    .unwrap();
    let rebuilt = Image::parse(report.image.clone()).unwrap();
    let patched_offset = rebuilt.rva_to_file_offset(reference_rva).unwrap();
    let patched_instruction = read_test_u32(&report.image[patched_offset..patched_offset + 4]);
    let stub_rva = report.code_stub_section_rva.unwrap();
    let patched_displacement = (((patched_instruction & ARM64_BRANCH_IMM26_MASK) as i32) << 6) >> 4;
    let patched_target = (image_base + reference_rva as u64).wrapping_add(patched_displacement as i64 as u64);
    let stub_offset = rebuilt.rva_to_file_offset(stub_rva).unwrap();
    let ldr_literal = ARM64_LDR_LITERAL_64_OPCODE | (4 << 5) | 16;
    let ldr_pointer = ARM64_LDR_UNSIGNED_64_OPCODE | (16 << 5) | 16;
    let br = ARM64_BR_OPCODE | (16 << 5);
    let stub_iat_va = read_test_u64(&report.image[stub_offset + 16..stub_offset + 24]);

    assert_eq!(report.direct_imports_added, 1);
    assert_eq!(report.patchable_code_references, 1);
    assert_eq!(report.patched_code_references, 1);
    assert_eq!(patched_instruction & !ARM64_BRANCH_IMM26_MASK, ARM64_BL_OPCODE);
    assert_eq!(patched_target, image_base + stub_rva as u64);
    assert_eq!(read_test_u32(&report.image[stub_offset..stub_offset + 4]), ldr_literal);
    assert_eq!(read_test_u32(&report.image[stub_offset + 4..stub_offset + 8]), ldr_pointer);
    assert_eq!(read_test_u32(&report.image[stub_offset + 8..stub_offset + 12]), br);
    assert_eq!(read_test_u32(&report.image[stub_offset + 12..stub_offset + 16]), ARM64_NOP);
    assert_eq!(stub_iat_va, image_base + report.iat_rva as u64);
}
