use super::*;

#[test]
fn scan_arm64_code_references_finds_bl_targets() {
    let exports = export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let code = ARM64_BL_OPCODE | 4;
    let mut references = Vec::new();

    scan_arm64_code_references(
        &mut references,
        &[],
        &code.to_le_bytes(),
        0,
        0x1000,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0,
            kind: ImportCodeReferenceKind::DirectCall,
            target_address: 0x1010,
            export_address: 0x1010,
            iat_rva: None,
            module_name: "kernel32.dll".to_string(),
            name: Some("Target".to_string()),
            ordinal: 1,
        }],
    );
}

#[test]
fn scan_arm64_code_references_finds_adrp_add_blr_targets() {
    let image_base = 0x400000u64;
    let code_rva = 0x1000usize;
    let register = 10u32;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);
    let mut references = Vec::new();

    write_arm64_adrp(&mut image_data, code_rva, register, image_base + code_rva as u64, 0x7010);
    write_arm64_add_immediate_64(&mut image_data, code_rva + 4, register, 0x10);
    write_test_u32(&mut image_data, code_rva + 8, ARM64_BLR_OPCODE | (register << 5));

    scan_arm64_code_references(
        &mut references,
        &image_data,
        &image_data[code_rva..code_rva + 12],
        code_rva as u32,
        image_base,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_code_reference(code_rva as u32, ImportCodeReferenceKind::ImmediateCall)],
    );
    assert!(!references[0].kind.is_patchable_direct_branch());
}

#[test]
fn scan_arm64_code_references_finds_adrp_ldr_blr_iat_calls() {
    let image_base = 0x400000u64;
    let code_rva = 0x1000usize;
    let iat_rva = 0x1200usize;
    let register = 8u32;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);
    let adrp = ARM64_ADRP_OPCODE | register;
    let ldr = ARM64_LDR_UNSIGNED_64_OPCODE | ((0x200 / 8) << 10) | (register << 5) | register;
    let blr = ARM64_BLR_OPCODE | (register << 5);
    let mut references = Vec::new();

    write_test_u32(&mut image_data, code_rva, adrp);
    write_test_u32(&mut image_data, code_rva + 4, ldr);
    write_test_u32(&mut image_data, code_rva + 8, blr);
    write_test_u64(&mut image_data, iat_rva, 0x7010);

    scan_arm64_code_references(
        &mut references,
        &image_data,
        &image_data[code_rva..code_rva + 12],
        code_rva as u32,
        image_base,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0x1000,
            kind: ImportCodeReferenceKind::IndirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x1200),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        }],
    );
}

#[test]
fn scan_arm64_code_references_finds_ldr_literal_br_iat_jumps() {
    let image_base = 0x400000u64;
    let code_rva = 0x1000usize;
    let iat_rva = 0x1010usize;
    let register = 9u32;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);
    let ldr_literal = ARM64_LDR_LITERAL_64_OPCODE | (((iat_rva - code_rva) as u32 / 4) << 5) | register;
    let br = ARM64_BR_OPCODE | (register << 5);
    let mut references = Vec::new();

    write_test_u32(&mut image_data, code_rva, ldr_literal);
    write_test_u32(&mut image_data, code_rva + 4, br);
    write_test_u64(&mut image_data, iat_rva, 0x7010);

    scan_arm64_code_references(
        &mut references,
        &image_data,
        &image_data[code_rva..code_rva + 0x18],
        code_rva as u32,
        image_base,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0x1000,
            kind: ImportCodeReferenceKind::IndirectJump,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x1010),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        }],
    );
}
