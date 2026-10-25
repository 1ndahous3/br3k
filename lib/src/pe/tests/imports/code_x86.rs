use super::*;

#[test]
fn scan_x86_code_references_finds_direct_call_targets() {
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let code = [0xe8, 0x0b, 0x60, 0x00, 0x00];
    let mut references = Vec::new();

    scan_x86_code_references(
        &mut references,
        &[],
        &code,
        0,
        0x1000,
        8,
        true,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0,
            kind: ImportCodeReferenceKind::DirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: None,
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        }],
    );
}

#[test]
fn scan_x64_code_references_finds_rip_relative_iat_calls() {
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let code = [0xff, 0x15, 0x0a, 0x00, 0x00, 0x00];
    let mut image_data = vec![0; 0x18];
    image_data[0x10..0x18].copy_from_slice(&0x7010u64.to_le_bytes());
    let mut references = Vec::new();

    scan_x86_code_references(
        &mut references,
        &image_data,
        &code,
        0,
        0x1000,
        8,
        true,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0,
            kind: ImportCodeReferenceKind::IndirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x10),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        }],
    );
}

#[test]
fn scan_x86_code_references_finds_immediate_register_calls() {
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut code = vec![0u8; 7];
    let mut references = Vec::new();

    code[0] = 0xbb;
    write_test_u32(&mut code, 1, 0x7010);
    code[5] = 0xff;
    code[6] = 0xd3;

    scan_x86_code_references(
        &mut references,
        &[],
        &code,
        0,
        0x1000,
        4,
        false,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_code_reference(0, ImportCodeReferenceKind::ImmediateCall)],
    );
    assert!(!references[0].kind.is_patchable_direct_branch());
}

#[test]
fn scan_x86_code_references_finds_memory_register_iat_calls() {
    let image_base = 0x400000u64;
    let iat_rva = 0x20usize;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = vec![0u8; 0x28];
    let mut references = Vec::new();

    image_data[0] = 0x8b;
    image_data[1] = 0x1d;
    write_test_u32(&mut image_data, 2, (image_base + iat_rva as u64) as u32);
    image_data[6] = 0xff;
    image_data[7] = 0xd3;
    write_test_u32(&mut image_data, iat_rva, 0x7010);

    scan_x86_code_references(
        &mut references,
        &image_data,
        &image_data[..8],
        0,
        image_base,
        4,
        false,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_iat_code_reference(0, iat_rva as u32, ImportCodeReferenceKind::IndirectCall)],
    );
}

#[test]
fn scan_x64_code_references_finds_immediate_register_calls() {
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut code = vec![0u8; 13];
    let mut references = Vec::new();

    code[0] = 0x49;
    code[1] = 0xba;
    write_test_u64(&mut code, 2, 0x7010);
    code[10] = 0x41;
    code[11] = 0xff;
    code[12] = 0xd2;

    scan_x86_code_references(
        &mut references,
        &[],
        &code,
        0,
        0x1000,
        8,
        true,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_code_reference(0, ImportCodeReferenceKind::ImmediateCall)],
    );
    assert!(!references[0].kind.is_patchable_direct_branch());
}

#[test]
fn scan_x64_code_references_finds_memory_register_iat_calls() {
    let image_base = 0x400000u64;
    let iat_rva = 0x20usize;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = vec![0u8; 0x28];
    let code_address = image_base;
    let iat_address = image_base + iat_rva as u64;
    let mut references = Vec::new();

    image_data[0] = 0x4c;
    image_data[1] = 0x8b;
    image_data[2] = 0x15;
    write_test_i32(&mut image_data, 3, i32::try_from(iat_address as i64 - code_address as i64 - 7).unwrap());
    image_data[7] = 0x41;
    image_data[8] = 0xff;
    image_data[9] = 0xd2;
    write_test_u64(&mut image_data, iat_rva, 0x7010);

    scan_x86_code_references(
        &mut references,
        &image_data,
        &image_data[..10],
        0,
        image_base,
        8,
        true,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_iat_code_reference(0, iat_rva as u32, ImportCodeReferenceKind::IndirectCall)],
    );
}

#[test]
fn scan_x64_code_references_follows_register_copy_after_memory_load() {
    let image_base = 0x400000u64;
    let iat_rva = 0x20usize;
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut image_data = vec![0u8; 0x28];
    let code_address = image_base;
    let iat_address = image_base + iat_rva as u64;
    let mut references = Vec::new();

    image_data[0] = 0x4c;
    image_data[1] = 0x8b;
    image_data[2] = 0x15;
    write_test_i32(&mut image_data, 3, i32::try_from(iat_address as i64 - code_address as i64 - 7).unwrap());
    image_data[7] = 0x49;
    image_data[8] = 0x8b;
    image_data[9] = 0xc2;
    image_data[10] = 0xff;
    image_data[11] = 0xd0;
    write_test_u64(&mut image_data, iat_rva, 0x7010);

    scan_x86_code_references(
        &mut references,
        &image_data,
        &image_data[..12],
        0,
        image_base,
        8,
        true,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_iat_code_reference(0, iat_rva as u32, ImportCodeReferenceKind::IndirectCall)],
    );
}

#[test]
fn scan_x86_code_references_follows_register_copy_after_immediate_load() {
    let exports = dll_export_table();
    let exports = [&exports];
    let resolver = address_resolver(&exports, ImportAddressResolveMode::Exact);
    let mut code = vec![0u8; 9];
    let mut references = Vec::new();

    code[0] = 0xbb;
    write_test_u32(&mut code, 1, 0x7010);
    code[5] = 0x8b;
    code[6] = 0xc3;
    code[7] = 0xff;
    code[8] = 0xe0;

    scan_x86_code_references(
        &mut references,
        &[],
        &code,
        0,
        0x1000,
        4,
        false,
        &resolver,
    )
    .unwrap();

    assert_eq!(
        references,
        vec![message_box_code_reference(0, ImportCodeReferenceKind::ImmediateJump)],
    );
    assert!(!references[0].kind.is_patchable_direct_branch());
}

#[test]
fn scan_code_references_in_range_limits_search_to_requested_rva() {
    let image_base = 0x400000u64;
    let code_rva = 0x1000usize;
    let iat_rva = 0x1100usize;
    let exports = dll_export_table();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);
    let code_address = image_base + code_rva as u64;
    let iat_address = image_base + iat_rva as u64;

    image_data[code_rva] = 0xff;
    image_data[code_rva + 1] = 0x15;
    write_test_i32(&mut image_data, code_rva + 2, i32::try_from(iat_address as i64 - code_address as i64 - 6).unwrap());
    image_data[code_rva + 0x20] = 0xff;
    image_data[code_rva + 0x21] = 0x15;
    write_test_i32(&mut image_data, code_rva + 0x22, i32::try_from(iat_address as i64 - (code_address + 0x20) as i64 - 6).unwrap());
    write_test_u64(&mut image_data, iat_rva, 0x7010);

    let references = scan_mapped_export_code_references_in_range_with_options(
        &image_data,
        Some(image_base),
        code_rva as u32,
        6,
        resolve_options(ImportAddressResolveMode::Exact),
        &[&exports],
    )
    .unwrap();

    assert_eq!(
        references,
        vec![ImportCodeReference {
            reference_rva: 0x1000,
            kind: ImportCodeReferenceKind::IndirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x1100),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        }],
    );
}
