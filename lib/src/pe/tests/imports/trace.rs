use super::*;

#[test]
fn trace_x86_branches_wrap_at_32_bits() {
    for (image_base, target) in [(0x400000u64, 0xf0007010u64), (0xf0000000, 0x7010)] {
        for opcode in [0xe8, 0xe9] {
            let mut exports = dll_export_table();
            exports.image_base = target - 0x10;
            for symbol in &mut exports.symbols { symbol.address = exports.image_base + symbol.rva as u64; }
            let mut image = mapped_pe_image(IMAGE_FILE_MACHINE_I386, 4);
            image[0x1000] = opcode;
            let displacement = (target as u32).wrapping_sub((image_base + 0x1005) as u32);
            image[0x1001..0x1005].copy_from_slice(&displacement.to_le_bytes());
            image[0x1005] = 0xc3;
            let trace = trace_mapped_export_code_references(
                &image, Some(image_base), trace_options(0x1000),
                resolve_options(ImportAddressResolveMode::Exact), &[&exports],
            ).unwrap();
            assert!(trace.references.iter().any(|reference| reference.reference_rva == 0x1000 && reference.target_address == target));
        }
    }
}

#[test]
fn trace_code_references_follows_x64_conditional_branches() {
    let image_base = 0x400000u64;
    let entry_rva = 0x1000usize;
    let target_rva = 0x1020usize;
    let exports = dll_export_table();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);

    image_data[entry_rva] = 0x75;
    image_data[entry_rva + 1] = u8::try_from(target_rva - entry_rva - 2).unwrap();
    image_data[entry_rva + 2] = 0xc3;
    write_x86_rel32_branch(&mut image_data, target_rva, 0xe8, image_base + target_rva as u64, 0x7010);
    image_data[target_rva + 5] = 0xc3;

    let trace = trace_mapped_export_code_references(
        &image_data,
        Some(image_base),
        trace_options(entry_rva as u32),
        resolve_options(ImportAddressResolveMode::Exact),
        &[&exports],
    )
    .unwrap();

    assert_eq!(trace.references, vec![message_box_code_reference(target_rva as u32, ImportCodeReferenceKind::DirectCall)]);
    assert_eq!(trace.visited_blocks, 3);
    assert_eq!(trace.scanned_bytes, 9);
}

#[test]
fn trace_code_references_follows_arm64_conditional_branches() {
    let image_base = 0x400000u64;
    let entry_rva = 0x1000usize;
    let target_rva = 0x1020usize;
    let exports = dll_export_table();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);

    write_arm64_conditional_branch(
        &mut image_data,
        entry_rva,
        image_base + entry_rva as u64,
        image_base + target_rva as u64,
    );
    write_test_u32(&mut image_data, entry_rva + 4, 0xd65f_03c0);
    write_arm64_branch(&mut image_data, target_rva, ARM64_BL_OPCODE, image_base + target_rva as u64, 0x7010);
    write_test_u32(&mut image_data, target_rva + 4, 0xd65f_03c0);

    let trace = trace_mapped_export_code_references(
        &image_data,
        Some(image_base),
        trace_options(entry_rva as u32),
        resolve_options(ImportAddressResolveMode::Exact),
        &[&exports],
    )
    .unwrap();

    assert_eq!(trace.references, vec![message_box_code_reference(target_rva as u32, ImportCodeReferenceKind::DirectCall)]);
    assert_eq!(trace.visited_blocks, 3);
    assert_eq!(trace.scanned_bytes, 16);
}

#[test]
fn recover_iat_traces_x86_relative_jump_thunks() {
    let image_base = 0x400000u64;
    let stub_rva = 0x1000usize;
    let stub_address = image_base + stub_rva as u64;
    let exports = export_table();
    let iat_data = (stub_address as u32).to_le_bytes();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_I386, 4);
    let mut direct_model = ImportModel::default();
    let mut traced_model = ImportModel::default();

    write_x86_rel32_branch(&mut image_data, stub_rva, 0xe9, stub_address, 0x1010);

    recover_iat(&mut direct_model, 0x2000, &iat_data, 4, ImportAddressResolveMode::Exact, &[&exports]).unwrap();
    let traced_count = recover_iat_with_traced_thunks(
        &mut traced_model,
        0x2000,
        &iat_data,
        &image_data,
        Some(image_base),
        4,
        resolve_options(ImportAddressResolveMode::Exact),
        4,
        &[&exports],
    )
    .unwrap();
    let traced_imports = traced_model.imports();

    assert_eq!(direct_model.function_count(), 0);
    assert_eq!(traced_count, 1);
    assert_eq!(traced_imports[0].module_name, "kernel32.dll");
    assert_eq!(traced_imports[0].rva, 0x2000);
    assert_eq!(traced_imports[0].name.as_deref(), Some("Target"));
}

#[test]
fn recover_iat_traces_x64_indirect_jump_thunks() {
    let image_base = 0x400000u64;
    let stub_rva = 0x1000usize;
    let pointer_rva = 0x1100usize;
    let stub_address = image_base + stub_rva as u64;
    let pointer_address = image_base + pointer_rva as u64;
    let exports = dll_export_table();
    let iat_data = stub_address.to_le_bytes();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);
    let mut model = ImportModel::default();

    image_data[stub_rva] = 0xff;
    image_data[stub_rva + 1] = 0x25;
    write_test_i32(&mut image_data, stub_rva + 2, i32::try_from(pointer_address as i64 - stub_address as i64 - 6).unwrap());
    write_test_u64(&mut image_data, pointer_rva, 0x7010);

    let recovered = recover_iat_with_traced_thunks(
        &mut model,
        0x3000,
        &iat_data,
        &image_data,
        Some(image_base),
        8,
        resolve_options(ImportAddressResolveMode::Exact),
        4,
        &[&exports],
    )
    .unwrap();
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports[0].module_name, "user32.dll");
    assert_eq!(imports[0].rva, 0x3000);
    assert_eq!(imports[0].name.as_deref(), Some("MessageBoxW"));
}

#[test]
fn recover_iat_traces_x64_memory_register_thunks() {
    let image_base = 0x400000u64;
    let stub_rva = 0x1000usize;
    let pointer_rva = 0x1100usize;
    let stub_address = image_base + stub_rva as u64;
    let pointer_address = image_base + pointer_rva as u64;
    let exports = dll_export_table();
    let iat_data = stub_address.to_le_bytes();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);
    let mut model = ImportModel::default();

    image_data[stub_rva] = 0x4c;
    image_data[stub_rva + 1] = 0x8b;
    image_data[stub_rva + 2] = 0x15;
    write_test_i32(&mut image_data, stub_rva + 3, i32::try_from(pointer_address as i64 - stub_address as i64 - 7).unwrap());
    image_data[stub_rva + 7] = 0x41;
    image_data[stub_rva + 8] = 0xff;
    image_data[stub_rva + 9] = 0xe2;
    write_test_u64(&mut image_data, pointer_rva, 0x7010);

    let recovered = recover_iat_with_traced_thunks(
        &mut model,
        0x3000,
        &iat_data,
        &image_data,
        Some(image_base),
        8,
        resolve_options(ImportAddressResolveMode::Exact),
        4,
        &[&exports],
    )
    .unwrap();
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports[0].module_name, "user32.dll");
    assert_eq!(imports[0].rva, 0x3000);
    assert_eq!(imports[0].name.as_deref(), Some("MessageBoxW"));
}

#[test]
fn recover_iat_traces_x64_register_copy_thunks() {
    let image_base = 0x400000u64;
    let stub_rva = 0x1000usize;
    let pointer_rva = 0x1100usize;
    let stub_address = image_base + stub_rva as u64;
    let pointer_address = image_base + pointer_rva as u64;
    let exports = dll_export_table();
    let iat_data = stub_address.to_le_bytes();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_AMD64, 8);
    let mut model = ImportModel::default();

    image_data[stub_rva] = 0x4c;
    image_data[stub_rva + 1] = 0x8b;
    image_data[stub_rva + 2] = 0x15;
    write_test_i32(&mut image_data, stub_rva + 3, i32::try_from(pointer_address as i64 - stub_address as i64 - 7).unwrap());
    image_data[stub_rva + 7] = 0x49;
    image_data[stub_rva + 8] = 0x8b;
    image_data[stub_rva + 9] = 0xc2;
    image_data[stub_rva + 10] = 0xff;
    image_data[stub_rva + 11] = 0xe0;
    write_test_u64(&mut image_data, pointer_rva, 0x7010);

    let recovered = recover_iat_with_traced_thunks(
        &mut model,
        0x3000,
        &iat_data,
        &image_data,
        Some(image_base),
        8,
        resolve_options(ImportAddressResolveMode::Exact),
        4,
        &[&exports],
    )
    .unwrap();
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports[0].module_name, "user32.dll");
    assert_eq!(imports[0].rva, 0x3000);
    assert_eq!(imports[0].name.as_deref(), Some("MessageBoxW"));
}

#[test]
fn recover_iat_traces_arm64_branch_thunks() {
    let image_base = 0x400000u64;
    let stub_rva = 0x1000usize;
    let stub_address = image_base + stub_rva as u64;
    let exports = export_table();
    let iat_data = stub_address.to_le_bytes();
    let mut image_data = mapped_pe_image(IMAGE_FILE_MACHINE_ARM64, 8);
    let mut model = ImportModel::default();

    write_arm64_branch(&mut image_data, stub_rva, ARM64_B_OPCODE, stub_address, 0x1010);

    let recovered = recover_iat_with_traced_thunks(
        &mut model,
        0x4000,
        &iat_data,
        &image_data,
        Some(image_base),
        8,
        resolve_options(ImportAddressResolveMode::Exact),
        4,
        &[&exports],
    )
    .unwrap();
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports[0].module_name, "kernel32.dll");
    assert_eq!(imports[0].rva, 0x4000);
    assert_eq!(imports[0].name.as_deref(), Some("Target"));
}
