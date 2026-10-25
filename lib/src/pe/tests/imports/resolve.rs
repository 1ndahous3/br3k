use super::*;

#[test]
fn exact_recovery_requires_export_start_address() {
    let (model, recovered) = recover_single_iat_pointer(0x1013, ImportAddressResolveMode::Exact);

    assert_eq!(recovered, 0);
    assert_eq!(model.function_count(), 0);
}

#[test]
fn recover_iat_can_keep_unresolved_slots_for_review() {
    let exports = export_table();
    let mut model = ImportModel::default();
    let mut iat_data = Vec::new();
    iat_data.extend_from_slice(&0x1010u64.to_le_bytes());
    iat_data.extend_from_slice(&0x5555u64.to_le_bytes());
    iat_data.extend_from_slice(&0u64.to_le_bytes());

    let recovered = recover_iat_with_recovery_options(
        &mut model,
        0x2000,
        &iat_data,
        8,
        RecoverIatOptions {
            address_resolve_options: resolve_options(ImportAddressResolveMode::Exact),
            keep_unresolved: true,
        },
        &[&exports],
    )
    .unwrap();

    let imports = model.imports();
    let issues = model.issues(8).unwrap();
    let unresolved = imports.iter().find(|entry| entry.rva == 0x2008).unwrap();

    assert_eq!(recovered, 1);
    assert_eq!(imports.len(), 2);

    let resolved = imports.iter().find(|entry| entry.rva == 0x2000).unwrap();
    assert_eq!(resolved.confidence, 95);
    assert_eq!(resolved.evidence.len(), 1);
    assert_eq!(resolved.evidence[0].kind, ImportEvidenceKind::IatDirectory);
    assert_eq!(resolved.evidence[0].resolution, ImportResolutionKind::Exact);
    assert_eq!(resolved.evidence[0].source_rva, 0x2000);

    assert!(!unresolved.valid);
    assert_eq!(unresolved.address, Some(0x5555));
    assert_eq!(unresolved.confidence, 20);
    assert_eq!(unresolved.evidence.len(), 1);
    assert_eq!(unresolved.evidence[0].kind, ImportEvidenceKind::IatDirectory);
    assert_eq!(unresolved.evidence[0].resolution, ImportResolutionKind::Unresolved);
    assert_eq!(unresolved.evidence[0].target_address, Some(0x5555));
    assert!(unresolved.module_name.starts_with("?0x2008"));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::InvalidFunction
            && issue.rva == 0x2008
            && issue.address == Some(0x5555)
    }));
}

#[test]
fn recover_iat_slots_accepts_explicit_non_contiguous_addresses() {
    let exports = export_table();
    let mut model = ImportModel::default();
    let slots = [
        ImportAddressSlot {
            rva: 0x2000,
            address: 0x1010,
        },
        ImportAddressSlot {
            rva: 0x2020,
            address: 0x5555,
        },
    ];

    let recovered = recover_iat_slots_with_recovery_options(
        &mut model,
        &slots,
        8,
        RecoverIatOptions {
            address_resolve_options: resolve_options(ImportAddressResolveMode::Exact),
            keep_unresolved: true,
        },
        &[&exports],
    )
    .unwrap();

    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports.len(), 2);
    assert!(imports.iter().any(|entry| {
        entry.rva == 0x2000
            && entry.module_name == "kernel32.dll"
            && entry.name.as_deref() == Some("Target")
            && entry.confidence == 100
            && entry.evidence[0].kind == ImportEvidenceKind::ManualSlot
    }));
    assert!(imports.iter().any(|entry| {
        entry.rva == 0x2020
            && entry.address == Some(0x5555)
            && !entry.valid
            && entry.confidence == 20
            && entry.evidence[0].kind == ImportEvidenceKind::ManualSlot
            && entry.evidence[0].resolution == ImportResolutionKind::Unresolved
            && entry.module_name.starts_with("?0x2020")
    }));
}

#[test]
fn nearest_recovery_accepts_address_inside_export_body() {
    let (model, recovered) = recover_single_iat_pointer(0x1013, ImportAddressResolveMode::Nearest);
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].module_name, "kernel32.dll");
    assert_eq!(imports[0].rva, 0x2000);
    assert_eq!(imports[0].name.as_deref(), Some("Target"));
}

#[test]
fn nearest_recovery_stays_inside_module_range() {
    let (model, recovered) = recover_single_iat_pointer(0x1110, ImportAddressResolveMode::Nearest);

    assert_eq!(recovered, 0);
    assert_eq!(model.function_count(), 0);
}

#[test]
fn recover_iat_from_code_references_uses_only_indirect_iat_slots() {
    let mut model = ImportModel::default();
    let references = vec![
        ImportCodeReference {
            reference_rva: 0x1000,
            kind: ImportCodeReferenceKind::DirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: None,
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        },
        ImportCodeReference {
            reference_rva: 0x1006,
            kind: ImportCodeReferenceKind::IndirectCall,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x2000),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        },
        ImportCodeReference {
            reference_rva: 0x1010,
            kind: ImportCodeReferenceKind::IndirectJump,
            target_address: 0x7010,
            export_address: 0x7010,
            iat_rva: Some(0x2000),
            module_name: "user32.dll".to_string(),
            name: Some("MessageBoxW".to_string()),
            ordinal: 10,
        },
    ];

    let recovered = recover_iat_from_code_references(&mut model, &references, 8).unwrap();
    let imports = model.imports();

    assert_eq!(recovered, 1);
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].module_name, "user32.dll");
    assert_eq!(imports[0].rva, 0x2000);
    assert_eq!(imports[0].name.as_deref(), Some("MessageBoxW"));
    assert_eq!(imports[0].confidence, 80);
    assert_eq!(imports[0].evidence.len(), 1);
    assert_eq!(imports[0].evidence[0].kind, ImportEvidenceKind::CodeReference);
    assert_eq!(imports[0].evidence[0].resolution, ImportResolutionKind::Exact);
    assert_eq!(imports[0].evidence[0].source_rva, 0x1006);
    assert_eq!(imports[0].evidence[0].reference_rva, Some(0x1006));
    assert_eq!(imports[0].evidence[0].iat_rva, Some(0x2000));
    assert_eq!(recover_iat_from_code_references(&mut model, &references, 8).unwrap(), 0);
}

#[test]
fn recover_iat_with_forwarders_prefers_public_forwarded_export() {
    let kernel32 = forwarded_kernel32_export_table();
    let ntdll = ntdll_export_table();
    let iat_data = 0x7010u64.to_le_bytes();
    let mut concrete_model = ImportModel::default();
    let mut forwarded_model = ImportModel::default();

    recover_iat(&mut concrete_model, 0x2000, &iat_data, 8, ImportAddressResolveMode::Exact, &[&kernel32, &ntdll]).unwrap();
    recover_iat_with_options(
        &mut forwarded_model,
        0x2000,
        &iat_data,
        8,
        ImportAddressResolveOptions {
            mode: ImportAddressResolveMode::Exact,
            resolve_forwarders: true,
            api_set_map: None,
        },
        &[&kernel32, &ntdll],
    )
    .unwrap();

    let concrete_imports = concrete_model.imports();
    let forwarded_imports = forwarded_model.imports();

    assert_eq!(concrete_imports[0].module_name, "ntdll.dll");
    assert_eq!(concrete_imports[0].name.as_deref(), Some("RtlAllocateHeap"));
    assert_eq!(forwarded_imports[0].module_name, "kernel32.dll");
    assert_eq!(forwarded_imports[0].name.as_deref(), Some("HeapAlloc"));
}

#[test]
fn exact_recovery_ignores_forwarder_metadata_addresses() {
    let kernel32 = forwarded_kernel32_export_table();
    let iat_data = 0x10500u64.to_le_bytes();
    let mut model = ImportModel::default();
    let recovered = recover_iat(&mut model, 0x2000, &iat_data, 8, ImportAddressResolveMode::Exact, &[&kernel32]).unwrap();

    assert_eq!(recovered, 0);
    assert_eq!(model.function_count(), 0);
}
