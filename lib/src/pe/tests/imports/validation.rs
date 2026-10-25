use super::*;

#[test]
fn import_model_issues_report_suspicious_rebuild_inputs() {
    let mut model = ImportModel::default();
    model.add_module("kernel32.dll", 0x1000, 1).unwrap();
    model.add_module("user32.dll", 0x1008, 1).unwrap();
    model.add_module("orphan.dll", 0x3000, 1).unwrap();
    model.add_module("dup.dll", 0x4000, 2).unwrap();

    model
        .add_function(
            "kernel32.dll",
            0x1000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "CreateFileW".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "user32.dll",
            0x1008,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "MessageBoxW".to_string(),
            },
            false,
            false,
        )
        .unwrap();
    model
        .add_function("user32.dll", 0x1018, ImportTarget::Ordinal(7), true, false)
        .unwrap();
    model
        .add_function(
            "dup.dll",
            0x4000,
            ImportTarget::Name {
                hint: 0,
                ordinal: Some(1),
                name: "SameApi".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "dup.dll",
            0x4008,
            ImportTarget::Name {
                hint: 7,
                ordinal: Some(1),
                name: "SameApi".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    let issues = model.issues(8).unwrap();
    let modules = model.modules();

    assert_eq!(modules.len(), 4);
    assert!(modules.iter().any(|module| {
        module.module_name == "user32.dll"
            && module.first_thunk == 0x1008
            && module.nb_thunks == 1
            && module.function_count == 2
            && module.valid_function_count == 1
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::AdjacentDifferentModule
            && issue.severity == ImportIssueSeverity::Warning
            && issue.rva == 0x1000
            && issue.module_name == "kernel32.dll"
            && issue.next_rva == Some(0x1008)
            && issue.next_module_name.as_deref() == Some("user32.dll")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::InvalidFunction
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x1008
            && issue.module_name == "user32.dll"
            && issue.name.as_deref() == Some("MessageBoxW")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ThunkOutsideModuleRange
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x1018
            && issue.module_name == "user32.dll"
            && issue.ordinal == Some(7)
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ModuleWithoutValidFunctions
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x3000
            && issue.module_name == "orphan.dll"
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::SingletonValidFunction
            && issue.severity == ImportIssueSeverity::Suspect
            && issue.rva == 0x1000
            && issue.module_name == "kernel32.dll"
            && issue.name.as_deref() == Some("CreateFileW")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::SingletonValidFunction
            && issue.rva == 0x1018
            && issue.module_name == "user32.dll"
            && issue.ordinal == Some(7)
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::DuplicateImportTargetInModule
            && issue.severity == ImportIssueSeverity::Suspect
            && issue.rva == 0x4008
            && issue.module_name == "dup.dll"
            && issue.name.as_deref() == Some("SameApi")
            && issue.ordinal == Some(1)
            && issue.next_rva == Some(0x4000)
            && issue.next_module_name.as_deref() == Some("dup.dll")
    }));
}

#[test]
fn import_model_issues_report_sparse_ranges_and_edge_functions() {
    let mut model = ImportModel::default();
    model.add_module("gap.dll", 0x5000, 4).unwrap();
    model
        .add_function(
            "gap.dll",
            0x5000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "First".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "gap.dll",
            0x5018,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "Last".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    let issues = model.issues(8).unwrap();

    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::SparseModuleRange
            && issue.severity == ImportIssueSeverity::Warning
            && issue.rva == 0x5008
            && issue.module_name == "gap.dll"
            && issue.next_rva == Some(0x5018)
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::FunctionAdjacentToRangeGap
            && issue.severity == ImportIssueSeverity::Suspect
            && issue.rva == 0x5000
            && issue.name.as_deref() == Some("First")
            && issue.next_rva == Some(0x5008)
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::FunctionAdjacentToRangeGap
            && issue.severity == ImportIssueSeverity::Suspect
            && issue.rva == 0x5018
            && issue.name.as_deref() == Some("Last")
            && issue.next_rva == Some(0x5010)
    }));
}

#[test]
fn import_model_issues_report_invalid_module_range_shapes() {
    let mut model = ImportModel::default();

    model.add_module("empty.dll", 0x6000, 0).unwrap();

    model.add_module("overlap_a.dll", 0x7000, 3).unwrap();
    model.add_module("overlap_b.dll", 0x7010, 2).unwrap();
    model
        .add_function(
            "overlap_a.dll",
            0x7000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "First".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "overlap_b.dll",
            0x7010,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "Second".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    model.add_module("misaligned.dll", 0x8000, 2).unwrap();
    model
        .add_function(
            "misaligned.dll",
            0x8004,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "OddSlot".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    model.add_module("dup_a.dll", 0x9000, 1).unwrap();
    model.add_module("dup_b.dll", 0x9000, 1).unwrap();
    model
        .add_function(
            "dup_a.dll",
            0x9000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "SameSlotA".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "dup_b.dll",
            0x9000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "SameSlotB".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    model.add_module("wide.dll", 0xa000, 8).unwrap();
    model.add_module("inside_a.dll", 0xa010, 1).unwrap();
    model.add_module("inside_b.dll", 0xa030, 1).unwrap();
    model
        .add_function(
            "wide.dll",
            0xa000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "Wide".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "inside_a.dll",
            0xa010,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "InsideA".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "inside_b.dll",
            0xa030,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "InsideB".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    let issues = model.issues(8).unwrap();

    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::EmptyModuleRange
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x6000
            && issue.module_name == "empty.dll"
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::OverlappingModuleRange
            && issue.severity == ImportIssueSeverity::Warning
            && issue.rva == 0x7010
            && issue.module_name == "overlap_a.dll"
            && issue.next_rva == Some(0x7018)
            && issue.next_module_name.as_deref() == Some("overlap_b.dll")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::OverlappingModuleRange
            && issue.severity == ImportIssueSeverity::Warning
            && issue.rva == 0xa030
            && issue.module_name == "wide.dll"
            && issue.next_rva == Some(0xa040)
            && issue.next_module_name.as_deref() == Some("inside_b.dll")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ThunkMisalignedInModuleRange
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x8004
            && issue.module_name == "misaligned.dll"
            && issue.name.as_deref() == Some("OddSlot")
    }));
    assert!(issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::DuplicateThunkRvaAcrossModules
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x9000
            && issue.module_name == "dup_b.dll"
            && issue.name.as_deref() == Some("SameSlotB")
            && issue.next_rva == Some(0x9000)
            && issue.next_module_name.as_deref() == Some("dup_a.dll")
    }));
}

#[test]
fn import_model_issues_can_validate_targets_against_exports() {
    let exports = export_table();
    let mut model = ImportModel::default();

    model.add_module("kernel32.dll", 0x6000, 4).unwrap();
    model
        .add_function(
            "kernel32.dll",
            0x6000,
            ImportTarget::Name {
                hint: 0,
                ordinal: Some(1),
                name: "Target".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "kernel32.dll",
            0x6008,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "MissingName".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function("kernel32.dll", 0x6010, ImportTarget::Ordinal(2), true, false)
        .unwrap();
    model
        .add_function("kernel32.dll", 0x6018, ImportTarget::Ordinal(999), true, false)
        .unwrap();
    model.add_module("custom.dll", 0x7000, 1).unwrap();
    model
        .add_function(
            "custom.dll",
            0x7000,
            ImportTarget::Name {
                hint: 0,
                ordinal: None,
                name: "Custom".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    let structural_issues = model.issues(8).unwrap();
    let export_issues = model.issues_with_exports(8, &[&exports]).unwrap();

    assert!(!structural_issues.iter().any(|issue| issue.kind == ImportIssueKind::ImportTargetMissingFromExports));
    assert!(export_issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ImportTargetMissingFromExports
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x6008
            && issue.module_name == "kernel32.dll"
            && issue.name.as_deref() == Some("MissingName")
    }));
    assert!(export_issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ImportTargetMissingFromExports
            && issue.severity == ImportIssueSeverity::Error
            && issue.rva == 0x6018
            && issue.module_name == "kernel32.dll"
            && issue.ordinal == Some(999)
    }));
    assert!(export_issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::OrdinalOnlyImportHasNamedExport
            && issue.severity == ImportIssueSeverity::Suspect
            && issue.rva == 0x6010
            && issue.module_name == "kernel32.dll"
            && issue.ordinal == Some(2)
    }));
    assert!(export_issues.iter().any(|issue| {
        issue.kind == ImportIssueKind::ImportModuleMissingExportTable
            && issue.severity == ImportIssueSeverity::Warning
            && issue.rva == 0x7000
            && issue.module_name == "custom.dll"
    }));
}

#[test]
fn import_model_issues_report_repeated_import_target_runs() {
    let mut model = ImportModel::default();

    model.add_module("repeat.dll", 0xb000, 6).unwrap();
    for rva in [0xb000, 0xb008, 0xb010] {
        model
            .add_function(
                "repeat.dll",
                rva,
                ImportTarget::Name {
                    hint: 0,
                    ordinal: Some(1),
                    name: "Repeated".to_string(),
                },
                true,
                false,
            )
            .unwrap();
    }
    model
        .add_function(
            "repeat.dll",
            0xb020,
            ImportTarget::Name {
                hint: 0,
                ordinal: Some(1),
                name: "Repeated".to_string(),
            },
            true,
            false,
        )
        .unwrap();
    model
        .add_function(
            "repeat.dll",
            0xb028,
            ImportTarget::Name {
                hint: 0,
                ordinal: Some(2),
                name: "Other".to_string(),
            },
            true,
            false,
        )
        .unwrap();

    let issues = model.issues(8).unwrap();
    let repeated_runs = issues
        .iter()
        .filter(|issue| issue.kind == ImportIssueKind::RepeatedImportTargetRun)
        .collect::<Vec<_>>();

    assert_eq!(repeated_runs.len(), 1);
    assert_eq!(repeated_runs[0].severity, ImportIssueSeverity::Suspect);
    assert_eq!(repeated_runs[0].rva, 0xb000);
    assert_eq!(repeated_runs[0].module_name, "repeat.dll");
    assert_eq!(repeated_runs[0].name.as_deref(), Some("Repeated"));
    assert_eq!(repeated_runs[0].next_rva, Some(0xb010));
}
