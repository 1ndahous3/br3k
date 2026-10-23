use super::*;
use super::code::{
    scan_arm64_code_references, scan_x86_code_references, ARM64_ADRP_OPCODE, ARM64_BLR_OPCODE,
    ARM64_BRANCH_IMM26_MASK, ARM64_BR_OPCODE, ARM64_B_OPCODE, ARM64_BL_OPCODE,
    ARM64_LDR_LITERAL_64_OPCODE, ARM64_LDR_UNSIGNED_64_OPCODE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use super::resolver::ImportAddressResolver;
use super::util::{
    ARM64_NOP, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_SCN_MEM_EXECUTE,
};

    fn export_table() -> ExportTable {
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

    fn dll_export_table() -> ExportTable {
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

    fn forwarded_kernel32_export_table() -> ExportTable {
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

    fn ntdll_export_table() -> ExportTable {
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

    fn pe32_file_image_with_import_adjacent_directories() -> Vec<u8> {
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

    fn write_test_data_directory(data: &mut [u8], base: usize, index: usize, rva: u32, size: u32) {
        let offset = base + index * 8;
        write_test_u32(data, offset, rva);
        write_test_u32(data, offset + 4, size);
    }

    fn write_test_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_test_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_test_i32(data: &mut [u8], offset: usize, value: i32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_test_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn read_test_i32(data: &[u8]) -> i32 {
        i32::from_le_bytes(data.try_into().unwrap())
    }

    fn read_test_u32(data: &[u8]) -> u32 {
        u32::from_le_bytes(data.try_into().unwrap())
    }

    fn read_test_u64(data: &[u8]) -> u64 {
        u64::from_le_bytes(data.try_into().unwrap())
    }

    fn mapped_pe_image(machine: u16, pointer_size: usize) -> Vec<u8> {
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

    fn write_x86_rel32_branch(data: &mut [u8], rva: usize, opcode: u8, source_address: u64, target_address: u64) {
        let displacement = target_address as i64 - source_address as i64 - 5;
        data[rva] = opcode;
        write_test_i32(data, rva + 1, i32::try_from(displacement).unwrap());
    }

    fn write_arm64_branch(data: &mut [u8], rva: usize, opcode: u32, source_address: u64, target_address: u64) {
        let displacement = target_address as i64 - source_address as i64;
        assert_eq!(displacement % 4, 0);
        write_test_u32(data, rva, opcode | (((displacement / 4) as i32 as u32) & ARM64_BRANCH_IMM26_MASK));
    }

    fn write_arm64_conditional_branch(data: &mut [u8], rva: usize, source_address: u64, target_address: u64) {
        let displacement = target_address as i64 - source_address as i64;
        assert_eq!(displacement % 4, 0);
        let imm19 = ((displacement / 4) as i32 as u32) & 0x7ffff;

        write_test_u32(data, rva, 0x5400_0000 | (imm19 << 5));
    }

    fn write_arm64_adrp(data: &mut [u8], rva: usize, register: u32, source_address: u64, target_address: u64) {
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

    fn write_arm64_add_immediate_64(data: &mut [u8], rva: usize, register: u32, immediate: u32) {
        assert!(immediate < 0x1000);
        write_test_u32(data, rva, 0x9100_0000 | (immediate << 10) | (register << 5) | register);
    }

    fn import_model() -> ImportModel {
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

    fn message_box_code_reference(reference_rva: u32, kind: ImportCodeReferenceKind) -> ImportCodeReference {
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

    fn message_box_iat_code_reference(reference_rva: u32, iat_rva: u32, kind: ImportCodeReferenceKind) -> ImportCodeReference {
        let mut reference = message_box_code_reference(reference_rva, kind);
        reference.iat_rva = Some(iat_rva);
        reference
    }

    fn recover_single_iat_pointer(address: u64, address_resolve_mode: ImportAddressResolveMode) -> (ImportModel, usize) {
        let mut model = ImportModel::default();
        let exports = export_table();
        let iat_data = address.to_le_bytes();
        let recovered = recover_iat(&mut model, 0x2000, &iat_data, 8, address_resolve_mode, &[&exports]).unwrap();

        (model, recovered)
    }

    fn resolve_options(mode: ImportAddressResolveMode) -> ImportAddressResolveOptions {
        ImportAddressResolveOptions {
            mode,
            resolve_forwarders: false,
            api_set_map: None,
        }
    }

    fn trace_options(start_rva: u32) -> ImportCodeTraceOptions {
        ImportCodeTraceOptions {
            start_rva,
            max_blocks: 8,
            max_bytes: 0x100,
            follow_calls: true,
        }
    }

    fn address_resolver<'a>(
        exports: &'a [&'a ExportTable],
        mode: ImportAddressResolveMode,
    ) -> ImportAddressResolver {
        ImportAddressResolver::new(exports, resolve_options(mode))
    }

    #[test]
    fn import_model_editing_updates_recovered_entries() {
        let mut model = ImportModel::default();
        model.add_module("user32.dll", 0x1000, 2).unwrap();
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
            .add_function(
                "user32.dll",
                0x1008,
                ImportTarget::Name {
                    hint: 0,
                    ordinal: None,
                    name: "LoadIconW".to_string(),
                },
                true,
                false,
            )
            .unwrap();
        model.add_module("ntdll.dll", 0x2000, 1).unwrap();
        model.add_function("ntdll.dll", 0x2000, ImportTarget::Ordinal(1), true, false).unwrap();

        model.set_function_validity(0x1000, false).unwrap();
        let invalid_import = model.imports().into_iter().find(|entry| entry.rva == 0x1000).unwrap();
        assert!(!invalid_import.valid);

        model.rename_module_containing_thunk(0x1008, "win32u.dll").unwrap();
        let renamed_import = model.imports().into_iter().find(|entry| entry.rva == 0x1008).unwrap();
        assert_eq!(renamed_import.module_name, "win32u.dll");
        assert!(matches!(
            model.rename_module_containing_thunk(0x1008, "ntdll.dll"),
            Err(ImportError::ModuleNameCollision(name)) if name == "ntdll.dll"
        ));

        model.remove_function(0x2000).unwrap();
        assert_eq!(model.module_count(), 1);
        assert_eq!(model.function_count(), 2);

        model.remove_module_containing_thunk(0x1008).unwrap();
        assert_eq!(model.module_count(), 0);
        assert_eq!(model.function_count(), 0);
        assert!(matches!(model.set_function_validity(0x1000, true), Err(ImportError::FunctionNotFound(0x1000))));
    }

    #[test]
    fn import_model_cut_thunk_removes_slot_and_splits_tail() {
        let mut model = ImportModel::default();
        model.add_module("kernel32.dll", 0x1000, 4).unwrap();
        for (index, rva) in [0x1000, 0x1008, 0x1010, 0x1018].into_iter().enumerate() {
            model
                .add_function(
                    "kernel32.dll",
                    rva,
                    ImportTarget::Name {
                        hint: 0,
                        ordinal: Some(index as u16),
                        name: format!("Function{index}"),
                    },
                    true,
                    false,
                )
                .unwrap();
        }

        model.cut_thunk(0x1008, 8).unwrap();
        let imports = model.imports();
        let modules = model.modules();

        assert_eq!(imports.len(), 3);
        assert!(!imports.iter().any(|entry| entry.rva == 0x1008));
        assert!(modules.iter().any(|module| {
            module.module_name == "kernel32.dll"
                && module.first_thunk == 0x1000
                && module.nb_thunks == 1
                && module.function_count == 1
        }));
        assert!(modules.iter().any(|module| {
            module.module_name == "?0x1010"
                && module.first_thunk == 0x1010
                && module.nb_thunks == 2
                && module.function_count == 2
        }));
        assert!(imports.iter().any(|entry| {
            entry.module_name == "?0x1010"
                && entry.rva == 0x1010
                && entry.name.as_deref() == Some("Function2")
        }));
        assert!(matches!(model.cut_thunk(0x1008, 8), Err(ImportError::ModuleThunkNotFound(0x1008))));
    }

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
    fn scan_iat_ranges_finds_terminated_export_pointer_runs() {
        let exports = export_table();
        let mut image_data = Vec::new();
        image_data.extend_from_slice(&0u64.to_le_bytes());
        image_data.extend_from_slice(&0x1010u64.to_le_bytes());
        image_data.extend_from_slice(&0x1030u64.to_le_bytes());
        image_data.extend_from_slice(&0u64.to_le_bytes());
        image_data.extend_from_slice(&0x5555u64.to_le_bytes());

        let ranges = scan_iat_ranges(&image_data, 0x3000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

        assert_eq!(
            ranges,
            vec![ImportAddressTableRange {
                rva: 0x3008,
                size: 16,
                entries: 2,
            }],
        );
    }

    #[test]
    fn rank_iat_ranges_prefers_anchor_hits_then_entry_count() {
        let ranges = vec![
            ImportAddressTableRange {
                rva: 0x3000,
                size: 0x40,
                entries: 8,
            },
            ImportAddressTableRange {
                rva: 0x5000,
                size: 0x10,
                entries: 2,
            },
        ];
        let unanchored = rank_iat_ranges(ranges.clone(), &[]).unwrap();
        let anchored = rank_iat_ranges(ranges, &[0x5008]).unwrap();

        assert_eq!(unanchored[0].range.rva, 0x3000);
        assert_eq!(unanchored[0].score, 128);
        assert_eq!(anchored[0].range.rva, 0x5000);
        assert_eq!(anchored[0].anchor_count, 1);
        assert_eq!(anchored[0].nearest_anchor_distance, Some(0));
        assert!(anchored[0].score > anchored[1].score);
    }

    #[test]
    fn scan_iat_ranges_uses_nearest_mode_when_requested() {
        let exports = export_table();
        let mut image_data = Vec::new();
        image_data.extend_from_slice(&0x1013u64.to_le_bytes());
        image_data.extend_from_slice(&0x1038u64.to_le_bytes());
        image_data.extend_from_slice(&0u64.to_le_bytes());

        let ranges = scan_iat_ranges(&image_data, 0x4000, 8, ImportAddressResolveMode::Nearest, &[&exports], 2).unwrap();

        assert_eq!(
            ranges,
            vec![ImportAddressTableRange {
                rva: 0x4000,
                size: 16,
                entries: 2,
            }],
        );
    }

    #[test]
    fn scan_iat_ranges_requires_null_terminator() {
        let exports = export_table();
        let mut image_data = Vec::new();
        image_data.extend_from_slice(&0x1010u64.to_le_bytes());
        image_data.extend_from_slice(&0x1030u64.to_le_bytes());

        let ranges = scan_iat_ranges(&image_data, 0x4000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

        assert!(ranges.is_empty());
    }

    #[test]
    fn scan_iat_ranges_keeps_singletons_near_anchor_run() {
        let exports = export_table();
        let mut image_data = Vec::new();
        image_data.extend_from_slice(&0x1010u64.to_le_bytes());
        image_data.extend_from_slice(&0x1030u64.to_le_bytes());
        image_data.extend_from_slice(&0u64.to_le_bytes());
        image_data.extend_from_slice(&0x1010u64.to_le_bytes());
        image_data.extend_from_slice(&0u64.to_le_bytes());

        let ranges = scan_iat_ranges(&image_data, 0x5000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

        assert_eq!(
            ranges,
            vec![ImportAddressTableRange {
                rva: 0x5000,
                size: 32,
                entries: 3,
            }],
        );
    }

    #[test]
    fn scan_iat_ranges_drops_isolated_singletons() {
        let exports = export_table();
        let mut image_data = Vec::new();
        image_data.extend_from_slice(&0x1010u64.to_le_bytes());
        image_data.extend_from_slice(&0u64.to_le_bytes());

        let ranges = scan_iat_ranges(&image_data, 0x5000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

        assert!(ranges.is_empty());
    }

    #[test]
    fn scan_iat_ranges_containing_rvas_keeps_anchor_ranges() {
        let exports = export_table();
        let mut image_data = vec![0u8; 0x120];
        image_data[0x00..0x08].copy_from_slice(&0x1010u64.to_le_bytes());
        image_data[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());
        image_data[0x100..0x108].copy_from_slice(&0x1030u64.to_le_bytes());
        image_data[0x108..0x110].copy_from_slice(&0u64.to_le_bytes());

        let ranges = scan_iat_ranges_containing_rvas(
            &image_data,
            0x5000,
            8,
            ImportAddressResolveMode::Exact,
            &[&exports],
            &[0x5100],
        )
        .unwrap();

        assert_eq!(
            ranges,
            vec![ImportAddressTableRange {
                rva: 0x5100,
                size: 8,
                entries: 1,
            }],
        );
    }

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
