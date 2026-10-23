use super::*;
use crate::pe::export_map::ExportMap;
use crate::pe::exports::{ExportSymbol, ExportTable};
use crate::pe::format;

const PE_OFFSET: usize = 0x80;
const FILE_HEADER_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_HEADER_OFFSET: usize = FILE_HEADER_OFFSET + 20;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 0xf0;
const LOAD_CONFIG_RVA: u32 = 0x2000;
const LOAD_CONFIG_OFFSET: usize = 0x400;

#[test]
fn reads_modern_pe64_load_config_fields() {
    let mut data = pe64_with_load_config(0x140);
    let guard_flags = format::IMAGE_GUARD_CF_INSTRUMENTED
        | format::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
        | format::IMAGE_GUARD_RF_ENABLE
        | format::IMAGE_GUARD_RETPOLINE_PRESENT
        | format::IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT
        | format::IMAGE_GUARD_XFG_ENABLED
        | format::IMAGE_GUARD_CASTGUARD_PRESENT
        | format::IMAGE_GUARD_MEMCPY_PRESENT
        | (2 << format::IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);

    put_u32(&mut data, LOAD_CONFIG_OFFSET, 0x140);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x04, 0x1234_5678);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0x08, 1);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0x0a, 2);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x48, 0x4000);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0x4e, 0x55aa);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x58, 0x18000_5000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x70, 0x18000_1000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x78, 0x18000_1008);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x80, 0x18000_6000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x88, 3);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x90, guard_flags);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0x94, 0x11);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0x96, 0xffff);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x98, 0x2222);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x9c, 0x3333);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0xc0, 0x18000_8000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0xc8, 0x18000_7000);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0xe0, 0x120);
    put_u16(&mut data, LOAD_CONFIG_OFFSET + 0xe4, 2);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0xf0, 0x80);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0xf8, 0x18000_9000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x100, 0x18000_a000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x108, 0x18000_b000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x110, 4);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x118, 0x18000_c000);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x120, 0x18000_c008);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x128, 0x18000_c010);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x130, 0x18000_c018);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x138, 0x18000_c020);

    let metadata = metadata_summary(&data, false).unwrap();
    let load_config = metadata.load_config;
    let flag_names = load_config.guard_flag_names();

    assert!(load_config.present);
    assert_eq!(load_config.rva, LOAD_CONFIG_RVA);
    assert_eq!(load_config.size, 0x140);
    assert_eq!(load_config.structure_size, Some(0x140));
    assert_eq!(load_config.time_date_stamp, Some(0x1234_5678));
    assert_eq!(load_config.major_version, Some(1));
    assert_eq!(load_config.minor_version, Some(2));
    assert_eq!(load_config.dependent_load_flags, Some(0x55aa));
    assert_eq!(load_config.process_heap_flags, Some(0x4000));
    assert_eq!(load_config.security_cookie, Some(0x18000_5000));
    assert_eq!(load_config.guard_flags, Some(guard_flags));
    assert_eq!(load_config.guard_cf_function_table_entry_size(), Some(6));
    assert_eq!(
        load_config.code_integrity,
        Some(LoadConfigCodeIntegrityInfo {
            flags: 0x11,
            catalog: 0xffff,
            catalog_offset: 0x2222,
            reserved: 0x3333,
        })
    );
    assert!(load_config.guard_cf_instrumented());
    assert!(load_config.guard_cf_function_table_present());
    assert!(load_config.guard_rf_enabled());
    assert!(load_config.has_xfg());
    assert!(load_config.has_cast_guard());
    assert!(load_config.has_guard_memcpy());
    assert!(load_config.has_chpe_metadata());
    assert!(load_config.has_dynamic_value_relocations());
    assert!(load_config.has_hotpatch_table());
    assert!(load_config.has_enclave_config());
    assert!(load_config.has_volatile_metadata());
    assert!(load_config.has_guard_eh_continuations());
    assert!(flag_names.contains(&"CFInstrumented"));
    assert!(flag_names.contains(&"XFGEnabled"));
    assert!(flag_names.contains(&"CastGuard"));
    assert!(flag_names.contains(&"GuardMemcpy"));
}

#[test]
fn respects_load_config_structure_size() {
    let mut data = pe64_with_load_config(0x140);

    put_u32(&mut data, LOAD_CONFIG_OFFSET, 0x90);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x48, 0x4000);
    put_u32(&mut data, LOAD_CONFIG_OFFSET + 0x90, format::IMAGE_GUARD_CF_INSTRUMENTED);
    put_u64(&mut data, LOAD_CONFIG_OFFSET + 0x118, 0x18000_c000);

    let metadata = metadata_summary(&data, false).unwrap();
    let load_config = metadata.load_config;

    assert!(load_config.present);
    assert_eq!(load_config.structure_size, Some(0x90));
    assert_eq!(load_config.process_heap_flags, Some(0x4000));
    assert_eq!(load_config.guard_flags, None);
    assert_eq!(load_config.code_integrity, None);
    assert!(!load_config.has_xfg());
}

#[test]
fn import_address_changes_report_patched_iat_slots() {
    let disk = pe32_with_imports();
    let mut mapped = disk.clone();
    put_u32(&mut mapped, 0x1300, 0x7700_2000);
    let export_map = ExportMap::new(vec![
        ExportTable {
            module_name: "kernel32.dll".to_string(),
            image_base: 0x7600_0000,
            image_size: 0x10000,
            time_date_stamp: None,
            symbols: vec![ExportSymbol {
                module_name: "kernel32.dll".to_string(),
                name: Some("LoadLibraryA".to_string()),
                names: vec!["LoadLibraryA".to_string()],
                ordinal: 1,
                rva: 0x1000,
                address: 0x7600_1000,
                forwarder: None,
            }],
        },
        ExportTable {
            module_name: "edr.dll".to_string(),
            image_base: 0x7700_0000,
            image_size: 0x10000,
            time_date_stamp: None,
            symbols: vec![ExportSymbol {
                module_name: "edr.dll".to_string(),
                name: Some("Hook".to_string()),
                names: vec!["Hook".to_string()],
                ordinal: 7,
                rva: 0x2000,
                address: 0x7700_2000,
                forwarder: None,
            }],
        },
    ]);

    let changes = import_address_changes(&mapped, &disk, &export_map).unwrap();

    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].module_name, "kernel32.dll");
    assert_eq!(changes[0].name.as_deref(), Some("LoadLibraryA"));
    assert_eq!(changes[0].ordinal, None);
    assert_eq!(changes[0].iat_rva, 0x1300);
    assert_eq!(changes[0].expected_address, 0x7600_1000);
    assert_eq!(changes[0].expected_module_name, "kernel32.dll");
    assert_eq!(changes[0].expected_name.as_deref(), Some("LoadLibraryA"));
    assert_eq!(changes[0].actual_address, 0x7700_2000);
    assert_eq!(changes[0].actual_module_name.as_deref(), Some("edr.dll"));
    assert_eq!(changes[0].actual_name.as_deref(), Some("Hook"));
    assert_eq!(changes[0].actual_ordinal, Some(7));
}

#[test]
fn image_anomalies_report_structural_oddities() {
    let mut data = pe32_with_imports();
    let pe32_section_table_offset = OPTIONAL_HEADER_OFFSET + 0xe0;

    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 16, 0x5000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 96 + format::PE_DIRECTORY_ENTRY_DEBUG * 8, 0x5000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 100 + format::PE_DIRECTORY_ENTRY_DEBUG * 8, 0x40);
    put_u32(
        &mut data,
        pe32_section_table_offset + 36,
        format::IMAGE_SCN_CNT_INITIALIZED_DATA | format::IMAGE_SCN_MEM_EXECUTE | format::IMAGE_SCN_MEM_WRITE,
    );

    let anomalies = image_anomalies(&data, false).unwrap();

    assert!(has_anomaly(&anomalies, ImageAnomalyKind::EntryPointOutsideSections));
    assert!(has_anomaly(&anomalies, ImageAnomalyKind::ExecutableWritableSection));
    assert!(has_anomaly(&anomalies, ImageAnomalyKind::DataDirectoryOutsideImage));
    assert!(metadata_summary(&data, false)
        .unwrap()
        .anomalies
        .iter()
        .any(|anomaly| anomaly.kind == ImageAnomalyKind::ExecutableWritableSection));
}

#[test]
fn section_byte_changes_report_normalized_changed_ranges() {
    let disk = pe32_with_imports();
    let mut mapped = disk.clone();
    put_u32(&mut mapped, 0x1300, 0x7700_2000);
    mapped[0x1260..0x1264].copy_from_slice(&[0x90, 0x90, 0xcc, 0xcc]);

    let changes = section_byte_changes(
        &mapped,
        &disk,
        ByteChangeOptions {
            max_ranges: 8,
            sample_size: 2,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(changes.compared_section_count, 1);
    assert_eq!(changes.changed_section_count, 1);
    assert_eq!(changes.changed_byte_count, 4);
    assert_eq!(changes.range_count(), 1);
    assert!(!changes.truncated);
    assert_eq!(changes.ranges[0].section_name, ".idata");
    assert_eq!(changes.ranges[0].rva, 0x1260);
    assert_eq!(changes.ranges[0].offset, 0x260);
    assert_eq!(changes.ranges[0].size, 4);
    assert_eq!(changes.ranges[0].mapped_sample, vec![0x90, 0x90]);
    assert_eq!(changes.ranges[0].disk_sample, vec![0, 0]);
    assert!(changes.ranges[0].sample_truncated);
}

fn pe64_with_load_config(load_config_size: u32) -> Vec<u8> {
    let mut data = vec![0u8; 0x800];
    put_u16(&mut data, 0, format::IMAGE_DOS_SIGNATURE);
    put_u32(&mut data, 0x3c, PE_OFFSET as u32);
    put_u32(&mut data, PE_OFFSET, format::IMAGE_NT_SIGNATURE);
    put_u16(&mut data, FILE_HEADER_OFFSET, format::IMAGE_FILE_MACHINE_AMD64);
    put_u16(&mut data, FILE_HEADER_OFFSET + 2, 1);
    put_u16(&mut data, FILE_HEADER_OFFSET + 16, 0xf0);
    put_u16(&mut data, FILE_HEADER_OFFSET + 18, format::IMAGE_FILE_EXECUTABLE_IMAGE);
    put_u16(&mut data, OPTIONAL_HEADER_OFFSET, format::IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 16, 0x1000);
    put_u64(&mut data, OPTIONAL_HEADER_OFFSET + 24, 0x18000_0000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 36, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 56, 0x3000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 60, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 108, 16);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 112 + format::PE_DIRECTORY_ENTRY_LOAD_CONFIG * 8, LOAD_CONFIG_RVA);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 116 + format::PE_DIRECTORY_ENTRY_LOAD_CONFIG * 8, load_config_size);
    put_section_header(
        &mut data,
        SECTION_TABLE_OFFSET,
        ".rdata",
        0x1000,
        LOAD_CONFIG_RVA,
        0x400,
        LOAD_CONFIG_OFFSET as u32,
        format::IMAGE_SCN_CNT_INITIALIZED_DATA | format::IMAGE_SCN_MEM_READ,
    );

    data
}

fn pe32_with_imports() -> Vec<u8> {
    const PE32_SECTION_TABLE_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 0xe0;
    const IMPORT_DIRECTORY_RVA: u32 = 0x1100;
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_OFFSET: usize = SECTION_RVA as usize;

    let mut data = vec![0u8; 0x3000];
    put_u16(&mut data, 0, format::IMAGE_DOS_SIGNATURE);
    put_u32(&mut data, 0x3c, PE_OFFSET as u32);
    put_u32(&mut data, PE_OFFSET, format::IMAGE_NT_SIGNATURE);
    put_u16(&mut data, FILE_HEADER_OFFSET, format::IMAGE_FILE_MACHINE_I386);
    put_u16(&mut data, FILE_HEADER_OFFSET + 2, 1);
    put_u16(&mut data, FILE_HEADER_OFFSET + 16, 0xe0);
    put_u16(&mut data, FILE_HEADER_OFFSET + 18, format::IMAGE_FILE_EXECUTABLE_IMAGE);
    put_u16(&mut data, OPTIONAL_HEADER_OFFSET, format::IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 28, 0x400000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 36, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 56, 0x3000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 60, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 92, 16);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 96 + format::PE_DIRECTORY_ENTRY_IMPORT * 8, IMPORT_DIRECTORY_RVA);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 100 + format::PE_DIRECTORY_ENTRY_IMPORT * 8, 0x40);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 96 + format::PE_DIRECTORY_ENTRY_IAT * 8, 0x1300);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 100 + format::PE_DIRECTORY_ENTRY_IAT * 8, 0x0c);
    put_section_header(
        &mut data,
        PE32_SECTION_TABLE_OFFSET,
        ".idata",
        0x2000,
        SECTION_RVA,
        0x2000,
        SECTION_OFFSET as u32,
        format::IMAGE_SCN_CNT_INITIALIZED_DATA | format::IMAGE_SCN_MEM_READ,
    );

    put_u32(&mut data, 0x1100, 0x1200);
    put_u32(&mut data, 0x1104, 0);
    put_u32(&mut data, 0x1108, 0);
    put_u32(&mut data, 0x110c, 0x1240);
    put_u32(&mut data, 0x1110, 0x1300);
    put_u32(&mut data, 0x1200, 0x1250);
    put_u32(&mut data, 0x1204, 0);
    put_u32(&mut data, 0x1300, 0x1250);
    put_u32(&mut data, 0x1304, 0);
    write_cstr(&mut data, 0x1240, "kernel32.dll");
    put_u16(&mut data, 0x1250, 7);
    write_cstr(&mut data, 0x1252, "LoadLibraryA");

    data
}

fn put_section_header(
    data: &mut [u8],
    offset: usize,
    name: &str,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) {
    data[offset..offset + 8].fill(0);
    data[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    put_u32(data, offset + 8, virtual_size);
    put_u32(data, offset + 12, virtual_address);
    put_u32(data, offset + 16, raw_size);
    put_u32(data, offset + 20, raw_offset);
    put_u32(data, offset + 36, characteristics);
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_cstr(data: &mut [u8], offset: usize, value: &str) {
    data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    data[offset + value.len()] = 0;
}

fn has_anomaly(anomalies: &[ImageAnomaly], kind: ImageAnomalyKind) -> bool {
    anomalies.iter().any(|anomaly| anomaly.kind == kind)
}
