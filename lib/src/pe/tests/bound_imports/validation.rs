use super::*;

use crate::pe::api_set::ApiSetMap;

use crate::pe::export_map::{ExportMap, ExportTableRecord, ExportTableSource};

use crate::pe::exports::ExportTable;

use crate::pe::format::{PE_DIRECTORY_ENTRY_EXPORT, PE_DIRECTORY_ENTRY_IMPORT};

fn dependency(name: &str, timestamp: Option<u32>) -> ExportTable {
    ExportTable {
        module_name: name.into(), image_base: 0x70000000, image_size: 0x2000,
        time_date_stamp: timestamp, symbols: Vec::new(),
    }
}

fn dependencies() -> ExportMap {
    let records = vec![
        ExportTableRecord { table: dependency("KERNEL32.DLL", Some(0x12345678)), source: ExportTableSource::Disk },
        ExportTableRecord { table: dependency("ntdll.dll", Some(0x87654321)), source: ExportTableSource::Mapped },
    ];
    ExportMap::with_records(records, ApiSetMap::default())
}

fn import_descriptor(image: &mut Image, timestamp: u32) {
    image.set_data_directory(PE_DIRECTORY_ENTRY_IMPORT, 0x1200, 40).unwrap();
    image.write_u32(0x1204, timestamp).unwrap();
    image.write_u32(0x120c, 0x1280).unwrap();
    image.write_u32(0x1210, 0x1300).unwrap();
    image.write_bytes(0x1280, b"KERNEL32.DLL\0").unwrap();
}

fn export_image(machine: &str) -> Image {
    let mut image = fixture(machine, 0x1100);
    image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_BOUND_IMPORT).unwrap();
    image.write_u32(image.file_header_offset() + 4, 0x12345678).unwrap();
    image.set_data_directory(PE_DIRECTORY_ENTRY_EXPORT, 0x1600, 40).unwrap();
    // The export-directory stamp deliberately differs from the COFF file-header stamp.
    image.write_u32(0x1604, 0xdeadbeef).unwrap();
    image
}

#[test]
fn matches_bound_dependencies_and_forwarders_in_both_layouts() {
    for machine in ["x86", "x64", "arm64"] {
        let mut mapped = fixture(machine, 0x1100);
        mapped.write_u16(0x110e, 0).unwrap();
        import_descriptor(&mut mapped, u32::MAX);
        let file = Image::parse(mapped.mapped_to_file_image().unwrap()).unwrap();
        for checks in [mapped.mapped_bound_import_checks(&dependencies()).unwrap(), file.bound_import_checks(&dependencies()).unwrap()] {
            assert_eq!(checks.len(), 2);
            let first = &checks[0];
            assert_eq!(first.kind, BoundImportKind::BoundDescriptor);
            assert_eq!(first.status, BoundImportStatus::TimestampMatch);
            assert_eq!(first.expected_timestamp, Some(0x12345678));
            assert_eq!(first.dependency_timestamp, Some(0x12345678));
            assert_eq!(first.dependency_source, Some(ExportTableSource::Disk));
            assert!(first.matches_dependencies());
            assert_eq!(first.forwarders[0].kind, BoundImportKind::ForwarderRef);
            assert_eq!(first.forwarders[0].dependency_source, Some(ExportTableSource::Mapped));
            assert_eq!(first.forwarders[0].reserved, Some(0));
            assert_eq!(checks[1].status, BoundImportStatus::InvalidTimestamp);
            assert!(!checks[1].matches_dependencies());
        }
    }
}

#[test]
fn reports_forwarder_mismatches_and_reserved_fields() {
    let mut image = fixture("x64", 0x1100);
    let check = image.mapped_bound_import_checks(&dependencies()).unwrap().remove(0);
    assert_eq!(check.status, BoundImportStatus::TimestampMatch);
    assert_eq!(check.forwarders[0].status, BoundImportStatus::InvalidForwarder);
    assert_eq!(check.forwarders[0].reserved, Some(7));
    assert!(!check.matches_dependencies());
    image.write_u16(0x110e, 0).unwrap();
    image.write_u32(0x1108, 0x87654322).unwrap();
    let check = image.mapped_bound_import_checks(&dependencies()).unwrap().remove(0);
    assert_eq!(check.forwarders[0].status, BoundImportStatus::TimestampMismatch);
    assert!(!check.matches_dependencies());
}

#[test]
fn distinguishes_missing_ambiguous_and_unavailable_dependency_metadata() {
    let image = fixture("x64", 0x1100);
    let missing = image.mapped_bound_import_checks(&ExportMap::default()).unwrap().remove(0);
    assert_eq!(missing.status, BoundImportStatus::DependencyMissing);
    assert_eq!(missing.dependency_source, None);
    assert_eq!(missing.dependency_timestamp, None);
    for timestamp in [None, Some(0), Some(u32::MAX), Some(1)] {
        let map = ExportMap::new(vec![dependency("kernel32.dll", timestamp)]);
        let check = image.mapped_bound_import_checks(&map).unwrap().remove(0);
        let expected = if timestamp == Some(1) { BoundImportStatus::TimestampMismatch } else { BoundImportStatus::TimestampUnavailable };
        assert_eq!(check.status, expected);
        assert_eq!(check.dependency_timestamp, timestamp);
        assert_eq!(check.dependency_source, Some(ExportTableSource::Unknown));
        assert!(!check.matches_dependencies());
    }
    let map = ExportMap::new(vec![dependency("kernel32.dll", Some(0x12345678)), dependency("KERNEL32.DLL", Some(1))]);
    let check = image.mapped_bound_import_checks(&map).unwrap().remove(0);
    assert_eq!(check.status, BoundImportStatus::DependencyAmbiguous);
    assert_eq!(check.dependency_timestamp, None);
    assert_eq!(check.dependency_source, None);
}

#[test]
fn invalid_binding_stamps_never_count_as_dependency_matches() {
    for timestamp in [0, u32::MAX] {
        let mut image = fixture("x64", 0x1100);
        image.write_u32(0x1100, timestamp).unwrap();
        let map = ExportMap::new(vec![dependency("kernel32.dll", Some(timestamp))]);
        let check = image.mapped_bound_import_checks(&map).unwrap().remove(0);
        assert_eq!(check.status, BoundImportStatus::InvalidTimestamp);
        assert!(!check.matches_dependencies());
    }
}

#[test]
fn api_set_hosts_do_not_substitute_for_bound_dependency_identity() {
    let contract = "api-ms-win-core-heap-l1-1-0";
    let host = "kernel32.dll";
    let mut namespace = vec![0u8; 0x120];
    for (offset, value) in [(0, 6u32), (4, 0x120), (12, 1), (16, 0x20), (0x24, 0x60),
        (0x28, contract.len() as u32 * 2), (0x30, 0x40), (0x34, 1), (0x4c, 0xa0), (0x50, host.len() as u32 * 2)] {
        namespace[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, text) in [(0x60, contract), (0xa0, host)] {
        for (index, unit) in text.encode_utf16().enumerate() {
            namespace[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let api_set_map = ApiSetMap::parse(&namespace).unwrap();
    assert_eq!(api_set_map.resolve_contract(contract), Some(host));
    let map = ExportMap::with_api_set_map(vec![dependency(host, Some(0x12345678))], api_set_map);
    let mut image = fixture("x64", 0x1100);
    image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_BOUND_IMPORT).unwrap();
    import_descriptor(&mut image, 0x12345678);
    image.write_bytes(0x1280, format!("{contract}.dll\0").as_bytes()).unwrap();
    assert_eq!(image.mapped_bound_import_checks(&map).unwrap()[0].status, BoundImportStatus::DependencyMissing);
}

#[test]
fn checks_legacy_stamps_without_reading_damaged_thunks() {
    for machine in ["x86", "x64", "arm64"] {
        let mut image = fixture(machine, 0x1100);
        image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_BOUND_IMPORT).unwrap();
        import_descriptor(&mut image, 0x12345678);
        image.write_u32(0x1200, 0xfffffff0).unwrap();
        assert!(image.mapped_imports().is_err());
        let checks = image.mapped_bound_import_checks(&dependencies()).unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].kind, BoundImportKind::LegacyDescriptor);
        assert_eq!(checks[0].rva, 0x1200);
        assert!(checks[0].matches_dependencies());
        let file = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
        assert!(file.bound_import_checks(&dependencies()).unwrap()[0].matches_dependencies());

        image.write_u32(0x1204, u32::MAX).unwrap();
        let checks = image.mapped_bound_import_checks(&dependencies()).unwrap();
        assert_eq!(checks[0].status, BoundImportStatus::MissingBoundDescriptor);
        assert_eq!(checks[0].expected_timestamp, None);
        assert!(!checks[0].matches_dependencies());
        image.write_u32(0x1204, 0).unwrap();
        assert!(image.mapped_bound_import_checks(&dependencies()).unwrap().is_empty());
    }
}

#[test]
fn reads_coff_timestamp_instead_of_export_directory_timestamp() {
    for machine in ["x86", "x64", "arm64"] {
        let image = export_image(machine);
        assert_eq!(image.time_date_stamp().unwrap(), 0x12345678);
        let table = ExportTable::parse(image.data(), None, Some("kernel32.dll".into())).unwrap();
        assert_eq!(table.time_date_stamp, Some(0x12345678));
    }
}
