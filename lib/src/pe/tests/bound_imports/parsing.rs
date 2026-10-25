use super::*;

#[test]
fn reads_interleaved_forwarders_in_file_and_mapped_layouts_on_all_architectures() {
    for machine in ["x86", "x64", "arm64"] {
        let mapped = fixture(machine, DIRECTORY_RVA);
        let descriptors = mapped.mapped_bound_imports().unwrap();
        assert_eq!(descriptors.len(), 2);
        let first = &descriptors[0];
        assert_eq!(first.dll_name, "kernel32.dll");
        assert_eq!(first.module_name_offset, 0x20);
        assert_eq!(first.descriptor_rva, DIRECTORY_RVA);
        assert_eq!(first.time_date_stamp, 0x12345678);
        assert_eq!(first.forwarders.len(), 1);
        assert_eq!(first.forwarders[0].dll_name, "ntdll.dll");
        assert_eq!(first.forwarders[0].rva, DIRECTORY_RVA + 8);
        assert_eq!(first.forwarders[0].time_date_stamp, 0x87654321);
        assert_eq!(first.forwarders[0].reserved, 7);
        assert_eq!(descriptors[1].descriptor_rva, DIRECTORY_RVA + 16);
        assert_eq!(descriptors[1].dll_name, "user32.dll");
        assert_eq!(descriptors[1].time_date_stamp, 0);
        assert!(descriptors[1].forwarders.is_empty());

        let file = Image::parse(mapped.mapped_to_file_image().unwrap()).unwrap();
        assert_ne!(file.rva_to_file_offset(DIRECTORY_RVA).unwrap(), DIRECTORY_RVA as usize);
        assert_eq!(file.bound_imports().unwrap(), descriptors);
        for (image, mapped_layout) in [(&mapped, true), (&file, false)] {
            let metadata = metadata_summary(image.data(), mapped_layout).unwrap();
            assert!(metadata.bound_imports.present);
            assert!(!metadata.anomalies.iter().any(|item| item.kind == ImageAnomalyKind::InvalidBoundImportDirectory));
        }
    }
}

#[test]
fn reads_directory_in_headers_and_shared_names() {
    let mut image = fixture("x64", 0x1b0);
    image.write_u16(0x1b0 + 20, 0x20).unwrap();
    assert_eq!(image.bound_imports().unwrap(), image.mapped_bound_imports().unwrap());
    let descriptors = image.bound_imports().unwrap();
    assert_eq!(descriptors[0].dll_name, descriptors[1].dll_name);
}

#[test]
fn accepts_missing_empty_and_null_directories() {
    let mut image = fixture("x64", DIRECTORY_RVA);
    image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_BOUND_IMPORT).unwrap();
    assert!(image.bound_imports().unwrap().is_empty());
    image.set_data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT, DIRECTORY_RVA + 24, 8).unwrap();
    assert!(image.mapped_bound_imports().unwrap().is_empty());
    image.write_u32(image.optional_header_offset() + 108, PE_DIRECTORY_ENTRY_BOUND_IMPORT as u32).unwrap();
    let image = Image::parse(image.into_data()).unwrap();
    assert!(image.bound_imports().unwrap().is_empty());
}

#[test]
fn rejects_partial_and_overflowing_directories() {
    for (rva, size) in [(0, 8), (DIRECTORY_RVA, 0), (u32::MAX - 3, 8), (0x1ff8, 16)] {
        let mut image = fixture("x64", DIRECTORY_RVA);
        image.set_data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT, rva, size).unwrap();
        assert!(matches!(image.bound_imports(), Err(BoundImportError::InvalidDirectory { .. })));
        assert!(matches!(image.mapped_bound_imports(), Err(BoundImportError::InvalidDirectory { .. })));
    }
}

#[test]
fn rejects_truncated_records_and_forwarder_arrays() {
    let mut image = fixture("x64", DIRECTORY_RVA);
    image.set_data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT, DIRECTORY_RVA, 7).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::TruncatedRecord { offset: 0 })));
    image.set_data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT, DIRECTORY_RVA, DIRECTORY_SIZE).unwrap();
    image.write_u16(DIRECTORY_RVA as usize + 6, u16::MAX).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::TruncatedForwarders { count: u16::MAX, .. })));
}

#[test]
fn requires_terminator_before_name_pool() {
    let mut image = fixture("x64", DIRECTORY_RVA);
    image.write_u16(DIRECTORY_RVA as usize + 24 + 4, 0x20).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::MissingTerminator)));
}

#[test]
fn rejects_out_of_bounds_and_unterminated_names() {
    let mut image = fixture("x64", DIRECTORY_RVA);
    image.write_u16(DIRECTORY_RVA as usize + 4, DIRECTORY_SIZE as u16).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::InvalidNameOffset { .. })));
    image.write_u16(DIRECTORY_RVA as usize + 4, (DIRECTORY_SIZE - 1) as u16).unwrap();
    image.write_bytes((DIRECTORY_RVA + DIRECTORY_SIZE - 1) as usize, b"x").unwrap();
    // A NUL exists just outside the directory, but must not terminate this name.
    assert!(matches!(image.bound_imports(), Err(BoundImportError::UnterminatedName { .. })));
}

#[test]
fn rejects_empty_non_ascii_and_record_overlapping_names() {
    let mut image = fixture("x64", DIRECTORY_RVA);
    image.write_bytes(DIRECTORY_RVA as usize + 0x20, b"\0").unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::InvalidName { .. })));
    image.write_bytes(DIRECTORY_RVA as usize + 0x20, &[0xff]).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::InvalidName { .. })));

    let mut image = fixture("x64", DIRECTORY_RVA);
    image.write_u32(DIRECTORY_RVA as usize, 0x41).unwrap();
    image.write_u16(DIRECTORY_RVA as usize + 4, 0).unwrap();
    assert!(matches!(image.bound_imports(), Err(BoundImportError::NameOverlapsRecords { offset: 0 })));
}

#[test]
fn file_directory_does_not_read_virtual_tail_or_overlay() {
    let mapped = fixture("x64", DIRECTORY_RVA);
    let mut file = Image::parse(mapped.mapped_to_file_image().unwrap()).unwrap();
    let section_table = file.section_table_offset();
    file.write_u32(section_table + 16, 0x120).unwrap();
    let file = Image::parse(file.into_data()).unwrap();
    assert!(matches!(file.bound_imports(), Err(BoundImportError::Image(ImageError::RvaNotMapped { rva: 0x1120 }))));
    assert_eq!(mapped.mapped_bound_imports().unwrap().len(), 2);
}

#[test]
fn malformed_bound_imports_become_anomalies_without_losing_metadata() {
    let mut image = fixture("arm64", DIRECTORY_RVA);
    image.write_u16(DIRECTORY_RVA as usize + 6, u16::MAX).unwrap();
    let metadata = metadata_summary(image.data(), true).unwrap();
    assert!(metadata.bound_imports.present);
    let anomaly = metadata.anomalies.iter().find(|item| item.kind == ImageAnomalyKind::InvalidBoundImportDirectory).unwrap();
    assert_eq!(anomaly.directory_index, Some(PE_DIRECTORY_ENTRY_BOUND_IMPORT));
    assert_eq!(anomaly.rva, Some(DIRECTORY_RVA));
    assert!(anomaly.message.contains("forwarder references"));
}
