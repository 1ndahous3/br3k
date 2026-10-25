use super::*;

#[test]
fn comparison_uses_reference_raw_offsets_and_reports_coverage() {
    let captured = file_image().to_mapped().unwrap();
    let source = file_image();
    let mut bytes = source.data().to_vec();
    bytes.resize(0x800, 0);
    bytes[0x600..0x800].copy_from_slice(&source.data()[0x200..0x400]);
    bytes[0x200..0x400].fill(0xff);
    let mut reference = Image::parse(bytes).unwrap();
    reference.write_u32(reference.section_table_offset() + 20, 0x600).unwrap();
    let comparison = Comparison::new(captured.clone(), reference.clone()).unwrap();
    assert!(comparison.complete());
    assert_eq!(comparison.sections.changed_count(), 0);
    assert_eq!(comparison.byte_changes(Default::default()).unwrap().changed_byte_count, 0);
    let missing = Image::from_mapped(captured.data().to_vec(), 0x400000, vec![MissingRange { rva: 0x1000, size: 1 }]).unwrap();
    let comparison = Comparison::new(missing, reference).unwrap();
    assert!(!comparison.complete());
    assert!(comparison.byte_changes(Default::default()).is_err());
}

#[test]
fn missing_relocations_are_a_comparison_limitation_not_a_clean_result() {
    let source = file_image();
    let captured = Image::from_mapped(source.to_mapped().unwrap().into_data(), 0x500000, Vec::new()).unwrap();
    let comparison = Comparison::new(captured, source).unwrap();
    assert!(!comparison.complete());
    assert_eq!(comparison.diagnostics[0].stage, crate::pe::diagnostic::Stage::Normalization);
}
