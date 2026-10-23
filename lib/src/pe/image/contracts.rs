use super::{Image, Error, Layout, MissingRange, SanitizeHeadersOptions};
use super::editor::{Editor, ChangeKind};
use super::tests::{mapped_pe32_image, trusted_pe32_image_with_resource, mapped_pe32_image_with_resource};
use crate::pe::{capture::Capture, diagnostics::comparison::Comparison};
use std::sync::Arc;

fn file_image() -> Image {
    Image::parse(Image::parse(mapped_pe32_image()).unwrap().mapped_to_file_image().unwrap()).unwrap()
}

#[test]
fn explicit_layout_preserves_addresses_and_mapping() {
    let file = file_image();
    let mapped = file.to_mapped().unwrap();
    assert_eq!(file.layout(), Layout::File);
    assert_eq!(mapped.layout(), Layout::Mapped);
    assert_eq!(file.read_rva(0x1000, 3).unwrap(), mapped.read_rva(0x1000, 3).unwrap());
    assert_eq!(mapped.rva_to_va(0x1000).unwrap(), 0x401000);
    assert_eq!(mapped.va_to_rva(0x401000).unwrap(), 0x1000);
    assert!(mapped.va_to_rva(0x3fffff).is_err());
    assert_eq!(mapped.to_file().unwrap().read_rva(0x1000, 3).unwrap(), &[1, 2, 3]);
}

#[test]
fn virtual_tails_are_not_file_bytes() {
    let mut file = file_image();
    file.write_u32(file.section_table_offset() + 8, 0x400).unwrap();
    assert!(file.read_rva(0x11ff, 2).is_err());
    assert!(file.read_rva(0x1200, 1).is_err());
    assert_eq!(file.to_mapped().unwrap().read_rva(0x1200, 1).unwrap(), &[0]);
}

#[test]
fn file_reads_recheck_section_ownership_across_boundaries() {
    let mut file = file_image();
    let second_header = file.section_table_offset() + 40;
    file.write_bytes(second_header, &[0; 40]).unwrap();
    file.write_u32(second_header + 8, 0x100).unwrap();
    file.write_u32(second_header + 12, 0x1100).unwrap();
    file.write_u32(second_header + 16, 0x100).unwrap();
    file.write_u32(second_header + 20, 0x300).unwrap();
    file.write_u16(file.file_header_offset() + 2, 2).unwrap();
    let file = Image::parse(file.into_data()).unwrap();
    assert!(file.read_rva(0x1000, 0x100).is_ok());
    assert!(file.read_rva(0x1000, 0x101).is_err());
    assert!(file.read_rva(0x1100, 1).is_err());
}

#[test]
fn capture_missing_section_is_not_recovered_zeroes() {
    let data = mapped_pe32_image();
    let capture = Capture::read(0x400000, data.len() as u32, "test".into(), None, 1, |address, size| {
        let offset = (address - 0x400000) as usize;
        if offset == 0x1000 { Err("fixture unreadable page".into()) } else { Ok(data[offset..offset + size].to_vec()) }
    }).unwrap();
    assert!(!capture.complete());
    let image = capture.image().unwrap();
    assert!(matches!(image.read_rva(0x1000, 1), Err(Error::MissingData { .. })));
    assert!(image.to_file().is_err());
    assert!(crate::pe::recovery::imports::Input::new(image).is_err());
}

#[test]
fn capture_layout_gaps_do_not_discard_readable_sections() {
    let image = Image::from_mapped(mapped_pe32_image(), 0x500000, vec![MissingRange { rva: 0x200, size: 0xe00 }]).unwrap();
    assert!(image.to_file().is_ok());
    assert_eq!(image.image_base().unwrap(), 0x400000);
    assert_eq!(image.load_base(), Some(0x500000));
    assert!(image.read_rva(0x200, 1).is_err());
    assert!(Image::from_mapped(mapped_pe32_image(), 0x400000, vec![MissingRange { rva: 0, size: 1 }]).is_err());
}

#[test]
fn image_clones_share_backing_but_edits_and_caches_do_not_leak() {
    let original = file_image();
    original.section_view().unwrap();
    let mut changed = original.clone();
    assert!(Arc::ptr_eq(&original.shared_data(), &changed.shared_data()));
    changed.write_u32(changed.section_table_offset() + 8, 0x100).unwrap();
    assert!(!Arc::ptr_eq(&original.shared_data(), &changed.shared_data()));
    assert_eq!(original.section_view().unwrap()[0].virtual_size, 3);
    assert_eq!(changed.section_view().unwrap()[0].virtual_size, 0x100);
}

#[test]
fn editor_failed_transaction_preserves_revision_and_source() {
    let mut source = file_image();
    source.write_u32(source.optional_header_offset() + 64, 0x12345678).unwrap();
    let mut editor = Editor::new(source.clone());
    let result = editor.apply::<Error>(ChangeKind::Bytes, |_| Ok(vec![0; 64]));
    assert!(result.is_err());
    assert_eq!(editor.revision(), 0);
    assert_eq!(editor.image().data(), source.data());
    editor.sanitize_headers(SanitizeHeadersOptions { clear_checksum: true, ..Default::default() }).unwrap();
    assert_eq!(editor.revision(), 1);
    assert_eq!(source.read_u32(source.optional_header_offset() + 64).unwrap(), 0x12345678);
    assert_eq!(editor.build().unwrap().image.read_u32(source.optional_header_offset() + 64).unwrap(), 0);
}

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

#[test]
fn resources_compare_payloads_even_when_sizes_match() {
    let reference = Image::parse(trusted_pe32_image_with_resource()).unwrap();
    let mut captured = Image::from_mapped(mapped_pe32_image_with_resource(), 0x400000, Vec::new()).unwrap();
    let entry = captured.resources().unwrap()[0].clone();
    let value = captured.read_rva(entry.data_rva, 1).unwrap()[0] ^ 0xff;
    captured.write_bytes(entry.data_rva as usize, &[value]).unwrap();
    let changes = crate::pe::diagnostics::resources::compare(&captured, &reference).unwrap();
    assert!(!changes.is_empty());
    assert_ne!(changes[0].before_hash, changes[0].after_hash);
}

#[test]
fn recovery_rejects_unrelated_reference_before_analysis() {
    let mapped = file_image().to_mapped().unwrap();
    let mut reference = file_image();
    reference.write_u32(reference.file_header_offset() + 4, 0x12345678).unwrap();
    let result = crate::pe::recovery::imports::Plan::from_image(mapped, &Default::default(), Default::default(), Some(reference));
    assert!(matches!(result, Err(crate::pe::recovery::imports::Error::Image(Error::ReferenceIdentity("timestamp")))));
}

#[test]
fn recovery_validation_uses_the_current_model() {
    let mapped = file_image().to_mapped().unwrap();
    let plan = crate::pe::recovery::imports::Plan::from_image(mapped, &Default::default(),
        crate::pe::recovery::imports::Options::from_strength(crate::pe::recovery::imports::ImportRecoveryStrength::Fast), None).unwrap();
    assert!(plan.validate(&plan.model).unwrap().is_empty());
    let mut edited = plan.model.clone();
    edited.add_module("missing.dll", 0x1000, 1).unwrap();
    assert!(!plan.validate(&edited).unwrap().is_empty());
    assert!(plan.validate(&plan.model).unwrap().is_empty());
    assert!(plan.build(&edited, Default::default()).is_err());
}
