use super::*;

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
