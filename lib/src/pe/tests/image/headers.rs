use super::*;

#[test]
fn sanitize_headers_can_clear_selected_directories() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let options = SanitizeHeadersOptions {
        clear_checksum: true,
        clear_security_directory: true,
        clear_bound_import_directory: true,
        clear_delay_import_directory: false,
        raw_sections_from_virtual: false,
    };
    let sanitized = image.sanitize_headers_with_options(options).unwrap();
    let optional_header_offset = 0x98;

    assert_eq!(read_u32(&sanitized, optional_header_offset + 64).unwrap(), 0);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 128).unwrap(), 0);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 132).unwrap(), 0);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 184).unwrap(), 0);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 188).unwrap(), 0);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 200).unwrap(), 0x3456);
    assert_eq!(read_u32(&sanitized, optional_header_offset + 204).unwrap(), 0x789a);
}

#[test]
fn sanitize_headers_can_make_section_raw_headers_virtual() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let options = SanitizeHeadersOptions {
        raw_sections_from_virtual: true,
        ..Default::default()
    };
    let sanitized = image.sanitize_headers_with_options(options).unwrap();
    let section_table_offset = 0x98 + 0xe0;

    assert_eq!(read_u32(&sanitized, section_table_offset + 16).unwrap(), 3);
    assert_eq!(read_u32(&sanitized, section_table_offset + 20).unwrap(), 0x1000);
}

#[test]
fn copy_headers_from_trusted_preserves_live_dump_fields_by_default() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let file_image = image
        .mapped_to_file_image_with_options(MappedToFileImageOptions {
            image_base: Some(0x500000),
            image_size: Some(0x5000),
            entry_point: Some(0x1234),
            section_raw_layout: SectionRawLayout::Packed,
        })
        .unwrap();
    let image = Image::parse(file_image).unwrap();
    let fixed = image
        .copy_headers_from_trusted(&trusted_pe32_image(), TrustedHeadersOptions::default())
        .unwrap();
    let optional_header_offset = 0x98usize;
    let section_table_offset = optional_header_offset + 0xe0;

    assert_eq!(read_u32(&fixed, optional_header_offset + 16).unwrap(), 0x1234);
    assert_eq!(read_u32(&fixed, optional_header_offset + 28).unwrap(), 0x500000);
    assert_eq!(read_u32(&fixed, optional_header_offset + 56).unwrap(), 0x5000);
    assert_eq!(read_u32(&fixed, optional_header_offset + 64).unwrap(), 0xfeedface);
    assert_eq!(&fixed[section_table_offset..section_table_offset + 5], b".code");
    assert_eq!(read_u32(&fixed, section_table_offset + 16).unwrap(), 0x200);
    assert_eq!(read_u32(&fixed, section_table_offset + 20).unwrap(), 0x200);
    assert_eq!(read_u32(&fixed, section_table_offset + 36).unwrap(), 0x60000020);
}

#[test]
fn copy_headers_from_trusted_can_normalize_raw_sections_to_virtual_layout() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let file_image = image.mapped_to_file_image().unwrap();
    let image = Image::parse(file_image).unwrap();
    let fixed = image
        .copy_headers_from_trusted(
            &trusted_pe32_image(),
            TrustedHeadersOptions {
                keep_section_raw_layout: false,
                raw_sections_from_virtual: true,
                ..Default::default()
            },
        )
        .unwrap();
    let section_table_offset = 0x98usize + 0xe0;

    assert_eq!(read_u32(&fixed, section_table_offset + 16).unwrap(), 3);
    assert_eq!(read_u32(&fixed, section_table_offset + 20).unwrap(), 0x1000);
}

#[test]
fn copy_headers_from_trusted_rejects_different_machine() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let mut trusted = trusted_pe32_image();
    trusted[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());

    assert!(matches!(
        image.copy_headers_from_trusted(&trusted, TrustedHeadersOptions::default()),
        Err(Error::TrustedHeaderMismatch {
            field: "machine",
            current: 0x14c,
            trusted: 0xaa64,
        })
    ));
}
