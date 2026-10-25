use super::*;

#[test]
fn mapped_to_file_image_can_stamp_live_image_base_and_size() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let options = MappedToFileImageOptions {
        image_base: Some(0x500000),
        image_size: Some(0x5000),
        entry_point: Some(0x1234),
        section_raw_layout: SectionRawLayout::Packed,
    };
    let file_image = image.mapped_to_file_image_with_options(options).unwrap();
    let optional_header_offset = 0x98;
    let section_table_offset = optional_header_offset + 0xe0;

    assert_eq!(read_u32(&file_image, optional_header_offset + 28).unwrap(), 0x500000);
    assert_eq!(read_u32(&file_image, optional_header_offset + 16).unwrap(), 0x1234);
    assert_eq!(read_u32(&file_image, optional_header_offset + 56).unwrap(), 0x5000);
    assert_eq!(read_u32(&file_image, optional_header_offset + 64).unwrap(), 0);
    assert_eq!(read_u32(&file_image, optional_header_offset + 128).unwrap(), 0);
    assert_eq!(read_u32(&file_image, optional_header_offset + 132).unwrap(), 0);
    assert_eq!(read_u32(&file_image, section_table_offset + 16).unwrap(), 0x200);
    assert_eq!(read_u32(&file_image, section_table_offset + 20).unwrap(), 0x200);
    assert_eq!(&file_image[0x200..0x203], &[1, 2, 3]);
}

#[test]
fn mapped_to_file_image_can_preserve_mapped_section_offsets() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let options = MappedToFileImageOptions {
        section_raw_layout: SectionRawLayout::MappedOffsets,
        ..Default::default()
    };
    let file_image = image.mapped_to_file_image_with_options(options).unwrap();
    let optional_header_offset = 0x98;
    let section_table_offset = optional_header_offset + 0xe0;

    assert_eq!(read_u32(&file_image, section_table_offset + 16).unwrap(), 0x200);
    assert_eq!(read_u32(&file_image, section_table_offset + 20).unwrap(), 0x1000);
    assert_eq!(&file_image[0x1000..0x1003], &[1, 2, 3]);
}

#[test]
fn overlay_range_reports_data_after_section_raw_end() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let mut file_image = image.mapped_to_file_image().unwrap();

    assert_eq!(Image::parse(file_image.clone()).unwrap().overlay_range().unwrap(), None);

    file_image.extend_from_slice(&[4, 5, 6]);
    let image = Image::parse(file_image).unwrap();

    assert_eq!(
        image.overlay_range().unwrap(),
        Some(OverlayRange {
            offset: 0x400,
            size: 3,
        }),
    );
    assert_eq!(image.overlay().unwrap(), Some(&[4, 5, 6][..]));
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
