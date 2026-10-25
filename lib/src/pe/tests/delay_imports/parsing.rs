use super::*;

#[test]
fn reads_delay_import_descriptors() {
    let image = Image::parse(test_pe64_with_delay_imports()).unwrap();

    let descriptors = image.delay_imports().unwrap();
    assert_eq!(descriptors.len(), 1);

    let descriptor = &descriptors[0];
    assert_eq!(descriptor.index, 0);
    assert_eq!(descriptor.descriptor_rva, 0x2000);
    assert!(descriptor.rva_based);
    assert_eq!(descriptor.dll_name.as_deref(), Some("delay.dll"));
    assert_eq!(descriptor.time_date_stamp, 0x12345678);
    assert_eq!(descriptor.import_count(), 2);

    let named = &descriptor.imports[0];
    assert_eq!(named.name.as_deref(), Some("DelayedFunc"));
    assert_eq!(named.hint, Some(0x33));
    assert_eq!(named.name_rva, Some(0x2080));
    assert_eq!(named.import_address_table_rva, Some(0x2090));

    let ordinal = &descriptor.imports[1];
    assert_eq!(ordinal.ordinal, Some(7));
    assert_eq!(ordinal.import_address_table_rva, Some(0x2098));
}

#[test]
fn rebuilds_delay_import_directory() {
    let image = Image::parse(test_pe64_with_delay_imports()).unwrap();
    let descriptors = image.delay_imports().unwrap();

    let result = image.rebuild_delay_imports(&descriptors, ".didat").unwrap();
    let rebuilt = Image::parse(result.image).unwrap();
    let directory = rebuilt.data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT).unwrap();
    let sections = rebuilt.sections().unwrap();
    let rebuilt_descriptors = rebuilt.delay_imports().unwrap();

    assert_eq!(result.section_rva, 0x3000);
    assert_eq!(result.directory_rva, result.section_rva);
    assert_eq!(result.directory_size, 64);
    assert_eq!(result.descriptor_count, 1);
    assert_eq!(result.import_count, 2);
    assert!(result.section_size > result.directory_size);
    assert_eq!(directory.virtual_address, result.directory_rva);
    assert_eq!(directory.size, result.directory_size);
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[2].name, ".didat");

    assert_eq!(rebuilt_descriptors.len(), 1);
    let descriptor = &rebuilt_descriptors[0];
    assert!(descriptor.rva_based);
    assert_eq!(descriptor.dll_name.as_deref(), Some("delay.dll"));
    assert_eq!(descriptor.bound_import_address_table_rva, None);
    assert_eq!(descriptor.unload_information_table_rva, None);
    assert_eq!(descriptor.time_date_stamp, 0);
    assert_eq!(descriptor.import_count(), 2);
    assert_eq!(descriptor.imports[0].name.as_deref(), Some("DelayedFunc"));
    assert_eq!(descriptor.imports[0].hint, Some(0x33));
    assert_eq!(descriptor.imports[1].ordinal, Some(7));
}

#[test]
fn rebuild_delay_imports_rejects_empty_model() {
    let image = Image::parse(test_pe64_with_delay_imports()).unwrap();

    assert!(matches!(
        image.rebuild_delay_imports(&[], ".didat"),
        Err(DelayImportError::EmptyDelayImportModel)
    ));
}

fn test_pe64_with_delay_imports() -> Vec<u8> {
    let mut data = vec![0u8; 0x800];

    write_u16(&mut data, 0, 0x5a4d);
    write_u32(&mut data, 0x3c, 0x80);
    write_u32(&mut data, 0x80, 0x4550);

    let file_header = 0x84;
    write_u16(&mut data, file_header, 0x8664);
    write_u16(&mut data, file_header + 2, 2);
    write_u16(&mut data, file_header + 16, 0xf0);

    let optional = 0x98;
    write_u16(&mut data, optional, 0x20b);
    write_u32(&mut data, optional + 16, 0x1000);
    write_u64(&mut data, optional + 24, 0x180000000);
    write_u32(&mut data, optional + 32, 0x1000);
    write_u32(&mut data, optional + 36, 0x200);
    write_u32(&mut data, optional + 56, 0x3000);
    write_u32(&mut data, optional + 60, 0x200);
    write_u32(&mut data, optional + 108, 16);

    let delay_directory = optional + 112 + PE_DIRECTORY_ENTRY_DELAY_IMPORT * 8;
    write_u32(&mut data, delay_directory, 0x2000);
    write_u32(&mut data, delay_directory + 4, 0x40);

    let sections = optional + 0xf0;
    write_section(&mut data, sections, b".text", 0x1000, 0x1000, 0x200, 0x200, 0x60000020);
    write_section(&mut data, sections + 40, b".rdata", 0x1000, 0x2000, 0x400, 0x400, 0x40000040);

    write_u32(&mut data, 0x400, 1);
    write_u32(&mut data, 0x404, 0x2050);
    write_u32(&mut data, 0x408, 0);
    write_u32(&mut data, 0x40c, 0x2090);
    write_u32(&mut data, 0x410, 0x2060);
    write_u32(&mut data, 0x414, 0);
    write_u32(&mut data, 0x418, 0);
    write_u32(&mut data, 0x41c, 0x12345678);

    data[0x450..0x45a].copy_from_slice(b"delay.dll\0");
    write_u64(&mut data, 0x460, 0x2080);
    write_u64(&mut data, 0x468, IMAGE_ORDINAL_FLAG64 | 7);
    write_u64(&mut data, 0x470, 0);
    write_u16(&mut data, 0x480, 0x33);
    data[0x482..0x48e].copy_from_slice(b"DelayedFunc\0");

    data
}

fn write_section(
    data: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) {
    data[offset..offset + name.len()].copy_from_slice(name);
    write_u32(data, offset + 8, virtual_size);
    write_u32(data, offset + 12, virtual_address);
    write_u32(data, offset + 16, raw_size);
    write_u32(data, offset + 20, raw_offset);
    write_u32(data, offset + 36, characteristics);
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
