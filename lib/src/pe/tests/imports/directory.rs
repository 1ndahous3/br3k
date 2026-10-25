use super::*;

const PE_OFFSET: usize = 0x80;
const FILE_HEADER_OFFSET: usize = PE_OFFSET + 4;
const OPTIONAL_HEADER_OFFSET: usize = FILE_HEADER_OFFSET + 20;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_HEADER_OFFSET + 0xe0;
const IMPORT_DIRECTORY_RVA: u32 = 0x1100;
const SECTION_RVA: u32 = 0x1000;
const SECTION_OFFSET: usize = SECTION_RVA as usize;

#[test]
fn reads_import_descriptors_from_file_layout() {
    let data = pe32_with_imports();
    let image = Image::parse(data).unwrap();
    let descriptors = image.imports().unwrap();

    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].dll_name.as_deref(), Some("kernel32.dll"));
    assert_eq!(descriptors[0].original_first_thunk_rva, Some(0x1200));
    assert_eq!(descriptors[0].first_thunk_rva, Some(0x1300));
    assert_eq!(descriptors[0].import_count(), 2);
    assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
    assert_eq!(descriptors[0].imports[0].hint, Some(7));
    assert_eq!(descriptors[0].imports[0].import_address_table_rva, Some(0x1300));
    assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0x1250));
    assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
    assert_eq!(descriptors[0].imports[1].raw_lookup_value, IMAGE_ORDINAL_FLAG32 | 0x123);
}

#[test]
fn reads_import_address_values_from_mapped_layout() {
    let mut data = pe32_with_imports();
    put_u32(&mut data, 0x1300, 0x7700_1000);
    put_u32(&mut data, 0x1304, 0x7700_2000);

    let image = Image::parse(data).unwrap();
    let descriptors = image.mapped_imports().unwrap();

    assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
    assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0x7700_1000));
    assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
    assert_eq!(descriptors[0].imports[1].raw_address_value, Some(0x7700_2000));
}

#[test]
fn missing_lookup_table_preserves_bound_and_mapped_addresses() {
    for timestamp in [0, 0x12345678, u32::MAX] {
        let mut data = pe32_with_imports();
        put_u32(&mut data, 0x1100, 0);
        put_u32(&mut data, 0x1104, timestamp);
        // One VA looks like an ordinal; the other happens to equal a valid name RVA.
        put_u32(&mut data, 0x1300, 0xf7001000);
        put_u32(&mut data, 0x1304, 0x1250);
        let image = Image::parse(data).unwrap();
        let mut checks = vec![(image.mapped_imports().unwrap(), ImportLookupKind::ResolvedAddresses)];
        if timestamp != 0 {
            let file = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
            checks.push((file.imports().unwrap(), ImportLookupKind::BoundAddresses));
        }
        for (descriptors, kind) in checks {
            assert_eq!(descriptors[0].lookup_kind, kind);
            assert_eq!(descriptors[0].imports[0].raw_lookup_value, 0xf7001000);
            for function in &descriptors[0].imports {
                assert_eq!(function.name_rva, None);
                assert_eq!(function.hint, None);
                assert_eq!(function.name, None);
                assert_eq!(function.ordinal, None);
                assert_eq!(function.raw_address_value, Some(function.raw_lookup_value));
            }
        }
    }
}

#[test]
fn unbound_file_without_original_first_thunk_still_reads_names_and_ordinals() {
    let mut data = pe32_with_imports();
    put_u32(&mut data, 0x1100, 0);
    let mut image = Image::parse(data).unwrap();
    let descriptors = image.imports().unwrap();
    assert_eq!(descriptors[0].lookup_kind, ImportLookupKind::FirstThunk);
    assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
    assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
    image.write_u32(0x1300, 0x7fff1000).unwrap();
    assert!(image.imports().is_err());
}

#[test]
fn bound_image_uses_original_lookup_table_when_present() {
    for timestamp in [0x12345678, u32::MAX] {
        let mut data = pe32_with_imports();
        put_u32(&mut data, 0x1104, timestamp);
        put_u32(&mut data, 0x1300, 0xf7001000);
        put_u32(&mut data, 0x1304, 0xf7002000);
        let image = Image::parse(data).unwrap();
        for descriptors in [image.imports().unwrap(), image.mapped_imports().unwrap()] {
            assert_eq!(descriptors[0].lookup_kind, ImportLookupKind::OriginalFirstThunk);
            assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("LoadLibraryA"));
            assert_eq!(descriptors[0].imports[1].ordinal, Some(0x123));
            assert_eq!(descriptors[0].imports[0].raw_address_value, Some(0xf7001000));
        }
    }
}

fn pe32_with_imports() -> Vec<u8> {
    let mut data = vec![0u8; 0x3000];
    put_u16(&mut data, 0, 0x5a4d);
    put_u32(&mut data, 0x3c, PE_OFFSET as u32);
    put_u32(&mut data, PE_OFFSET, 0x0000_4550);
    put_u16(&mut data, FILE_HEADER_OFFSET, 0x014c);
    put_u16(&mut data, FILE_HEADER_OFFSET + 2, 1);
    put_u16(&mut data, FILE_HEADER_OFFSET + 16, 0xe0);
    put_u16(&mut data, OPTIONAL_HEADER_OFFSET, 0x10b);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 28, 0x400000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 32, 0x1000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 36, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 56, 0x3000);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 60, 0x200);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 92, 16);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 96 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, IMPORT_DIRECTORY_RVA);
    put_u32(&mut data, OPTIONAL_HEADER_OFFSET + 100 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, 0x40);
    put_section_header(&mut data, SECTION_TABLE_OFFSET, ".idata", 0x2000, SECTION_RVA, 0x2000, SECTION_OFFSET as u32, 0x4000_0040);

    put_u32(&mut data, 0x1100, 0x1200);
    put_u32(&mut data, 0x1104, 0);
    put_u32(&mut data, 0x1108, 0);
    put_u32(&mut data, 0x110c, 0x1240);
    put_u32(&mut data, 0x1110, 0x1300);
    put_u32(&mut data, 0x1200, 0x1250);
    put_u32(&mut data, 0x1204, (IMAGE_ORDINAL_FLAG32 | 0x123) as u32);
    put_u32(&mut data, 0x1208, 0);
    put_u32(&mut data, 0x1300, 0x1250);
    put_u32(&mut data, 0x1304, (IMAGE_ORDINAL_FLAG32 | 0x123) as u32);
    put_u32(&mut data, 0x1308, 0);
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

fn write_cstr(data: &mut [u8], offset: usize, value: &str) {
    data[offset..offset + value.len()].copy_from_slice(value.as_bytes());
    data[offset + value.len()] = 0;
}

fn put_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
