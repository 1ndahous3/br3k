use super::*;

#[test]
fn reads_pe64_tls_callbacks() {
    let image = Image::parse(test_pe64_with_tls()).unwrap();
    let tls = image.tls_directory().unwrap().unwrap();

    assert_eq!(tls.rva, 0x2000);
    assert_eq!(tls.address_of_callbacks, 0x180002040);
    assert_eq!(tls.callbacks.len(), 1);
    assert_eq!(tls.callbacks[0].index, 0);
    assert_eq!(tls.callbacks[0].address, 0x180001234);
    assert_eq!(tls.callbacks[0].rva, Some(0x1234));
}

#[test]
fn clears_pe64_tls_callbacks() {
    let image = Image::parse(test_pe64_with_tls()).unwrap();

    let result = image.clear_tls_callbacks().unwrap();
    let fixed = Image::parse(result.image).unwrap();
    let fixed_tls = fixed.tls_directory().unwrap().unwrap();

    assert!(result.directory_present);
    assert_eq!(result.callback_count, 1);
    assert!(result.cleared_callbacks);
    assert_eq!(fixed_tls.address_of_callbacks, 0);
    assert!(fixed_tls.callbacks.is_empty());
}

#[test]
fn clears_pe64_tls_directory() {
    let image = Image::parse(test_pe64_with_tls()).unwrap();

    let result = image.clear_tls_directory().unwrap();
    let fixed = Image::parse(result.image).unwrap();

    assert!(result.directory_present);
    assert_eq!(result.callback_count, 1);
    assert!(result.cleared_directory);
    assert!(fixed.tls_directory().unwrap().is_none());
}

fn test_pe64_with_tls() -> Vec<u8> {
    let mut data = vec![0u8; 0x600];

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

    let tls_directory = optional + 112 + PE_DIRECTORY_ENTRY_TLS * 8;
    write_u32(&mut data, tls_directory, 0x2000);
    write_u32(&mut data, tls_directory + 4, 40);

    let sections = optional + 0xf0;
    write_section(&mut data, sections, b".text", 0x1000, 0x1000, 0x200, 0x200, 0x60000020);
    write_section(&mut data, sections + 40, b".rdata", 0x1000, 0x2000, 0x200, 0x400, 0x40000040);

    write_u64(&mut data, 0x400 + 24, 0x180002040);
    write_u64(&mut data, 0x400 + 0x40, 0x180001234);
    write_u64(&mut data, 0x400 + 0x48, 0);

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
