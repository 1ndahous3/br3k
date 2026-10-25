use super::*;

pub(super) fn mapped_pe32_image() -> Vec<u8> {
    let mut data = vec![0u8; 0x3000];
    let nt_header_offset = 0x80usize;
    let file_header_offset = nt_header_offset + 4;
    let optional_header_offset = file_header_offset + IMAGE_FILE_HEADER_SIZE;
    let section_table_offset = optional_header_offset + 0xe0;

    data[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
    data[0x3c..0x40].copy_from_slice(&(nt_header_offset as u32).to_le_bytes());
    data[nt_header_offset..nt_header_offset + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
    data[file_header_offset..file_header_offset + 2].copy_from_slice(&0x14cu16.to_le_bytes());
    data[file_header_offset + 2..file_header_offset + 4].copy_from_slice(&1u16.to_le_bytes());
    data[file_header_offset + 16..file_header_offset + 18].copy_from_slice(&0xe0u16.to_le_bytes());
    data[optional_header_offset..optional_header_offset + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
    data[optional_header_offset + 28..optional_header_offset + 32].copy_from_slice(&0x400000u32.to_le_bytes());
    data[optional_header_offset + 16..optional_header_offset + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    data[optional_header_offset + 32..optional_header_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    data[optional_header_offset + 36..optional_header_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
    data[optional_header_offset + 56..optional_header_offset + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    data[optional_header_offset + 60..optional_header_offset + 64].copy_from_slice(&0x200u32.to_le_bytes());
    data[optional_header_offset + 64..optional_header_offset + 68].copy_from_slice(&0x12345678u32.to_le_bytes());
    data[optional_header_offset + 92..optional_header_offset + 96].copy_from_slice(&16u32.to_le_bytes());
    data[optional_header_offset + 128..optional_header_offset + 132].copy_from_slice(&0x1234u32.to_le_bytes());
    data[optional_header_offset + 132..optional_header_offset + 136].copy_from_slice(&0x5678u32.to_le_bytes());
    data[optional_header_offset + 184..optional_header_offset + 188].copy_from_slice(&0x2345u32.to_le_bytes());
    data[optional_header_offset + 188..optional_header_offset + 192].copy_from_slice(&0x6789u32.to_le_bytes());
    data[optional_header_offset + 200..optional_header_offset + 204].copy_from_slice(&0x3456u32.to_le_bytes());
    data[optional_header_offset + 204..optional_header_offset + 208].copy_from_slice(&0x789au32.to_le_bytes());

    data[section_table_offset..section_table_offset + 5].copy_from_slice(b".text");
    data[section_table_offset + 8..section_table_offset + 12].copy_from_slice(&3u32.to_le_bytes());
    data[section_table_offset + 12..section_table_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[section_table_offset + 16..section_table_offset + 20].copy_from_slice(&0u32.to_le_bytes());
    data[section_table_offset + 20..section_table_offset + 24].copy_from_slice(&0u32.to_le_bytes());
    data[0x1000..0x1003].copy_from_slice(&[1, 2, 3]);

    data
}

pub(super) fn trusted_pe32_image() -> Vec<u8> {
    let mut data = mapped_pe32_image();
    let optional_header_offset = 0x98usize;
    let section_table_offset = optional_header_offset + 0xe0;

    data[optional_header_offset + 16..optional_header_offset + 20].copy_from_slice(&0x2222u32.to_le_bytes());
    data[optional_header_offset + 28..optional_header_offset + 32].copy_from_slice(&0x700000u32.to_le_bytes());
    data[optional_header_offset + 56..optional_header_offset + 60].copy_from_slice(&0x9000u32.to_le_bytes());
    data[optional_header_offset + 64..optional_header_offset + 68].copy_from_slice(&0xfeedfaceu32.to_le_bytes());
    data[section_table_offset..section_table_offset + 8].copy_from_slice(b".code\0\0\0");
    data[section_table_offset + 16..section_table_offset + 20].copy_from_slice(&0x400u32.to_le_bytes());
    data[section_table_offset + 20..section_table_offset + 24].copy_from_slice(&0x800u32.to_le_bytes());
    data[section_table_offset + 36..section_table_offset + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

    data
}

pub(super) fn trusted_pe32_image_with_resource() -> Vec<u8> {
    let mut data = trusted_pe32_image();
    let optional_header_offset = 0x98usize;
    let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
    let resource_rva = 0x1000u32;
    let resource_size = 44u32;
    let resource_raw_offset = 0x800usize;

    data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
    data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
    write_test_resource_directory(&mut data, resource_raw_offset, resource_rva);

    data
}

pub(super) fn mapped_pe32_image_with_resource() -> Vec<u8> {
    let mut data = mapped_pe32_image();
    let optional_header_offset = 0x98usize;
    let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
    let resource_rva = 0x1000u32;
    let resource_size = 44u32;

    data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
    data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
    write_test_resource_directory(&mut data, resource_rva as usize, resource_rva);

    data
}

pub(super) fn trusted_pe32_image_with_nested_resource() -> Vec<u8> {
    let mut data = trusted_pe32_image();
    let optional_header_offset = 0x98usize;
    let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
    let resource_rva = 0x1000u32;
    let resource_size = 92u32;
    let resource_raw_offset = 0x800usize;

    data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
    data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
    write_test_nested_resource_directory(&mut data, resource_raw_offset, resource_rva);

    data
}

pub(super) fn trusted_pe32_image_with_resource_blob(resource: &[u8]) -> Vec<u8> {
    let mut data = trusted_pe32_image();
    let optional_header_offset = 0x98usize;
    let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
    let resource_rva = 0x1000u32;
    let resource_raw_offset = 0x800usize;
    let mut resource = resource.to_vec();

    rebase_resource_directory_data_rvas(&mut resource, 0, resource_rva).unwrap();
    data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
    data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&(resource.len() as u32).to_le_bytes());
    data[resource_raw_offset..resource_raw_offset + resource.len()].copy_from_slice(&resource);

    data
}

pub(super) fn mapped_pe32_image_with_resource_blob(resource: &[u8]) -> Vec<u8> {
    let mut data = mapped_pe32_image();
    let optional_header_offset = 0x98usize;
    let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
    let resource_rva = 0x1000u32;
    let mut resource = resource.to_vec();

    rebase_resource_directory_data_rvas(&mut resource, 0, resource_rva).unwrap();
    data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
    data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&(resource.len() as u32).to_le_bytes());
    data[resource_rva as usize..resource_rva as usize + resource.len()].copy_from_slice(&resource);

    data
}

pub(super) fn write_test_resource_directory(data: &mut [u8], offset: usize, resource_rva: u32) {
    let resource = &mut data[offset..offset + 44];
    resource[14..16].copy_from_slice(&1u16.to_le_bytes());
    resource[16..20].copy_from_slice(&1u32.to_le_bytes());
    resource[20..24].copy_from_slice(&24u32.to_le_bytes());
    resource[24..28].copy_from_slice(&(resource_rva + 40).to_le_bytes());
    resource[28..32].copy_from_slice(&4u32.to_le_bytes());
    resource[40..44].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
}

pub(super) fn write_test_nested_resource_directory(data: &mut [u8], offset: usize, resource_rva: u32) {
    let resource = &mut data[offset..offset + 92];
    resource[14..16].copy_from_slice(&1u16.to_le_bytes());
    resource[16..20].copy_from_slice(&16u32.to_le_bytes());
    resource[20..24].copy_from_slice(&(IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY | 24).to_le_bytes());
    resource[38..40].copy_from_slice(&1u16.to_le_bytes());
    resource[40..44].copy_from_slice(&1u32.to_le_bytes());
    resource[44..48].copy_from_slice(&(IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY | 48).to_le_bytes());
    resource[62..64].copy_from_slice(&1u16.to_le_bytes());
    resource[64..68].copy_from_slice(&1033u32.to_le_bytes());
    resource[68..72].copy_from_slice(&72u32.to_le_bytes());
    resource[72..76].copy_from_slice(&(resource_rva + 88).to_le_bytes());
    resource[76..80].copy_from_slice(&4u32.to_le_bytes());
    resource[80..84].copy_from_slice(&1200u32.to_le_bytes());
    resource[88..92].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
}

pub(super) fn test_resource_leaf(path: &[u32], payload: &[u8]) -> ResourceDataLeaf {
    ResourceDataLeaf {
        path: path
            .iter()
            .map(|id| ResourcePathEntry {
                name: None,
                id: Some(*id),
            })
            .collect(),
        data: payload.to_vec(),
        code_page: 1200,
        reserved: 0,
    }
}

pub(super) fn resource_path_ids(entry: &ResourceDataEntry) -> Vec<u32> {
    entry.path
        .iter()
        .map(|entry| entry.id.unwrap())
        .collect()
}

pub(super) fn file_image() -> Image {
    Image::parse(Image::parse(mapped_pe32_image()).unwrap().mapped_to_file_image().unwrap()).unwrap()
}
