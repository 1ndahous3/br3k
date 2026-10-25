use super::*;

#[test]
fn copy_resource_directory_from_file_appends_resource_section() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let file_image = image.mapped_to_file_image().unwrap();
    let image = Image::parse(file_image).unwrap();
    let fixed = image
        .copy_resource_directory_from_file(&trusted_pe32_image_with_resource(), ".rsrc")
        .unwrap();
    let fixed_image = Image::parse(fixed).unwrap();
    let directory = fixed_image.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE).unwrap();
    let sections = fixed_image.sections().unwrap();

    assert_eq!(sections.len(), 2);
    assert_eq!(sections[1].name, ".rsrc");
    assert_eq!(sections[1].characteristics, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
    assert_eq!(directory.virtual_address, sections[1].virtual_address);
    assert_eq!(directory.size, 44);

    let resource_data = fixed_image.read_bytes_rva(directory.virtual_address, directory.size as usize).unwrap();
    assert_eq!(read_u32(&resource_data, 24).unwrap(), directory.virtual_address + 40);
    assert_eq!(&resource_data[40..44], &[0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn copy_resource_directory_from_mapped_image_appends_resource_section() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let file_image = image.mapped_to_file_image().unwrap();
    let image = Image::parse(file_image).unwrap();
    let fixed = image
        .copy_resource_directory_from_mapped_image(&mapped_pe32_image_with_resource(), ".rsrc")
        .unwrap();
    let fixed_image = Image::parse(fixed).unwrap();
    let directory = fixed_image.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE).unwrap();
    let sections = fixed_image.sections().unwrap();

    assert_eq!(sections.len(), 2);
    assert_eq!(sections[1].name, ".rsrc");
    assert_eq!(directory.virtual_address, sections[1].virtual_address);

    let resource_data = fixed_image.read_bytes_rva(directory.virtual_address, directory.size as usize).unwrap();
    assert_eq!(read_u32(&resource_data, 24).unwrap(), directory.virtual_address + 40);
    assert_eq!(&resource_data[40..44], &[0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn resource_directory_info_counts_file_resource_tree() {
    let image = Image::parse(trusted_pe32_image_with_resource()).unwrap();
    let info = image.resource_directory_info().unwrap();

    assert_eq!(
        info,
        ResourceDirectoryInfo {
            virtual_address: 0x1000,
            size: 44,
            directory_count: 1,
            named_entry_count: 0,
            id_entry_count: 1,
            data_entry_count: 1,
            data_size: 4,
            max_depth: 0,
        },
    );
}

#[test]
fn mapped_resource_directory_info_counts_mapped_resource_tree() {
    let image = Image::parse(mapped_pe32_image_with_resource()).unwrap();
    let info = image.mapped_resource_directory_info().unwrap();

    assert_eq!(
        info,
        ResourceDirectoryInfo {
            virtual_address: 0x1000,
            size: 44,
            directory_count: 1,
            named_entry_count: 0,
            id_entry_count: 1,
            data_entry_count: 1,
            data_size: 4,
            max_depth: 0,
        },
    );
}

#[test]
fn resource_data_entries_report_leaf_paths() {
    let image = Image::parse(trusted_pe32_image_with_nested_resource()).unwrap();
    let entries = image.resource_data_entries().unwrap();

    assert_eq!(
        entries,
        vec![ResourceDataEntry {
            path: vec![
                ResourcePathEntry { name: None, id: Some(16) },
                ResourcePathEntry { name: None, id: Some(1) },
                ResourcePathEntry { name: None, id: Some(1033) },
            ],
            data_rva: 0x1058,
            size: 4,
            code_page: 1200,
            reserved: 0,
        }],
    );
}

#[test]
fn copy_merged_resource_directory_merges_file_and_mapped_leaves() {
    let target = Image::parse(mapped_pe32_image()).unwrap();
    let target = Image::parse(target.mapped_to_file_image().unwrap()).unwrap();
    let file_resource = build_resource_directory_data(&[
        test_resource_leaf(&[16, 1, 1033], b"file"),
        test_resource_leaf(&[24, 1, 1033], b"file-only"),
    ])
    .unwrap();
    let mapped_resource = build_resource_directory_data(&[
        test_resource_leaf(&[14, 2, 1033], b"mapped-only"),
        test_resource_leaf(&[16, 1, 1033], b"mapped"),
    ])
    .unwrap();
    let file_source = trusted_pe32_image_with_resource_blob(&file_resource);
    let mapped_source = mapped_pe32_image_with_resource_blob(&mapped_resource);
    let fixed = target
        .copy_merged_resource_directory_from_file_and_mapped_image(
            &file_source,
            &mapped_source,
            ".rsrc",
            ResourceMergePreference::Larger,
        )
        .unwrap();
    let fixed_image = Image::parse(fixed).unwrap();
    let entries = fixed_image.resource_data_entries().unwrap();
    let mut payloads = BTreeMap::new();

    for entry in entries {
        payloads.insert(
            resource_path_ids(&entry),
            fixed_image.read_bytes_rva(entry.data_rva, entry.size as usize).unwrap(),
        );
    }

    assert_eq!(payloads.get(&vec![14, 2, 1033]).map(Vec::as_slice), Some(b"mapped-only".as_slice()));
    assert_eq!(payloads.get(&vec![16, 1, 1033]).map(Vec::as_slice), Some(b"mapped".as_slice()));
    assert_eq!(payloads.get(&vec![24, 1, 1033]).map(Vec::as_slice), Some(b"file-only".as_slice()));
}

#[test]
fn copy_resource_directory_from_file_rejects_empty_source_directory() {
    let image = Image::parse(mapped_pe32_image()).unwrap();
    let file_image = image.mapped_to_file_image().unwrap();
    let image = Image::parse(file_image).unwrap();

    assert!(matches!(
        image.copy_resource_directory_from_file(&trusted_pe32_image(), ".rsrc"),
        Err(Error::DataDirectoryEmpty {
            index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
        })
    ));
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
