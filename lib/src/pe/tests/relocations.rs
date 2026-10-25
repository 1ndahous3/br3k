use super::*;

#[test]
fn parses_base_relocations() {
    let image = Image::parse(test_pe_with_highlow_relocation()).unwrap();

    let blocks = image.base_relocations().unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].page_rva, 0x1000);
    assert_eq!(blocks[0].entries.len(), 2);
    assert_eq!(blocks[0].entries[0].rva, 0x1010);
    assert_eq!(blocks[0].entries[0].kind, BaseRelocationKind::HighLow);
    assert_eq!(blocks[0].entries[1].kind, BaseRelocationKind::Absolute);
}

#[test]
fn rebases_pe32_image() {
    let image = Image::parse(test_pe_with_highlow_relocation()).unwrap();

    let result = image.rebase(0x500000).unwrap();
    let rebased = Image::parse(result.image).unwrap();

    assert_eq!(result.old_image_base, 0x400000);
    assert_eq!(result.new_image_base, 0x500000);
    assert_eq!(result.delta, 0x100000);
    assert_eq!(result.block_count, 1);
    assert_eq!(result.entry_count, 2);
    assert_eq!(result.applied_count, 1);
    assert_eq!(result.skipped_count, 1);
    assert_eq!(rebased.image_base().unwrap(), 0x500000);
    assert_eq!(rebased.read_u32_rva(0x1010).unwrap(), 0x502234);
}

#[test]
fn rebases_pe64_image() {
    let image = Image::parse(test_pe_with_dir64_relocation()).unwrap();

    let result = image.rebase(0x190000000).unwrap();
    let rebased = Image::parse(result.image).unwrap();
    let relocated_offset = rebased.rva_to_file_offset(0x1018).unwrap();

    assert_eq!(result.old_image_base, 0x180000000);
    assert_eq!(result.new_image_base, 0x190000000);
    assert_eq!(result.delta, 0x10000000);
    assert_eq!(result.applied_count, 1);
    assert_eq!(rebased.image_base().unwrap(), 0x190000000);
    assert_eq!(rebased.read_u64(relocated_offset).unwrap(), 0x190003456);
}

#[test]
fn builds_pe32_base_relocation_table() {
    let image = Image::parse(test_pe_with_highlow_relocation()).unwrap();

    let table = image.build_relocation_table(&[0x1010]).unwrap();
    let blocks = parse_relocation_blocks(&table).unwrap();

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].page_rva, 0x1000);
    assert_eq!(blocks[0].block_size, 12);
    assert_eq!(blocks[0].entries.len(), 2);
    assert_eq!(blocks[0].entries[0].rva, 0x1010);
    assert_eq!(blocks[0].entries[0].kind, BaseRelocationKind::HighLow);
    assert_eq!(blocks[0].entries[1].kind, BaseRelocationKind::Absolute);
}

#[test]
fn builds_pe64_base_relocation_table() {
    let image = Image::parse(test_pe_with_dir64_relocation()).unwrap();

    let table = image.build_relocation_table(&[0x2010, 0x1018, 0x1010, 0x1018]).unwrap();
    let blocks = parse_relocation_blocks(&table).unwrap();

    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].page_rva, 0x1000);
    assert_eq!(blocks[0].block_size, 12);
    assert_eq!(blocks[0].entries.len(), 2);
    assert_eq!(blocks[0].entries[0].rva, 0x1010);
    assert_eq!(blocks[0].entries[1].rva, 0x1018);
    assert_eq!(blocks[0].entries[0].kind, BaseRelocationKind::Dir64);
    assert_eq!(blocks[1].page_rva, 0x2000);
    assert_eq!(blocks[1].entries[0].rva, 0x2010);
    assert_eq!(blocks[1].entries[0].kind, BaseRelocationKind::Dir64);
    assert_eq!(blocks[1].entries[1].kind, BaseRelocationKind::Absolute);
}

#[test]
fn adds_base_relocation_section() {
    let image = Image::parse(test_pe_with_dir64_relocation()).unwrap();

    let result = image.add_relocations(&[0x1018, 0x1020], ".reloc").unwrap();
    let rebuilt = Image::parse(result.image).unwrap();
    let directory = rebuilt.data_directory(PE_DIRECTORY_ENTRY_BASERELOC).unwrap();
    let sections = rebuilt.sections().unwrap();
    let blocks = rebuilt.base_relocations().unwrap();

    assert_eq!(result.entry_count, 2);
    assert_eq!(result.block_count, 1);
    assert_eq!(result.section_rva, 0x3000);
    assert_eq!(result.directory_rva, result.section_rva);
    assert_eq!(result.directory_size, 12);
    assert_eq!(directory.virtual_address, result.directory_rva);
    assert_eq!(directory.size, result.directory_size);
    assert_eq!(sections.len(), 3);
    assert_eq!(sections[2].name, ".reloc");
    assert_eq!(sections[2].virtual_address, result.section_rva);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].entries[0].kind, BaseRelocationKind::Dir64);
    assert_eq!(blocks[0].entries[0].rva, 0x1018);
    assert_eq!(blocks[0].entries[1].rva, 0x1020);
}

#[test]
fn discovers_pe32_relocation_candidates() {
    let image = Image::parse(test_pe_with_highlow_relocation()).unwrap();

    let discovery = image.relocation_candidates().unwrap();

    assert_eq!(discovery.image_base, 0x400000);
    assert_eq!(discovery.pointer_size, 4);
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.candidates[0].rva, 0x1010);
    assert_eq!(discovery.candidates[0].value, 0x402234);
    assert_eq!(discovery.candidates[0].target_rva, 0x2234);
    assert_eq!(discovery.candidates[0].section_name.as_deref(), Some(".text"));
    assert_eq!(discovery.candidates[0].target_section_name.as_deref(), Some(".reloc"));
    assert_eq!(discovery.rvas(), vec![0x1010]);
}

#[test]
fn discovers_pe64_relocation_candidates() {
    let mut data = test_pe_with_dir64_relocation();
    write_u64(&mut data, 0x200 + 0x20, 0x180002456);
    let image = Image::parse(data).unwrap();

    let discovery = image.relocation_candidates().unwrap();

    assert_eq!(discovery.image_base, 0x180000000);
    assert_eq!(discovery.pointer_size, 8);
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.candidates[0].rva, 0x1020);
    assert_eq!(discovery.candidates[0].value, 0x180002456);
    assert_eq!(discovery.candidates[0].target_rva, 0x2456);
    assert_eq!(discovery.candidates[0].section_name.as_deref(), Some(".text"));
    assert_eq!(discovery.candidates[0].target_section_name.as_deref(), Some(".reloc"));
    assert_eq!(discovery.rvas(), vec![0x1020]);
}

#[test]
fn adds_discovered_relocations() {
    let mut data = test_pe_with_dir64_relocation();
    write_u64(&mut data, 0x200 + 0x20, 0x180002456);
    let mut image = Image::parse(data).unwrap();
    image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_BASERELOC).unwrap();
    let image = Image::parse(image.into_data()).unwrap();

    let result = image.add_discovered_relocations(".reloc").unwrap();
    let rebuilt = Image::parse(result.image).unwrap();
    let blocks = rebuilt.base_relocations().unwrap();

    assert_eq!(result.entry_count, 1);
    assert_eq!(result.block_count, 1);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].entries[0].rva, 0x1020);
    assert_eq!(blocks[0].entries[0].kind, BaseRelocationKind::Dir64);
    assert_eq!(blocks[0].entries[1].kind, BaseRelocationKind::Absolute);
}

#[test]
fn build_relocation_table_rejects_empty_model() {
    let image = Image::parse(test_pe_with_dir64_relocation()).unwrap();

    assert!(matches!(
        image.build_relocation_table(&[]),
        Err(RelocationError::EmptyRelocationModel)
    ));
}

#[test]
fn build_relocation_table_rejects_out_of_bounds_rva() {
    let image = Image::parse(test_pe_with_dir64_relocation()).unwrap();

    assert!(matches!(
        image.build_relocation_table(&[0x2ffc]),
        Err(RelocationError::RelocationRvaOutOfBounds { .. })
    ));
}

#[test]
fn editor_rebases_mapped_addresses_across_revisions() {
    let file = Image::parse(test_pe_with_highlow_relocation()).unwrap();
    let original = file.to_mapped().unwrap();
    let mut editor = crate::pe::image::editor::Editor::new(original.clone());
    editor.rebase(0x500000).unwrap();
    assert_eq!(editor.image().load_base(), Some(0x500000));
    assert_eq!(editor.image().read_u32_rva(0x1010).unwrap(), 0x502234);
    editor.rebase(0x600000).unwrap();
    assert_eq!(editor.image().read_u32_rva(0x1010).unwrap(), 0x602234);
    assert_eq!(editor.revision(), 2);
    assert_eq!(original.load_base(), Some(0x400000));
    assert_eq!(original.read_u32_rva(0x1010).unwrap(), 0x402234);
    assert_eq!(editor.build().unwrap().image.to_file().unwrap().image_base().unwrap(), 0x600000);
}

fn test_pe_with_highlow_relocation() -> Vec<u8> {
    let mut data = vec![0u8; 0x600];

    write_u16(&mut data, 0, 0x5a4d);
    write_u32(&mut data, 0x3c, 0x80);
    write_u32(&mut data, 0x80, 0x4550);

    let file_header = 0x84;
    write_u16(&mut data, file_header, 0x14c);
    write_u16(&mut data, file_header + 2, 2);
    write_u16(&mut data, file_header + 16, 0xe0);

    let optional = 0x98;
    write_u16(&mut data, optional, 0x10b);
    write_u32(&mut data, optional + 16, 0x1000);
    write_u32(&mut data, optional + 28, 0x400000);
    write_u32(&mut data, optional + 32, 0x1000);
    write_u32(&mut data, optional + 36, 0x200);
    write_u32(&mut data, optional + 56, 0x3000);
    write_u32(&mut data, optional + 60, 0x200);
    write_u32(&mut data, optional + 92, 16);

    let reloc_directory = optional + 96 + PE_DIRECTORY_ENTRY_BASERELOC * 8;
    write_u32(&mut data, reloc_directory, 0x2000);
    write_u32(&mut data, reloc_directory + 4, 12);

    let sections = optional + 0xe0;
    write_section(&mut data, sections, b".text", 0x1000, 0x1000, 0x200, 0x200, 0x60000020);
    write_section(&mut data, sections + 40, b".reloc", 0x1000, 0x2000, 0x200, 0x400, 0x42000040);

    write_u32(&mut data, 0x200 + 0x10, 0x402234);
    write_u32(&mut data, 0x400, 0x1000);
    write_u32(&mut data, 0x404, 12);
    write_u16(&mut data, 0x408, (3 << 12) | 0x10);
    write_u16(&mut data, 0x40a, 0);

    data
}

fn test_pe_with_dir64_relocation() -> Vec<u8> {
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

    let reloc_directory = optional + 112 + PE_DIRECTORY_ENTRY_BASERELOC * 8;
    write_u32(&mut data, reloc_directory, 0x2000);
    write_u32(&mut data, reloc_directory + 4, 12);

    let sections = optional + 0xf0;
    write_section(&mut data, sections, b".text", 0x1000, 0x1000, 0x200, 0x200, 0x60000020);
    write_section(&mut data, sections + 40, b".reloc", 0x1000, 0x2000, 0x200, 0x400, 0x42000040);

    write_u64(&mut data, 0x200 + 0x18, 0x180003456);
    write_u32(&mut data, 0x400, 0x1000);
    write_u32(&mut data, 0x404, 12);
    write_u16(&mut data, 0x408, (10 << 12) | 0x18);
    write_u16(&mut data, 0x40a, 0);

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
