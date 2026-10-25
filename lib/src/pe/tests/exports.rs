use super::*;

#[test]
fn parse_preserves_multiple_export_names_for_one_function() {
    let table = ExportTable::parse(&export_alias_pe(), None, None).unwrap();
    let symbol = table.resolve_va(0x400300).unwrap();

    assert_eq!(table.module_name, "alias.dll");
    assert_eq!(table.symbols.len(), 1);
    assert_eq!(symbol.name.as_deref(), Some("AliasA"));
    assert_eq!(symbol.names, vec!["AliasA".to_string(), "AliasB".to_string()]);
    assert_eq!(table.resolve_name("AliasB").unwrap().ordinal, 1);
    assert_eq!(table.resolve_all_va(0x400300).len(), 1);
}

#[test]
fn resolve_va_prefers_named_symbol_for_duplicate_address() {
    let table = ExportTable {
        module_name: "dup.dll".to_string(),
        image_base: 0x1000,
        image_size: 0x100,
        time_date_stamp: None,
        symbols: vec![
            ExportSymbol {
                module_name: "dup.dll".to_string(),
                name: None,
                names: Vec::new(),
                ordinal: 1,
                rva: 0x20,
                address: 0x1020,
                forwarder: None,
            },
            ExportSymbol {
                module_name: "dup.dll".to_string(),
                name: Some("NamedAlias".to_string()),
                names: vec!["NamedAlias".to_string()],
                ordinal: 2,
                rva: 0x20,
                address: 0x1020,
                forwarder: None,
            },
        ],
    };

    let symbol = table.resolve_va(0x1020).unwrap();
    assert_eq!(symbol.name.as_deref(), Some("NamedAlias"));
    assert_eq!(table.resolve_nearest_va(0x1024).unwrap().name.as_deref(), Some("NamedAlias"));
    assert_eq!(table.resolve_all_va(0x1020).len(), 2);
}

fn export_alias_pe() -> Vec<u8> {
    let mut data = vec![0u8; 0x600];
    let nt_header_offset = 0x80usize;
    let file_header_offset = nt_header_offset + 4;
    let optional_header_offset = file_header_offset + 20;
    let section_table_offset = optional_header_offset + 0xe0;
    let data_directory_offset = optional_header_offset + 96;

    write_u16(&mut data, 0, 0x5a4d);
    write_u32(&mut data, 0x3c, nt_header_offset as u32);
    write_u32(&mut data, nt_header_offset, 0x0000_4550);
    write_u16(&mut data, file_header_offset, 0x014c);
    write_u16(&mut data, file_header_offset + 2, 1);
    write_u16(&mut data, file_header_offset + 16, 0xe0);
    write_u16(&mut data, optional_header_offset, 0x10b);
    write_u32(&mut data, optional_header_offset + 28, 0x400000);
    write_u32(&mut data, optional_header_offset + 32, 0x200);
    write_u32(&mut data, optional_header_offset + 36, 0x200);
    write_u32(&mut data, optional_header_offset + 56, 0x1000);
    write_u32(&mut data, optional_header_offset + 60, 0x200);
    write_u32(&mut data, optional_header_offset + 92, 16);
    write_u32(&mut data, data_directory_offset, 0x200);
    write_u32(&mut data, data_directory_offset + 4, 0x100);

    data[section_table_offset..section_table_offset + 6].copy_from_slice(b".edata");
    write_u32(&mut data, section_table_offset + 8, 0x400);
    write_u32(&mut data, section_table_offset + 12, 0x200);
    write_u32(&mut data, section_table_offset + 16, 0x400);
    write_u32(&mut data, section_table_offset + 20, 0x200);

    write_u32(&mut data, 0x200 + 12, 0x250);
    write_u32(&mut data, 0x200 + 16, 1);
    write_u32(&mut data, 0x200 + 20, 1);
    write_u32(&mut data, 0x200 + 24, 2);
    write_u32(&mut data, 0x200 + 28, 0x260);
    write_u32(&mut data, 0x200 + 32, 0x270);
    write_u32(&mut data, 0x200 + 36, 0x280);

    write_u32(&mut data, 0x260, 0x300);
    write_u32(&mut data, 0x270, 0x290);
    write_u32(&mut data, 0x274, 0x2a0);
    write_u16(&mut data, 0x280, 0);
    write_u16(&mut data, 0x282, 0);
    write_cstr(&mut data, 0x250, b"alias.dll");
    write_cstr(&mut data, 0x290, b"AliasA");
    write_cstr(&mut data, 0x2a0, b"AliasB");

    data
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_cstr(data: &mut [u8], offset: usize, value: &[u8]) {
    data[offset..offset + value.len()].copy_from_slice(value);
    data[offset + value.len()] = 0;
}
