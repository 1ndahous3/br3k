use super::*;

#[test]
fn export_map_resolves_api_set_forwarder_to_host_module() {
    let api_set_map = ApiSetMap::parse(&test_api_set_namespace()).unwrap();
    let map = ExportMap::with_api_set_map(
        vec![
            ExportTable {
                module_name: "kernel32.dll".to_string(),
                image_base: 0x1000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "kernel32.dll".to_string(),
                    name: Some("PublicHeapAlloc".to_string()),
                    names: vec!["PublicHeapAlloc".to_string()],
                    ordinal: 1,
                    rva: 0x100,
                    address: 0x1100,
                    forwarder: Some("api-ms-win-core-heap-l1-1-0.HostHeapAlloc".to_string()),
                }],
            },
            ExportTable {
                module_name: "kernelbase.dll".to_string(),
                image_base: 0x5000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "kernelbase.dll".to_string(),
                    name: Some("HostHeapAlloc".to_string()),
                    names: vec!["HostHeapAlloc".to_string()],
                    ordinal: 7,
                    rva: 0x300,
                    address: 0x5300,
                    forwarder: None,
                }],
            },
        ],
        api_set_map,
    );

    let host_symbol = map
        .resolve_module_name("api-ms-win-core-heap-l1-1-0.dll", "HostHeapAlloc")
        .unwrap();
    let public_symbol = map.resolve_public_va(0x5300).unwrap();

    assert_eq!(host_symbol.module_name, "kernelbase.dll");
    assert_eq!(public_symbol.module_name, "kernel32.dll");
    assert_eq!(public_symbol.name.as_deref(), Some("PublicHeapAlloc"));
}

#[test]
fn export_map_resolves_recursive_forwarders() {
    let map = ExportMap::new(vec![
        ExportTable {
            module_name: "a.dll".to_string(),
            image_base: 0x1000,
            image_size: 0x1000,
            time_date_stamp: None,
            symbols: vec![ExportSymbol {
                module_name: "a.dll".to_string(),
                name: Some("A".to_string()),
                names: vec!["A".to_string()],
                ordinal: 1,
                rva: 0x100,
                address: 0x1100,
                forwarder: Some("b.B".to_string()),
            }],
        },
        ExportTable {
            module_name: "b.dll".to_string(),
            image_base: 0x2000,
            image_size: 0x1000,
            time_date_stamp: None,
            symbols: vec![ExportSymbol {
                module_name: "b.dll".to_string(),
                name: Some("B".to_string()),
                names: vec!["B".to_string()],
                ordinal: 1,
                rva: 0x200,
                address: 0x2200,
                forwarder: Some("c.C".to_string()),
            }],
        },
        ExportTable {
            module_name: "c.dll".to_string(),
            image_base: 0x3000,
            image_size: 0x1000,
            time_date_stamp: None,
            symbols: vec![ExportSymbol {
                module_name: "c.dll".to_string(),
                name: Some("C".to_string()),
                names: vec!["C".to_string()],
                ordinal: 1,
                rva: 0x300,
                address: 0x3300,
                forwarder: None,
            }],
        },
    ]);

    let public_symbol = map.resolve_public_va(0x3300).unwrap();

    assert_eq!(public_symbol.module_name, "a.dll");
    assert_eq!(public_symbol.name.as_deref(), Some("A"));
}

#[test]
fn export_map_keeps_table_source_metadata() {
    let map = ExportMap::with_records(
        vec![ExportTableRecord {
            source: ExportTableSource::Disk,
            table: ExportTable {
                module_name: "kernel32.dll".to_string(),
                image_base: 0x1000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "kernel32.dll".to_string(),
                    name: Some("CreateFileW".to_string()),
                    names: vec!["CreateFileW".to_string()],
                    ordinal: 1,
                    rva: 0x200,
                    address: 0x1200,
                    forwarder: None,
                }],
            },
        }],
        ApiSetMap::default(),
    );

    let resolved = map.resolve_va_with_source(0x1200).unwrap();

    assert_eq!(resolved.symbol.name.as_deref(), Some("CreateFileW"));
    assert_eq!(resolved.source, ExportTableSource::Disk);
}

fn test_api_set_namespace() -> Vec<u8> {
    let mut data = vec![0u8; 0x120];
    let contract = wide("api-ms-win-core-heap-l1-1-0");
    let host = wide("kernelbase.dll");

    write_u32(&mut data, 0, 6);
    write_u32(&mut data, 4, 0x120);
    write_u32(&mut data, 12, 1);
    write_u32(&mut data, 16, 0x20);

    write_u32(&mut data, 0x20 + 4, 0x60);
    write_u32(&mut data, 0x20 + 8, contract.len() as u32);
    write_u32(&mut data, 0x20 + 16, 0x40);
    write_u32(&mut data, 0x20 + 20, 1);

    write_u32(&mut data, 0x40 + 12, 0xa0);
    write_u32(&mut data, 0x40 + 16, host.len() as u32);

    data[0x60..0x60 + contract.len()].copy_from_slice(&contract);
    data[0xa0..0xa0 + host.len()].copy_from_slice(&host);
    data
}

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(|ch| ch.to_le_bytes())
        .collect()
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
