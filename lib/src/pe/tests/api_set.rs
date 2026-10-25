use super::*;

#[test]
fn api_set_map_parses_contract_hosts() {
    let data = test_namespace();
    let map = ApiSetMap::parse(&data).unwrap();

    assert_eq!(map.entries().len(), 1);
    assert_eq!(map.entries()[0].contract, "api-ms-win-core-test-l1-1-0");
    assert_eq!(map.entries()[0].hosts, vec!["kernelbase.dll"]);
    assert_eq!(
        map.resolve_contract("api-ms-win-core-test-l1-1-0.dll"),
        Some("kernelbase.dll"),
    );
}

fn test_namespace() -> Vec<u8> {
    let mut data = vec![0u8; 0x120];
    let contract = wide("api-ms-win-core-test-l1-1-0");
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
