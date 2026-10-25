use super::*;

#[test]
fn scan_header_artifacts_finds_mz_pe() {
    let raw = synthesize_mapped_image(
        &[0; 0x2000],
        0x180000000,
        &[SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x200,
            raw_offset: 0x1000,
            raw_size: 0x200,
            characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        }],
        Some("x64"),
        true,
        None,
        None,
    )
    .unwrap();
    let artifacts = scan_header_artifacts(&raw.data, 0x180000000, 0x180000000);

    assert!(artifacts.iter().any(|artifact| artifact.kind == HeaderArtifactKind::MzPe));
    assert!(artifacts.iter().any(|artifact| artifact.kind == HeaderArtifactKind::SectionTable));
}

#[test]
fn parse_section_table_rejects_non_executable_tables() {
    let mut data = vec![0; SECTION_HEADER_SIZE];
    data[0..5].copy_from_slice(b".data");
    data[8..12].copy_from_slice(&0x100u32.to_le_bytes());
    data[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[16..20].copy_from_slice(&0x100u32.to_le_bytes());
    data[20..24].copy_from_slice(&0x1000u32.to_le_bytes());
    data[36..40].copy_from_slice(&IMAGE_SCN_MEM_READ.to_le_bytes());

    assert!(parse_section_table(&data, 0, Some(1)).is_none());
}
