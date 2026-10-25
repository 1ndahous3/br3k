use super::*;

#[test]
fn scan_iat_ranges_finds_terminated_export_pointer_runs() {
    let exports = export_table();
    let mut image_data = Vec::new();
    image_data.extend_from_slice(&0u64.to_le_bytes());
    image_data.extend_from_slice(&0x1010u64.to_le_bytes());
    image_data.extend_from_slice(&0x1030u64.to_le_bytes());
    image_data.extend_from_slice(&0u64.to_le_bytes());
    image_data.extend_from_slice(&0x5555u64.to_le_bytes());

    let ranges = scan_iat_ranges(&image_data, 0x3000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

    assert_eq!(
        ranges,
        vec![ImportAddressTableRange {
            rva: 0x3008,
            size: 16,
            entries: 2,
        }],
    );
}

#[test]
fn rank_iat_ranges_prefers_anchor_hits_then_entry_count() {
    let ranges = vec![
        ImportAddressTableRange {
            rva: 0x3000,
            size: 0x40,
            entries: 8,
        },
        ImportAddressTableRange {
            rva: 0x5000,
            size: 0x10,
            entries: 2,
        },
    ];
    let unanchored = rank_iat_ranges(ranges.clone(), &[]).unwrap();
    let anchored = rank_iat_ranges(ranges, &[0x5008]).unwrap();

    assert_eq!(unanchored[0].range.rva, 0x3000);
    assert_eq!(unanchored[0].score, 128);
    assert_eq!(anchored[0].range.rva, 0x5000);
    assert_eq!(anchored[0].anchor_count, 1);
    assert_eq!(anchored[0].nearest_anchor_distance, Some(0));
    assert!(anchored[0].score > anchored[1].score);
}

#[test]
fn scan_iat_ranges_uses_nearest_mode_when_requested() {
    let exports = export_table();
    let mut image_data = Vec::new();
    image_data.extend_from_slice(&0x1013u64.to_le_bytes());
    image_data.extend_from_slice(&0x1038u64.to_le_bytes());
    image_data.extend_from_slice(&0u64.to_le_bytes());

    let ranges = scan_iat_ranges(&image_data, 0x4000, 8, ImportAddressResolveMode::Nearest, &[&exports], 2).unwrap();

    assert_eq!(
        ranges,
        vec![ImportAddressTableRange {
            rva: 0x4000,
            size: 16,
            entries: 2,
        }],
    );
}

#[test]
fn scan_iat_ranges_requires_null_terminator() {
    let exports = export_table();
    let mut image_data = Vec::new();
    image_data.extend_from_slice(&0x1010u64.to_le_bytes());
    image_data.extend_from_slice(&0x1030u64.to_le_bytes());

    let ranges = scan_iat_ranges(&image_data, 0x4000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

    assert!(ranges.is_empty());
}

#[test]
fn scan_iat_ranges_keeps_singletons_near_anchor_run() {
    let exports = export_table();
    let mut image_data = Vec::new();
    image_data.extend_from_slice(&0x1010u64.to_le_bytes());
    image_data.extend_from_slice(&0x1030u64.to_le_bytes());
    image_data.extend_from_slice(&0u64.to_le_bytes());
    image_data.extend_from_slice(&0x1010u64.to_le_bytes());
    image_data.extend_from_slice(&0u64.to_le_bytes());

    let ranges = scan_iat_ranges(&image_data, 0x5000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

    assert_eq!(
        ranges,
        vec![ImportAddressTableRange {
            rva: 0x5000,
            size: 32,
            entries: 3,
        }],
    );
}

#[test]
fn scan_iat_ranges_drops_isolated_singletons() {
    let exports = export_table();
    let mut image_data = Vec::new();
    image_data.extend_from_slice(&0x1010u64.to_le_bytes());
    image_data.extend_from_slice(&0u64.to_le_bytes());

    let ranges = scan_iat_ranges(&image_data, 0x5000, 8, ImportAddressResolveMode::Exact, &[&exports], 2).unwrap();

    assert!(ranges.is_empty());
}

#[test]
fn scan_iat_ranges_containing_rvas_keeps_anchor_ranges() {
    let exports = export_table();
    let mut image_data = vec![0u8; 0x120];
    image_data[0x00..0x08].copy_from_slice(&0x1010u64.to_le_bytes());
    image_data[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());
    image_data[0x100..0x108].copy_from_slice(&0x1030u64.to_le_bytes());
    image_data[0x108..0x110].copy_from_slice(&0u64.to_le_bytes());

    let ranges = scan_iat_ranges_containing_rvas(
        &image_data,
        0x5000,
        8,
        ImportAddressResolveMode::Exact,
        &[&exports],
        &[0x5100],
    )
    .unwrap();

    assert_eq!(
        ranges,
        vec![ImportAddressTableRange {
            rva: 0x5100,
            size: 8,
            entries: 1,
        }],
    );
}
