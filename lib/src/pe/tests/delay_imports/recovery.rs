use super::*;
use crate::pe::format::{synthesize_mapped_image, IMAGE_SCN_MEM_EXECUTE};
use crate::pe::image::SectionInfo;

fn fixture(machine: &str) -> Image {
    let section = SectionInfo {
        name: ".rdata".into(), virtual_address: 0x1000, virtual_size: 0x3000, raw_offset: 0x1000, raw_size: 0x3000,
        characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE,
    };
    let data = synthesize_mapped_image(&[], 0x400000, &[section], Some(machine), true, Some(0x1000), None).unwrap().data;
    let mut image = Image::parse(data).unwrap();
    for (offset, value) in [(0, 1), (4, 0x1500), (8, 0x1580), (12, 0x1600), (16, 0x1700)] {
        image.write_u32(0x1200 + offset, value).unwrap();
    }
    image.write_bytes(0x1500, b"sample.dll\0").unwrap();
    image.write_bytes(0x1802, b"Function\0").unwrap();
    image.write_pointer(0x1700, image.pointer_size(), 0x1800).unwrap();
    image.write_pointer(0x1600, image.pointer_size(), 0x70123456).unwrap();
    image
}

#[test]
fn discovers_delay_directory_without_relocating_runtime_tables() {
    for machine in ["x86", "x64", "arm64"] {
        let mapped = fixture(machine);
        let file = Image::parse(mapped.mapped_to_file_image().unwrap()).unwrap();
        for (image, mapped_layout) in [(&mapped, true), (&file, false)] {
            let report = if mapped_layout { image.recover_mapped_delay_imports() } else { image.recover_delay_imports() }.unwrap();
            assert_eq!(report.status, DelayImportRecoveryStatus::Discovered);
            let candidate = report.selected().unwrap();
            assert_eq!(candidate.directory_rva, 0x1200);
            assert_eq!(candidate.directory_size, 64);
            assert_eq!(candidate.descriptors[0].imports[0].name.as_deref(), Some("Function"));
            let data = if mapped_layout { image.restore_mapped_delay_imports(&report) } else { image.restore_delay_imports(&report) }.unwrap();
            let restored = Image::parse(data).unwrap();
            let declared = if mapped_layout { restored.recover_mapped_delay_imports() } else { restored.recover_delay_imports() }.unwrap();
            assert_eq!(declared.status, DelayImportRecoveryStatus::Declared);
            assert_eq!(&restored.data()[image.size_of_headers() as usize..], &image.data()[image.size_of_headers() as usize..]);
        }
    }
}

#[test]
fn refuses_ambiguous_destroyed_and_mutated_delay_candidates() {
    let mut image = fixture("x64");
    let report = image.recover_mapped_delay_imports().unwrap();
    image.write_bytes(0x1802, b"Changed!\0").unwrap();
    assert!(image.restore_mapped_delay_imports(&report).is_err());
    let second = image.read_mapped_bytes_rva(0x1200, 32).unwrap();
    image.write_bytes(0x2000, &second).unwrap();
    let report = image.recover_mapped_delay_imports().unwrap();
    assert_eq!(report.status, DelayImportRecoveryStatus::Ambiguous);
    assert!(image.restore_mapped_delay_imports(&report).is_err());
    image.write_bytes(0x1200, &[0; 64]).unwrap();
    image.write_bytes(0x2000, &[0; 64]).unwrap();
    assert_eq!(image.recover_mapped_delay_imports().unwrap().status, DelayImportRecoveryStatus::NotFound);
}

#[test]
fn supports_legacy_va_descriptors_but_rejects_partial_metadata() {
    let mut image = fixture("x86");
    image.write_u32(0x1200, 0).unwrap();
    for offset in [4, 8, 12, 16] {
        image.write_u32(0x1200 + offset, image.read_u32(0x1200 + offset).unwrap() + 0x400000).unwrap();
    }
    image.write_u32(0x1700, 0x401800).unwrap();
    assert_eq!(image.recover_mapped_delay_imports().unwrap().status, DelayImportRecoveryStatus::Discovered);
    image.write_u32(0x1208, 0).unwrap();
    assert_eq!(image.recover_mapped_delay_imports().unwrap().status, DelayImportRecoveryStatus::NotFound);
}

#[test]
fn parser_requires_descriptor_terminator_and_valid_attribute_and_ordinal_bits() {
    let mut image = fixture("x86");
    image.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x1200, 32).unwrap();
    assert!(matches!(image.mapped_delay_imports(), Err(DelayImportError::MissingTerminator)));
    image.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x1200, 64).unwrap();
    image.write_u32(0x1200, 3).unwrap();
    assert!(matches!(image.mapped_delay_imports(), Err(DelayImportError::InvalidDescriptor { .. })));
    image.write_u32(0x1200, 1).unwrap();
    image.write_u32(0x1700, 0xf0000001).unwrap();
    assert!(image.mapped_delay_imports().is_err());
    image.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, 0, 64).unwrap();
    assert!(image.mapped_delay_imports().is_err());
}

#[test]
fn restores_erased_descriptors_only_from_matching_source_with_surviving_tables() {
    for machine in ["x86", "x64", "arm64"] {
        let mut image = fixture(machine);
        image.write_u32(image.file_header_offset() + 4, 0x12345678).unwrap();
        image.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x1200, 64).unwrap();
        let source = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
        image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_DELAY_IMPORT).unwrap();
        image.write_bytes(0x1200, &[0; 64]).unwrap();
        let report = image.recover_mapped_delay_imports_from(&source).unwrap();
        assert_eq!(report.status, DelayImportRecoveryStatus::FromSource);
        let restored = Image::parse(image.restore_mapped_delay_imports(&report).unwrap()).unwrap();
        assert_eq!(restored.mapped_delay_imports().unwrap(), source.delay_imports().unwrap());
        let file = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
        let restored = Image::parse(file.restore_delay_imports(&report).unwrap()).unwrap();
        assert_eq!(restored.delay_imports().unwrap(), source.delay_imports().unwrap());
        image.write_bytes(0x1802, b"Changed!\0").unwrap();
        assert!(image.recover_mapped_delay_imports_from(&source).is_err());
        assert!(image.restore_mapped_delay_imports(&report).is_err());
        image.write_u32(image.file_header_offset() + 4, 1).unwrap();
        assert!(image.restore_mapped_delay_imports(&report).is_err());
    }
}

#[test]
fn incomplete_capture_does_not_promote_a_single_candidate() {
    let mut data = fixture("x64").into_data();
    data.truncate(0x3000);
    let image = Image::parse(data).unwrap();
    let report = image.recover_mapped_delay_imports().unwrap();
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.status, DelayImportRecoveryStatus::ScanLimit);
    assert!(report.selected().is_none());
}

#[test]
fn discovery_keeps_complete_runs_and_enforces_candidate_limits() {
    let mut image = fixture("x64");
    for (offset, value) in [(0, 1), (4, 0x1a00), (8, 0x1a80), (12, 0x1b00), (16, 0x1c00)] {
        image.write_u32(0x1220 + offset, value).unwrap();
    }
    image.write_bytes(0x1a00, b"second.dll\0").unwrap();
    image.write_bytes(0x1d02, b"Second\0").unwrap();
    image.write_pointer(0x1c00, 8, 0x1d00).unwrap();
    image.write_pointer(0x1b00, 8, 0x70200000).unwrap();
    let report = image.recover_mapped_delay_imports().unwrap();
    assert_eq!(report.status, DelayImportRecoveryStatus::Discovered);
    assert_eq!(report.candidates.len(), 1);
    assert_eq!(report.selected().unwrap().descriptors.len(), 2);
    assert_eq!(report.selected().unwrap().directory_size, 96);

    let descriptor = image.read_mapped_bytes_rva(0x1200, 32).unwrap();
    for index in 0..128 { image.write_bytes(0x2000 + index * 64, &descriptor).unwrap(); }
    let report = image.recover_mapped_delay_imports().unwrap();
    assert_eq!(report.status, DelayImportRecoveryStatus::ScanLimit);
    assert_eq!(report.candidates.len(), 128);
    assert!(report.scanned_bytes > 0);
    assert!(report.selected().is_none());
}

#[test]
fn zeroed_or_unterminated_runtime_iat_is_not_discovery_evidence() {
    let mut image = fixture("x64");
    image.write_pointer(0x1600, 8, 0).unwrap();
    assert_eq!(image.recover_mapped_delay_imports().unwrap().status, DelayImportRecoveryStatus::NotFound);
    image.write_pointer(0x1600, 8, 0x70123456).unwrap();
    image.write_pointer(0x1608, 8, 1).unwrap();
    assert_eq!(image.recover_mapped_delay_imports().unwrap().status, DelayImportRecoveryStatus::NotFound);
}

#[test]
fn python_delay_recovery_returns_typed_candidates_and_restores_file_and_mapped_layouts() {
    let mut image = fixture("arm64");
    image.write_u32(image.file_header_offset() + 4, 1234).unwrap();
    let mapped_data = image.data().to_vec();
    let file_data = image.mapped_to_file_image().unwrap();
    image.set_data_directory(PE_DIRECTORY_ENTRY_DELAY_IMPORT, 0x1200, 64).unwrap();
    let source = image.mapped_to_file_image().unwrap();
    image.clear_data_directory_if_present(PE_DIRECTORY_ENTRY_DELAY_IMPORT).unwrap();
    image.write_bytes(0x1200, &[0; 64]).unwrap();
    // Byte strings avoid exhausting RustPython's 32-bit refcount with repeated integer constants.
    let hex = |data: &[u8]| data.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let script = format!(r#"
import br3k
for data, mapped in [(bytes.fromhex("{mapped_data}"), True), (bytes.fromhex("{file_data}"), False)]:
    image = br3k.pe.Image.from_mapped(data, br3k.pe.Image(data).headers.preferred_base) if mapped else br3k.pe.Image(data)
    recovery = image.imports.delay.recover()
    assert isinstance(recovery, br3k.pe.imports.DelayRecovery)
    assert recovery.status == br3k.pe.imports.DelayRecoveryStatus.Discovered
    assert recovery.scanned_bytes > 0
    assert recovery.diagnostic is None
    candidate = recovery.selected()
    assert isinstance(candidate, br3k.pe.imports.DelayCandidate)
    assert candidate.directory_rva == 0x1200
    assert candidate.descriptors[0].dll_name == "sample.dll"
    assert candidate.descriptors[0].imports[0].name == "Function"
    editor = image.edit()
    editor.imports.delay.restore(recovery)
    restored = editor.build().image
    declared = restored.imports.delay.recover()
    assert declared.status == br3k.pe.imports.DelayRecoveryStatus.Declared

erased = br3k.pe.Image.from_mapped(bytes.fromhex("{erased}"), br3k.pe.Image(bytes.fromhex("{erased}")).headers.preferred_base)
missing = erased.imports.delay.recover()
assert missing.status == br3k.pe.imports.DelayRecoveryStatus.NotFound
assert missing.selected() is None
try:
    erased.edit().imports.delay.restore(missing)
except ValueError:
    pass
else:
    raise AssertionError("Restoring without a candidate must fail")
recovery = erased.imports.delay.recover(reference=br3k.pe.Image(bytes.fromhex("{source}")))
assert recovery.status == br3k.pe.imports.DelayRecoveryStatus.FromSource
editor = erased.edit()
editor.imports.delay.restore(recovery)
assert editor.build().image.imports.delay.entries()[0].dll_name == "sample.dll"
"#, mapped_data = hex(&mapped_data), file_data = hex(&file_data), erased = hex(image.data()), source = hex(&source));
    crate::vm::Vm::default().execute_script(&script, None, &None).unwrap();
}
