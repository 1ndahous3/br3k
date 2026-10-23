use super::*;
use crate::pe::image::SectionInfo;
use crate::vm::Vm;

fn fixture(machine: &str, index: usize, size: u32) -> Image {
    let section = SectionInfo {
        name: ".test".into(), virtual_address: 0x1000, virtual_size: 0x3000, raw_offset: 0x1000, raw_size: 0x3000,
        characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
    };
    let data = synthesize_mapped_image(&[], 0x400000, &[section], Some(machine), true, Some(0x1000), None).unwrap().data;
    let mut image = Image::parse(data).unwrap();
    image.set_data_directory(index, 0x1400, size).unwrap();
    image
}

fn status(source: &Image, index: usize) -> DirectoryRecovery {
    let mut destination = Image::parse(source.data().to_vec()).unwrap();
    destination.set_data_directory(index, 0x1f00, 4).unwrap();
    let records = destination.salvage_directories(source.data(), source.file_header_offset()).unwrap();
    let record = records.into_iter().find(|record| record.index == index).unwrap();
    if record.status != DirectoryRecoveryStatus::Restored {
        assert_eq!(destination.data_directory(index).unwrap().virtual_address, 0x1f00);
    }
    record
}

#[test]
fn salvages_x64_chained_and_arm64_packed_and_full_unwind_records() {
    let mut x64 = fixture("x64", PE_DIRECTORY_ENTRY_EXCEPTION, 12);
    x64.write_u32(0x1400, 0x1000).unwrap();
    x64.write_u32(0x1404, 0x1040).unwrap();
    x64.write_u32(0x1408, 0x1800).unwrap();
    x64.write_u32(0x1800, 0x21).unwrap();
    x64.write_u32(0x1804, 0x1000).unwrap();
    x64.write_u32(0x1808, 0x1040).unwrap();
    x64.write_u32(0x180c, 0x1820).unwrap();
    x64.write_u32(0x1820, 1).unwrap();
    assert_eq!(status(&x64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Restored);
    x64.write_u32(0x180c, 0x1800).unwrap();
    assert_eq!(status(&x64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Invalid);
    x64.write_u32(0x1800, 3).unwrap();
    assert_eq!(status(&x64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Unsupported);

    let mut arm64 = fixture("arm64", PE_DIRECTORY_ENTRY_EXCEPTION, 8);
    arm64.write_u32(0x1400, 0x1000).unwrap();
    for packed in [0x41, 0x42] {
        arm64.write_u32(0x1404, packed).unwrap();
        assert_eq!(status(&arm64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Restored);
    }
    arm64.write_u32(0x1404, 0x1800).unwrap();
    arm64.write_u32(0x1800, 16 | (1 << 27)).unwrap();
    arm64.write_u32(0x1804, 0xe4).unwrap();
    assert_eq!(status(&arm64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Restored);
    arm64.write_u32(0x1800, 16).unwrap();
    arm64.write_u32(0x1804, 1 << 16).unwrap();
    arm64.write_u32(0x1808, 0xe4).unwrap();
    assert_eq!(status(&arm64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Restored);
    arm64.write_u32(0x1404, 3).unwrap();
    assert_eq!(status(&arm64, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Invalid);
}

#[test]
fn rejects_truncated_unsorted_and_nonexecutable_exception_ranges() {
    let mut image = fixture("x64", PE_DIRECTORY_ENTRY_EXCEPTION, 24);
    for (offset, begin) in [(0x1400, 0x1100), (0x140c, 0x1000)] {
        image.write_u32(offset, begin).unwrap();
        image.write_u32(offset + 4, begin + 16).unwrap();
        image.write_u32(offset + 8, 0x1800).unwrap();
    }
    image.write_u32(0x1800, 1).unwrap();
    assert_eq!(status(&image, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Invalid);
    image.set_data_directory(PE_DIRECTORY_ENTRY_EXCEPTION, 0x1400, 11).unwrap();
    assert_eq!(status(&image, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Invalid);
    image.set_data_directory(PE_DIRECTORY_ENTRY_EXCEPTION, 0x1400, 12).unwrap();
    image.write_u32(image.section_table_offset() + 36, IMAGE_SCN_MEM_READ).unwrap();
    let image = Image::parse(image.into_data()).unwrap();
    assert_eq!(status(&image, PE_DIRECTORY_ENTRY_EXCEPTION).status, DirectoryRecoveryStatus::Invalid);
}

#[test]
fn salvages_debug_and_bound_metadata_across_architectures() {
    for machine in ["x86", "x64", "arm64"] {
        let mut debug = fixture(machine, PE_DIRECTORY_ENTRY_DEBUG, 28);
        debug.write_u32(0x140c, 2).unwrap();
        debug.write_u32(0x1410, 26).unwrap();
        debug.write_u32(0x1414, 0x1800).unwrap();
        debug.write_bytes(0x1800, b"RSDS").unwrap();
        debug.write_bytes(0x1818, b"p\0").unwrap();
        assert_eq!(status(&debug, PE_DIRECTORY_ENTRY_DEBUG).status, DirectoryRecoveryStatus::Restored);
        debug.write_u32(0x1410, 24).unwrap();
        assert_eq!(status(&debug, PE_DIRECTORY_ENTRY_DEBUG).status, DirectoryRecoveryStatus::Invalid);
        debug.write_u32(0x1414, 0).unwrap();
        assert_eq!(status(&debug, PE_DIRECTORY_ENTRY_DEBUG).status, DirectoryRecoveryStatus::Unsupported);

        let mut bound = fixture(machine, PE_DIRECTORY_ENTRY_BOUND_IMPORT, 32);
        bound.write_u32(0x1400, 123).unwrap();
        bound.write_u16(0x1404, 16).unwrap();
        bound.write_bytes(0x1410, b"ntdll.dll\0").unwrap();
        assert_eq!(status(&bound, PE_DIRECTORY_ENTRY_BOUND_IMPORT).status, DirectoryRecoveryStatus::Restored);
    }
}

fn clr_fixture(machine: &str) -> Image {
    let mut image = fixture(machine, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR, 72);
    image.write_u32(0x1400, 72).unwrap();
    image.write_u32(0x1408, 0x1800).unwrap();
    image.write_u32(0x140c, 80).unwrap();
    image.write_bytes(0x1800, b"BSJB").unwrap();
    image.write_u32(0x180c, 4).unwrap();
    image.write_bytes(0x1810, b"v4\0\0").unwrap();
    image.write_u16(0x1816, 1).unwrap();
    image.write_u32(0x1818, 48).unwrap();
    image.write_u32(0x181c, 24).unwrap();
    image.write_bytes(0x1820, b"#~\0\0").unwrap();
    image
}

#[test]
fn clr_stream_ranges_are_checked_before_restoring_headers() {
    for machine in ["x86", "x64", "arm64"] {
        let mut image = clr_fixture(machine);
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR).status, DirectoryRecoveryStatus::Restored);
        image.write_u32(0x1818, 4).unwrap();
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR).status, DirectoryRecoveryStatus::Invalid);
        image.write_u32(0x1818, u32::MAX).unwrap();
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR).status, DirectoryRecoveryStatus::Invalid);
    }
}

#[test]
fn load_config_checks_cookie_va_and_guard_tables_without_dereferencing_external_targets() {
    for machine in ["x86", "x64", "arm64"] {
        let pointer_size = if machine == "x86" { 4 } else { 8 };
        let size = if pointer_size == 4 { 0xc0 } else { 0x140 };
        let mut image = fixture(machine, PE_DIRECTORY_ENTRY_LOAD_CONFIG, size);
        image.write_u32(0x1400, size).unwrap();
        let cookie = 0x1400 + if pointer_size == 4 { 0x3c } else { 0x58 };
        let table = 0x1400 + if pointer_size == 4 { 0x50 } else { 0x80 };
        image.write_pointer(cookie, pointer_size, 0x401800).unwrap();
        image.write_pointer(0x1800, pointer_size, 0xfeedface).unwrap();
        image.write_pointer(table, pointer_size, 0x401900).unwrap();
        image.write_pointer(table + pointer_size, pointer_size, 1).unwrap();
        image.write_u32(0x1900, 0x1100).unwrap();
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_LOAD_CONFIG).status, DirectoryRecoveryStatus::Restored);
        image.write_pointer(table + pointer_size, pointer_size, u32::MAX as u64).unwrap();
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_LOAD_CONFIG).status, DirectoryRecoveryStatus::Invalid);
        image.write_pointer(table + pointer_size, pointer_size, 1).unwrap();
        image.write_pointer(cookie, pointer_size, 0x500000).unwrap();
        assert_eq!(status(&image, PE_DIRECTORY_ENTRY_LOAD_CONFIG).status, DirectoryRecoveryStatus::Invalid);
    }
}

#[test]
fn python_directory_salvage_reports_extended_metadata() {
    let source = clr_fixture("arm64");
    let data = source.data().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let script = format!(r#"
import br3k
data = bytes.fromhex("{data}")
editor = br3k.pe.Image(data).edit()
records = editor.headers.salvage(data, {offset})
record = next(record for record in records if record.index == br3k.pe.PE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
assert record.status == br3k.pe.headers.DirectoryRecoveryStatus.Restored
assert record.error is None
assert editor.build().image.headers.directory(record.index).virtual_address == 0x1400
"#, offset = source.file_header_offset());
    Vm::default().execute_script(&script, None, &None).unwrap();
}

#[test]
fn metadata_offset_mutations_fail_without_panics_or_lost_rollback() {
    for machine in ["x86", "x64", "arm64"] {
        for offset in (0x1400..0x1448).step_by(4) {
            for value in [0, u32::MAX, 0xfffffff0, 0x4001] {
                let mut image = clr_fixture(machine);
                image.write_u32(offset, value).unwrap();
                status(&image, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
            }
        }
        for offset in (0x1800..0x1828).step_by(4) {
            for value in [0, u32::MAX, 0xfffffff0, 0x4001] {
                let mut image = clr_fixture(machine);
                image.write_u32(offset, value).unwrap();
                status(&image, PE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
            }
        }
    }
}
