use super::*;
use crate::pe::diagnostics::{metadata_summary, ImageAnomalyKind};
use crate::pe::format::{synthesize_mapped_image, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ};
use crate::pe::image::SectionInfo;

const DIRECTORY_RVA: u32 = 0x1100;
const DIRECTORY_SIZE: u32 = 0x50;

pub(super) fn fixture(machine: &str, directory_rva: u32) -> Image {
    let section = SectionInfo {
        name: ".rdata".to_string(),
        virtual_address: 0x1000,
        virtual_size: 0x1000,
        raw_offset: 0x1000,
        raw_size: 0x1000,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    };
    let synthetic = synthesize_mapped_image(&[], 0x400000, &[section], Some(machine), true, Some(0), None).unwrap();
    let mut image = Image::parse(synthetic.data).unwrap();
    image.set_data_directory(PE_DIRECTORY_ENTRY_BOUND_IMPORT, directory_rva, DIRECTORY_SIZE).unwrap();
    let base = directory_rva as usize;

    // Two descriptors, with one forwarder between them, followed by the terminator and name pool.
    image.write_u32(base, 0x12345678).unwrap();
    image.write_u16(base + 4, 0x20).unwrap();
    image.write_u16(base + 6, 1).unwrap();
    image.write_u32(base + 8, 0x87654321).unwrap();
    image.write_u16(base + 12, 0x30).unwrap();
    image.write_u16(base + 14, 7).unwrap();
    image.write_u32(base + 16, 0).unwrap();
    image.write_u16(base + 20, 0x40).unwrap();
    image.write_bytes(base + 0x20, b"kernel32.dll\0").unwrap();
    image.write_bytes(base + 0x30, b"ntdll.dll\0").unwrap();
    image.write_bytes(base + 0x40, b"user32.dll\0").unwrap();
    image
}

mod parsing;
mod validation;
