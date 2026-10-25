use super::embedded::EmbeddedImageLayout;
use super::exports::{ExportSymbol, ExportTable};
use super::format::*;
use super::image::{Error, Image, SectionInfo};
use super::imports::{ImportAddressResolveOptions, ImportModel};
use super::export_map::ExportMap;
use super::headers::{synthesize_from_regions, DirectoryRecoveryStatus};
use super::imports::{apply_import_context, ImportEvidenceKind, ImportTarget};
use crate::sysapi::MemoryRegion;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE};

fn mapped_image(machine: &str, section_size: u32) -> Image {
    let section = SectionInfo {
        name: ".text".into(), virtual_address: 0x1000, virtual_size: section_size,
        raw_offset: 0x1000, raw_size: section_size,
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
    };
    let image = synthesize_mapped_image(&[], 0x400000, &[section], Some(machine), true, Some(0x1000), None).unwrap();
    Image::parse(image.data).unwrap()
}

fn exports() -> ExportTable {
    ExportTable {
        module_name: "target.dll".into(), image_base: 0x7000, image_size: 0x1000,
        time_date_stamp: None,
        symbols: vec![ExportSymbol {
            module_name: "target.dll".into(), name: Some("Target".into()), names: vec!["Target".into()],
            ordinal: 1, rva: 0x10, address: 0x7010, forwarder: None,
        }],
    }
}

#[test]
fn anchored_iat_expands_from_unaligned_interior_slot() {
    for pointer_size in [4, 8] {
        let mut data = vec![0u8; 64];
        for index in 0..3 {
            let offset = 3 + index * pointer_size;
            data[offset..offset + pointer_size].copy_from_slice(&0x7010u64.to_le_bytes()[..pointer_size]);
        }
        let table = exports();
        let ranges = crate::pe::imports::scan_iat_ranges_containing_rvas_with_options(
            &data, 0x1000, pointer_size, ImportAddressResolveOptions::default(), &[&table],
            &[0x1003 + pointer_size as u32, 0x1003 + 2 * pointer_size as u32, 0xffff_ffff],
        ).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].rva, 0x1003);
        assert_eq!(ranges[0].entries, 3);
        assert_eq!(ranges[0].size, 3 * pointer_size as u32);
        data.truncate(3 + 3 * pointer_size);
        assert!(crate::pe::imports::scan_iat_ranges_containing_rvas_with_options(
            &data, 0x1000, pointer_size, ImportAddressResolveOptions::default(), &[&table], &[0x1003],
        ).unwrap().is_empty());
    }
}

#[test]
fn embedded_file_is_excluded_from_parent_iat_and_code_scans() {
    let mut inner = mapped_image("x64", 0x200);
    let call = [0x48, 0xb8, 0x10, 0x70, 0, 0, 0, 0, 0, 0, 0xff, 0xd0];
    inner.write_bytes(0x1000, &call).unwrap();
    inner.write_pointer(0x1040, 8, 0x7010).unwrap();
    inner.write_pointer(0x1048, 8, 0x7010).unwrap();
    let file = inner.mapped_to_file_image().unwrap();
    assert_eq!(file.len(), 0x400);
    let mut parent = mapped_image("x64", 0x2000);
    parent.write_bytes(0x1000, &call).unwrap();
    parent.write_bytes(0x2c00, &file).unwrap();
    let found = parent.mapped_embedded_images().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].offset, 0x2c00);
    assert_eq!(found[0].layout, EmbeddedImageLayout::File);
    assert!(found[0].excluded_from_parent());
    let table = exports();
    let refs = super::imports::scan_mapped_export_code_references_with_options(
        parent.data(), None, ImportAddressResolveOptions::default(), &[&table],
    ).unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].reference_rva, 0x1000);
    assert!(crate::pe::imports::scan_iat_ranges_with_options(
        parent.data(), 0, 8, ImportAddressResolveOptions::default(), &[&table], 2,
    ).unwrap().is_empty());
    assert!(crate::pe::imports::scan_iat_ranges_containing_rvas_with_options(
        parent.data(), 0, 8, ImportAddressResolveOptions::default(), &[&table], &[0x2e40],
    ).unwrap().is_empty());
    parent.write_pointer(0x2000, 8, 0x402e00).unwrap();
    assert!(crate::pe::imports::scan_iat_ranges_with_traced_thunks(
        parent.data(), 0, 8, ImportAddressResolveOptions::default(), &[&table], 1, None, 4,
    ).unwrap().is_empty());
}

#[test]
fn ambiguous_embedded_image_is_not_excluded_without_resource_evidence() {
    for machine in ["x86", "x64", "arm64"] {
        let inner = mapped_image(machine, 0x200).mapped_to_file_image().unwrap();
        let mut parent = mapped_image(machine, 0x3000);
        parent.write_bytes(0x2000, &inner).unwrap();
        let found = parent.mapped_embedded_images().unwrap();
        assert_eq!(found[0].layout, EmbeddedImageLayout::Ambiguous);
        assert!(!found[0].excluded_from_parent());
        parent.set_data_directory(PE_DIRECTORY_ENTRY_RESOURCE, 0x1800, 0x1000).unwrap();
        parent.write_u16(0x180e, 1).unwrap();
        parent.write_u32(0x1810, 1).unwrap();
        parent.write_u32(0x1814, 24).unwrap();
        parent.write_u32(0x1818, 0x2000).unwrap();
        parent.write_u32(0x181c, inner.len() as u32).unwrap();
        let found = parent.mapped_embedded_images().unwrap();
        assert_eq!(found[0].layout, EmbeddedImageLayout::File);
        assert!(found[0].resource_backed);
    }
}

#[test]
fn header_growth_preserves_header_data_rvas_and_file_offset_fields() {
    for machine in ["x86", "x64", "arm64"] {
        let mut image = Image::parse(mapped_image(machine, 0x200).mapped_to_file_image().unwrap()).unwrap();
        let table_end = image.section_table_offset() + 40;
        image.write_bytes(table_end, b"preserve header data").unwrap();
        image.write_bytes(0x240, b"section payload").unwrap();
        image.set_data_directory(PE_DIRECTORY_ENTRY_DEBUG, 0x1000, 28).unwrap();
        image.write_u32(0x218, 0x240).unwrap();
        image.write_u32(image.file_header_offset() + 8, 0x2f0).unwrap();
        image.set_data_directory(PE_DIRECTORY_ENTRY_SECURITY, 0x400, 8).unwrap();
        let mut data = image.into_data();
        data.extend_from_slice(b"overlay!");
        let mut image = Image::parse(data).unwrap();
        let added = image.append_section(".idata", 0x80).unwrap();
        let growth = image.size_of_headers() - 0x200;
        assert!(growth > 0);
        assert_eq!(&image.data()[table_end..table_end + 20], b"preserve header data");
        assert_eq!(image.sections().unwrap()[0].virtual_address, 0x1000);
        assert_eq!(image.read_bytes_rva(0x1040, 15).unwrap(), b"section payload");
        let debug_offset = image.rva_to_file_offset(0x1000).unwrap();
        assert_eq!(image.read_u32(debug_offset + 24).unwrap(), 0x240 + growth);
        assert_eq!(image.read_u32(image.file_header_offset() + 8).unwrap(), 0x2f0 + growth);
        let security = image.data_directory(PE_DIRECTORY_ENTRY_SECURITY).unwrap();
        assert_eq!(security.virtual_address, 0x400 + growth);
        assert_eq!(&image.data()[security.virtual_address as usize..security.virtual_address as usize + 8], b"overlay!");
        assert_eq!(added.virtual_address, 0x2000);
        assert!(added.raw_offset > security.virtual_address as usize);
    }
}

#[test]
fn failed_header_growth_does_not_modify_image() {
    let mut image = Image::parse(mapped_image("x64", 0x200).mapped_to_file_image().unwrap()).unwrap();
    image.write_bytes(image.section_table_offset() + 40, b"occupied").unwrap();
    image.write_u32(image.section_table_offset() + 12, 0x200).unwrap();
    let original = image.data().to_vec();
    assert!(matches!(image.append_section(".idata", 16), Err(Error::SectionHeaderSpace)));
    assert_eq!(image.data(), original);
}

#[test]
fn zero_filled_directory_is_not_free_section_header_space() {
    let mut image = Image::parse(mapped_image("x64", 0x200).mapped_to_file_image().unwrap()).unwrap();
    let slot = image.section_table_offset() + 40;
    image.set_data_directory(PE_DIRECTORY_ENTRY_TLS, slot as u32, 40).unwrap();
    image.append_section(".extra", 16).unwrap();
    assert!(image.size_of_headers() > 0x200);
    assert_eq!(image.data_directory(PE_DIRECTORY_ENTRY_TLS).unwrap().virtual_address, slot as u32);
    assert!(image.data()[slot..slot + 40].iter().all(|byte| *byte == 0));
}

fn region(offset: u64, size: usize, protect: u32) -> MemoryRegion {
    MemoryRegion {
        base_address: 0x400000 + offset, allocation_base: 0x400000, allocation_protect: protect,
        region_size: size, state: MEM_COMMIT, protect, memory_type: MEM_PRIVATE, mapped_path: None,
    }
}

#[test]
fn region_synthesis_preserves_bytes_addresses_and_protections() {
    let mut regions = vec![region(0, 0x1000, PAGE_EXECUTE_READ), region(0x1000, 0x1000, PAGE_READWRITE), region(0x2000, 0x1000, 0)];
    regions[2].state = MEM_RESERVE;
    let mut raw = vec![0x5a; 0x2000];
    raw.resize(0x3000, 0);
    for machine in ["x86", "x64", "arm64"] {
        let synthetic = synthesize_from_regions(&raw, 0x400000, &regions, machine, true, None).unwrap();
        assert_eq!(synthetic.entry_point, 0);
        assert_eq!(&synthetic.data[synthetic.header_prefix as usize..synthetic.header_prefix as usize + raw.len()], raw);
        assert_eq!(synthetic.image_base + synthetic.header_prefix as u64, 0x400000);
        let image = Image::parse(synthetic.data).unwrap();
        let sections = image.sections().unwrap();
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].characteristics & IMAGE_SCN_MEM_WRITE, 0);
        assert_ne!(sections[0].characteristics & IMAGE_SCN_MEM_EXECUTE, 0);
        assert_ne!(sections[1].characteristics & IMAGE_SCN_MEM_WRITE, 0);
        assert_eq!(sections[1].characteristics & IMAGE_SCN_MEM_EXECUTE, 0);
        let file = Image::parse(image.mapped_to_file_image().unwrap()).unwrap();
        assert_eq!(file.read_bytes_rva(sections[0].virtual_address, 0x2000).unwrap(), raw[..0x2000]);
        let explicit = synthesize_from_regions(&raw, 0x400000, &regions, machine, true, Some(0x123)).unwrap();
        assert_eq!(explicit.image_base + explicit.entry_point as u64, 0x400123);
    }
    regions.push(region(0, 0x1000, PAGE_READWRITE));
    assert!(synthesize_from_regions(&raw, 0x400000, &regions, "x64", true, None).is_err());
    assert!(synthesize_from_regions(&raw, 0, &regions, "x86", true, None).is_err());
}

#[test]
fn directories_are_salvaged_independently_of_damaged_section_table() {
    for machine in ["x86", "x64", "arm64"] {
        let mut source = mapped_image(machine, 0x2000);
        source.set_data_directory(PE_DIRECTORY_ENTRY_IMPORT, 0x1300, 20).unwrap();
        source.write_u32(0x130c, 0xfffffff0).unwrap();
        source.set_data_directory(PE_DIRECTORY_ENTRY_IAT, 0x1800, 16).unwrap();
        source.set_data_directory(PE_DIRECTORY_ENTRY_BASERELOC, 0x1900, 12).unwrap();
        source.write_u32(0x1900, 0x1000).unwrap();
        source.write_u32(0x1904, 12).unwrap();
        source.write_u16(0x1908, if machine == "x86" { 0x3080 } else { 0xa080 }).unwrap();
        source.set_data_directory(PE_DIRECTORY_ENTRY_SECURITY, 0x1800, 16).unwrap();
        source.set_data_directory(PE_DIRECTORY_ENTRY_TLS, 0x180, 40).unwrap();
        let offset = source.file_header_offset();
        let sections = source.sections().unwrap();
        source.write_bytes(source.section_table_offset(), &[0xff; 40]).unwrap();
        let synthetic = synthesize_mapped_image(source.data(), 0x400000, &sections, Some(machine), true, Some(0), None).unwrap();
        let mut image = Image::parse(synthetic.data).unwrap();
        let records = image.salvage_directories(source.data(), offset).unwrap();
        let status = |index| records.iter().find(|record| record.index == index).unwrap().status;
        assert_eq!(status(PE_DIRECTORY_ENTRY_IMPORT), DirectoryRecoveryStatus::Invalid);
        assert_eq!(status(PE_DIRECTORY_ENTRY_IAT), DirectoryRecoveryStatus::Restored);
        assert_eq!(status(PE_DIRECTORY_ENTRY_BASERELOC), DirectoryRecoveryStatus::Restored);
        assert_eq!(status(PE_DIRECTORY_ENTRY_SECURITY), DirectoryRecoveryStatus::FileOnly);
        assert_eq!(status(PE_DIRECTORY_ENTRY_TLS), DirectoryRecoveryStatus::HeaderOverlap);
        assert!(image.data_directory(PE_DIRECTORY_ENTRY_IMPORT).unwrap().is_empty());
        assert_eq!(image.mapped_base_relocations().unwrap().len(), 1);
        assert!(image.salvage_directories(source.data(), usize::MAX).is_err());
    }
}

fn public_exports(module: &str, base: u64) -> ExportTable {
    ExportTable {
        module_name: module.into(), image_base: base, image_size: 0x1000,
        time_date_stamp: None,
        symbols: vec![ExportSymbol {
            module_name: module.into(), name: Some("PublicTarget".into()), names: vec!["PublicTarget".into()],
            ordinal: 7, rva: 0x100, address: base + 0x100, forwarder: Some("target.Target".into()),
        }],
    }
}

#[test]
fn public_export_candidates_preserve_all_forwarders() {
    let map = ExportMap::new(vec![public_exports("first.dll", 0x8000), public_exports("second.dll", 0x9000), exports()]);
    let candidates = map.public_candidates(0x7010);
    assert_eq!(candidates.len(), 3);
    assert_eq!(candidates[0].symbol.module_name, "first.dll");
    assert_eq!(candidates[1].symbol.module_name, "second.dll");
    assert_eq!(candidates[2].symbol.module_name, "target.dll");
    assert_eq!(map.resolve_public_va_for_module(0x7010, "second.dll").unwrap().symbol.name.as_deref(), Some("PublicTarget"));
    assert!(map.resolve_public_va_for_module(0x7010, "missing.dll").is_none());
}

#[test]
fn import_declarations_override_aliases_only_when_live_address_matches() {
    let map = ExportMap::new(vec![public_exports("first.dll", 0x8000), public_exports("second.dll", 0x9000), exports()]);
    for machine in ["x86", "x64", "arm64"] {
        let mut image = mapped_image(machine, 0x2000);
        let size = image.pointer_size();
        image.set_data_directory(PE_DIRECTORY_ENTRY_IMPORT, 0x1100, 40).unwrap();
        image.write_u32(0x1100, 0x1200).unwrap();
        image.write_u32(0x110c, 0x1400).unwrap();
        image.write_u32(0x1110, 0x1300).unwrap();
        image.write_pointer(0x1200, size, 0x1500).unwrap();
        image.write_pointer(0x1300, size, 0x7010).unwrap();
        image.write_bytes(0x1400, b"second.dll\0").unwrap();
        image.write_bytes(0x1502, b"PublicTarget\0").unwrap();
        let mut model = ImportModel::default();
        model.add_module("first.dll", 0x1300, 1).unwrap();
        model.add_function("first.dll", 0x1300, ImportTarget::Ordinal(7), true, true).unwrap();
        assert_eq!(apply_import_context(&mut model, &image, &map).unwrap(), 1);
        let imports = model.imports();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module_name, "second.dll");
        assert!(imports[0].evidence.iter().any(|evidence| evidence.kind == ImportEvidenceKind::ImportDeclaration));
        image.write_pointer(0x1300, size, 0x7020).unwrap();
        let mut model = ImportModel::default();
        assert_eq!(apply_import_context(&mut model, &image, &map).unwrap(), 0);
        assert_eq!(model.function_count(), 0);
    }
}

#[test]
fn address_only_imports_use_exact_public_exports_from_the_declared_module() {
    let map = ExportMap::new(vec![public_exports("first.dll", 0x8000), public_exports("second.dll", 0x9000), exports()]);
    for machine in ["x86", "x64", "arm64"] {
        let mut image = mapped_image(machine, 0x2000);
        image.set_data_directory(PE_DIRECTORY_ENTRY_IMPORT, 0x1100, 40).unwrap();
        image.write_u32(0x110c, 0x1400).unwrap();
        image.write_u32(0x1110, 0x1300).unwrap();
        image.write_pointer(0x1300, image.pointer_size(), 0x7010).unwrap();
        image.write_bytes(0x1400, b"second.dll\0").unwrap();
        let mut model = ImportModel::default();
        assert_eq!(apply_import_context(&mut model, &image, &map).unwrap(), 1);
        let imports = model.imports();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module_name, "second.dll");
        assert_eq!(imports[0].name.as_deref(), Some("PublicTarget"));
        assert!(imports[0].evidence.iter().any(|evidence| evidence.kind == ImportEvidenceKind::ImportModuleContext));
        assert!(!imports[0].evidence.iter().any(|evidence| evidence.kind == ImportEvidenceKind::ImportDeclaration));
        for (name, address) in [(b"absent.dll\0", 0x7010), (b"second.dll\0", 0x7011)] {
            image.write_bytes(0x1400, name).unwrap();
            image.write_pointer(0x1300, image.pointer_size(), address).unwrap();
            let mut model = ImportModel::default();
            assert_eq!(apply_import_context(&mut model, &image, &map).unwrap(), 0);
            assert_eq!(model.function_count(), 0);
        }
    }
}
