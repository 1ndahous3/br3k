use super::{BuildPolicy, imports::Plan};
use crate::pe::export_map::ExportMap;
use crate::pe::exports::{ExportSymbol, ExportTable};
use crate::pe::format::{self, PE_DIRECTORY_ENTRY_IAT};
use crate::pe::image::{Image, SectionInfo};
use crate::pe::image::editor::BuildStatus;
use crate::pe::imports::{ImportCodeReference, ImportCodeReferenceKind, ImportError, ImportTarget};

const IMAGE_BASE: u64 = 0x400000;
const IAT_RVA: u32 = 0x1100;

fn mapped_image(machine: &str, code: &[u8]) -> Image {
    let section = SectionInfo {
        name: ".text".into(), virtual_address: 0x1000, virtual_size: 0x1000,
        raw_offset: 0x200, raw_size: 0x1000, characteristics: 0x60000020,
    };
    let synthetic = format::synthesize_mapped_image(
        &vec![0; 0x2000], IMAGE_BASE, &[section], Some(machine), false, Some(0x1000), None,
    ).unwrap();
    let mut image = Image::from_mapped(synthetic.data, IMAGE_BASE, Vec::new()).unwrap();
    image.write_bytes(0x1000, code).unwrap();
    let pointer_size = image.pointer_size();
    image.write_pointer(IAT_RVA as usize, pointer_size, 0x7010).unwrap();
    image.set_data_directory(PE_DIRECTORY_ENTRY_IAT, IAT_RVA, 2 * pointer_size as u32).unwrap();
    image
}

fn exports() -> ExportMap {
    ExportMap::new(vec![ExportTable {
        module_name: "fixture.dll".into(), image_base: 0x7000, image_size: 0x100, time_date_stamp: None,
        symbols: [("Target", 1, 0x10), ("Additional", 2, 0x20)].into_iter().map(|(name, ordinal, rva)| ExportSymbol {
            module_name: "fixture.dll".into(), name: Some(name.into()), names: vec![name.into()],
            ordinal, rva, address: 0x7000 + rva as u64, forwarder: None,
        }).collect(),
    }])
}

fn direct_call(reference_rva: u32, name: &str, ordinal: u32, target_address: u64) -> ImportCodeReference {
    ImportCodeReference {
        reference_rva, kind: ImportCodeReferenceKind::DirectCall, target_address, export_address: target_address,
        iat_rva: None, module_name: "fixture.dll".into(), name: Some(name.into()), ordinal,
    }
}

fn write_direct_call(image: &mut Image, machine: &str, reference: &ImportCodeReference) {
    let displacement = reference.target_address as i64 - (IMAGE_BASE + reference.reference_rva as u64) as i64;
    let offset = reference.reference_rva as usize;
    if machine == "arm64" {
        let instruction = 0x94000000 | ((displacement / 4) as u32 & 0x03ffffff);
        image.write_u32(offset, instruction).unwrap();
    } else {
        image.write_bytes(offset, &[0xe8]).unwrap();
        image.write_bytes(offset + 1, &((displacement - 5) as i32).to_le_bytes()).unwrap();
    }
}

fn assert_direct_call_slot(image: &Image, machine: &str, reference_rva: u32, expected_iat: u32) {
    let stub_rva = if machine == "arm64" {
        let instruction = image.read_u32_rva(reference_rva).unwrap();
        assert_eq!(instruction & 0xfc000000, 0x94000000);
        reference_rva as i64 + (((instruction & 0x03ffffff) << 6) as i32 >> 4) as i64
    } else {
        let instruction = image.read_rva(reference_rva, 5).unwrap();
        assert_eq!(instruction[0], 0xe8);
        reference_rva as i64 + 5 + i32::from_le_bytes(instruction[1..].try_into().unwrap()) as i64
    } as u32;
    let iat_rva = match machine {
        "arm64" => {
            let stub = image.read_rva(stub_rva, 24).unwrap();
            assert_eq!(&stub[..4], &0x58000090u32.to_le_bytes());
            (u64::from_le_bytes(stub[16..24].try_into().unwrap()) - IMAGE_BASE) as u32
        }
        "x64" => {
            let stub = image.read_rva(stub_rva, 6).unwrap();
            assert_eq!(&stub[..2], &[0xff, 0x25]);
            (stub_rva as i64 + 6 + i32::from_le_bytes(stub[2..].try_into().unwrap()) as i64) as u32
        }
        _ => {
            let stub = image.read_rva(stub_rva, 6).unwrap();
            assert_eq!(&stub[..2], &[0xff, 0x25]);
            u32::from_le_bytes(stub[2..].try_into().unwrap()) - IMAGE_BASE as u32
        }
    };
    assert_eq!(iat_rva, expected_iat, "{machine}");
}

#[test]
fn partial_build_preserves_capture_when_all_imports_are_invalid() {
    for machine in ["x86", "x64", "arm64"] {
        let code: &[u8] = if machine == "arm64" { &[0xc0, 0x03, 0x5f, 0xd6] } else { &[0xc3] };
        let plan = Plan::from_image(mapped_image(machine, code), &exports(), Default::default(), None).unwrap();
        let mut model = plan.model.clone();
        model.set_function_validity(IAT_RVA, false).unwrap();
        assert!(matches!(plan.build(&model, BuildPolicy::default()), Err(super::imports::Error::PartialOutput)));
        assert!(matches!(plan.rebuild(&model, Default::default()), Err(super::imports::Error::Imports(ImportError::EmptyImportModel))));

        let result = plan.build(&model, BuildPolicy {
            allow_partial: true, sanitize_headers: false, preserve_resources: false, ..Default::default()
        }).unwrap();
        assert_eq!(result.status, BuildStatus::Partial);
        assert_eq!(result.image.data(), plan.input.file.data());
        assert!(result.changes.is_empty());
        assert!(result.diagnostics.iter().any(|item| item.stage == crate::pe::diagnostic::Stage::Imports));
    }
}

#[test]
fn build_preserves_existing_slots_and_adds_direct_only_imports() {
    for machine in ["x86", "x64", "arm64"] {
        let code: &[u8] = if machine == "arm64" { &[0xc0, 0x03, 0x5f, 0xd6] } else { &[0xc3] };
        let mut image = mapped_image(machine, code);
        let references = vec![direct_call(0x1020, "Target", 1, 0x7010), direct_call(0x1030, "Additional", 2, 0x7020)];
        for reference in &references { write_direct_call(&mut image, machine, reference); }
        let mut plan = Plan::from_image(image, &exports(), Default::default(), None).unwrap();
        plan.direct_references = references;
        let report = plan.rebuild(&plan.model, Default::default()).unwrap();
        assert_eq!(report.direct_imports_added, 1, "{machine}");
        assert_eq!(report.patched_code_references, 2, "{machine}");

        let result = plan.build(&plan.model, BuildPolicy::default()).unwrap();
        assert_eq!(result.status, BuildStatus::Complete, "{machine}");
        let descriptors = result.image.imports().unwrap();
        assert_eq!(descriptors.len(), 2, "{machine}");
        assert_eq!(descriptors[0].first_thunk_rva, Some(IAT_RVA));
        assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("Target"));
        assert_eq!(descriptors[1].imports[0].name.as_deref(), Some("Additional"));
        let additional_slot = descriptors[1].first_thunk_rva.unwrap();
        assert!(additional_slot >= 0x2000);
        let iat = result.image.data_directory(PE_DIRECTORY_ENTRY_IAT).unwrap();
        assert_eq!(iat.virtual_address, IAT_RVA);
        assert_eq!(iat.virtual_address + iat.size, additional_slot + 2 * result.image.pointer_size() as u32);
        assert_direct_call_slot(&result.image, machine, 0x1020, IAT_RVA);
        assert_direct_call_slot(&result.image, machine, 0x1030, additional_slot);
        assert_eq!(result.image.read_rva(0x1000, code.len()).unwrap(), code);
    }
}

#[test]
fn build_recovers_direct_calls_without_an_existing_iat() {
    for machine in ["x86", "x64", "arm64"] {
        let code: &[u8] = if machine == "arm64" { &[0xc0, 0x03, 0x5f, 0xd6] } else { &[0xc3] };
        let mut image = mapped_image(machine, code);
        image.set_data_directory(PE_DIRECTORY_ENTRY_IAT, 0, 0).unwrap();
        image.write_pointer(IAT_RVA as usize, image.pointer_size(), 0).unwrap();
        let reference = direct_call(0x1020, "Target", 1, 0x7010);
        write_direct_call(&mut image, machine, &reference);
        let mut plan = Plan::from_image(image, &exports(), Default::default(), None).unwrap();
        assert_eq!(plan.model.function_count(), 0);
        plan.direct_references = vec![reference];
        let result = plan.build(&plan.model, BuildPolicy::default()).unwrap();
        assert_eq!(result.status, BuildStatus::Complete, "{machine}");
        let descriptors = result.image.imports().unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].imports[0].name.as_deref(), Some("Target"));
        assert_direct_call_slot(&result.image, machine, 0x1020, descriptors[0].first_thunk_rva.unwrap());
    }
}

#[test]
fn build_preserves_sparse_interleaved_and_filtered_iat_slots() {
    for machine in ["x86", "x64", "arm64"] {
        let code: &[u8] = if machine == "arm64" { &[0xc0, 0x03, 0x5f, 0xd6] } else { &[0xc3] };
        let mut image = mapped_image(machine, code);
        let pointer_size = image.pointer_size();
        let stride = pointer_size as u32;
        let sentinel = 0x12345678u64;
        for index in 1..7 {
            image.write_pointer((IAT_RVA + index * stride) as usize, pointer_size, sentinel).unwrap();
        }
        let plan = Plan::from_image(image, &exports(), Default::default(), None).unwrap();
        for interleaved in [false, true] {
            let mut model = plan.model.clone();
            model.add_function("fixture.dll", IAT_RVA + 4 * stride, ImportTarget::Ordinal(9), false, false).unwrap();
            model.add_function("fixture.dll", IAT_RVA + 2 * stride, ImportTarget::Ordinal(2), true, false).unwrap();
            model.add_function("fixture.dll", IAT_RVA + 3 * stride, ImportTarget::Ordinal(3), true, false).unwrap();
            if interleaved {
                model.add_module("other.dll", IAT_RVA + stride, 5).unwrap();
                model.add_function("other.dll", IAT_RVA + stride, ImportTarget::Ordinal(4), true, false).unwrap();
                model.add_function("other.dll", IAT_RVA + 5 * stride, ImportTarget::Ordinal(5), true, false).unwrap();
            }
            let result = plan.build(&model, BuildPolicy { allow_partial: true, ..Default::default() }).unwrap();
            let descriptors = result.image.imports().unwrap();
            assert_eq!(descriptors.len(), if interleaved { 4 } else { 2 }, "{machine}");
            assert_eq!(descriptors[0].first_thunk_rva, Some(IAT_RVA));
            assert_eq!(descriptors[0].imports.len(), 1);
            assert_eq!(descriptors[1].first_thunk_rva, Some(IAT_RVA + 2 * stride));
            assert_eq!(descriptors[1].imports.len(), 2);
            assert_eq!(descriptors[0].dll_name, descriptors[1].dll_name);
            for index in [4, 6] {
                assert_eq!(result.image.read_rva(IAT_RVA + index * stride, pointer_size).unwrap(), &sentinel.to_le_bytes()[..pointer_size], "{machine}");
            }
            if !interleaved {
                assert_eq!(result.image.read_rva(IAT_RVA + stride, pointer_size).unwrap(), &sentinel.to_le_bytes()[..pointer_size]);
            } else {
                assert_eq!(descriptors[2].first_thunk_rva, Some(IAT_RVA + stride));
                assert_eq!(descriptors[3].first_thunk_rva, Some(IAT_RVA + 5 * stride));
            }
            let iat = result.image.data_directory(PE_DIRECTORY_ENTRY_IAT).unwrap();
            assert_eq!(iat.virtual_address, IAT_RVA);
            assert_eq!(iat.size, (if interleaved { 6 } else { 4 }) * stride);
        }
    }
}

#[test]
fn build_rejects_overlapping_preserved_slots_even_with_partial_output() {
    for machine in ["x86", "x64", "arm64"] {
        let plan = Plan::from_image(mapped_image(machine, &[]), &exports(), Default::default(), None).unwrap();
        for offset in [0, 1, plan.input.pointer_size as u32 - 1] {
            let mut model = plan.model.clone();
            model.add_module("other.dll", IAT_RVA + offset, 1).unwrap();
            model.add_function("other.dll", IAT_RVA + offset, ImportTarget::Ordinal(2), true, false).unwrap();
            let error = plan.build(&model, BuildPolicy { allow_partial: true, ..Default::default() }).unwrap_err();
            assert!(matches!(error, super::imports::Error::Imports(ImportError::InvalidPreservedIatLayout { .. })), "{machine}: {error}");
        }
    }
}

#[test]
fn build_preserves_iat_slots_referenced_by_indirect_calls() {
    let cases: [(&str, &[u8]); 3] = [
        ("x86", &[0xff, 0x15, 0x00, 0x11, 0x40, 0x00, 0xc3]),
        ("x64", &[0xff, 0x15, 0xfa, 0x00, 0x00, 0x00, 0xc3]),
        // LDR X16, [PC + 0x100]; BLR X16; RET.
        ("arm64", &[0x10, 0x08, 0x00, 0x58, 0x00, 0x02, 0x3f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6]),
    ];
    for (machine, code) in cases {
        let plan = Plan::from_image(mapped_image(machine, code), &exports(), Default::default(), None).unwrap();
        assert_eq!(plan.model.function_count(), 1, "{machine}");
        assert!(plan.direct_references.is_empty(), "{machine}");
        let result = plan.build(&plan.model, BuildPolicy::default()).unwrap();
        assert_eq!(result.status, BuildStatus::Complete, "{machine}");
        let descriptors = result.image.imports().unwrap();
        assert_eq!(descriptors.len(), 1, "{machine}");
        assert_eq!(descriptors[0].first_thunk_rva, Some(IAT_RVA), "{machine}");
        let iat = result.image.data_directory(PE_DIRECTORY_ENTRY_IAT).unwrap();
        assert_eq!(iat.virtual_address, IAT_RVA);
        assert_eq!(iat.size, result.image.pointer_size() as u32);
        let import = &descriptors[0].imports[0];
        assert_eq!(import.name.as_deref(), Some("Target"));
        assert_eq!(import.import_address_table_rva, Some(IAT_RVA));
        assert_eq!(import.raw_address_value, Some(import.raw_lookup_value));
        assert_ne!(import.raw_address_value, Some(0x7010));
        assert_eq!(result.image.read_rva(0x1000, code.len()).unwrap(), code, "{machine}");

        // Emulate loader resolution at a different export VA. The original call must see this slot.
        let mut loaded = result.image.to_mapped().unwrap();
        let pointer_size = loaded.pointer_size();
        loaded.write_pointer(import.import_address_table_rva.unwrap() as usize, pointer_size, 0x9010).unwrap();
        assert_eq!(loaded.read_rva(IAT_RVA, pointer_size).unwrap(), &0x9010u64.to_le_bytes()[..pointer_size]);
    }
}
