use super::*;
use super::code::{self, ImportCodeMachine};
use super::issues::*;
use super::model::ImportModel;
use super::resolver::*;
use super::types::*;
use super::util::*;

pub fn rebuild_imports(
    image: &[u8],
    model: &ImportModel,
    options: RebuildImportsOptions,
) -> Result<Vec<u8>, ImportError> {
    Ok(rebuild_imports_with_report(image, model, options)?.image)
}

pub fn rebuild_imports_with_report(
    image: &[u8],
    model: &ImportModel,
    options: RebuildImportsOptions,
) -> Result<RebuildImportsReport, ImportError> {
    let mut image = Image::parse(image.to_vec())?;
    let pointer_size = image.pointer_size();
    let patchable_code_references = options
        .code_references
        .iter()
        .filter(|reference| reference.kind.is_patchable_direct_branch())
        .count();
    let mut layout_model = model.clone();
    let mut additional_model = ImportModel::default();
    // Direct-only imports have no captured slot to preserve. Keep their new tables separate.
    let direct_model = match options.write_mode {
        ImportWriteMode::NewIat => &mut layout_model,
        ImportWriteMode::PreserveIatSlots => &mut additional_model,
    };
    let direct_imports_added = add_direct_code_reference_imports(
        direct_model,
        import_model_identities(model),
        &options.code_references,
        pointer_size,
    )?;
    let layout = ImportLayout::new(&layout_model, &additional_model, pointer_size, options.write_mode, options.import_by_ordinal)?;
    let section = image.append_section_with_characteristics(
        &options.section_name,
        layout.size,
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    )?;
    let blob = layout.write_blob(section.virtual_address, pointer_size)?;

    image.write_bytes(section.raw_offset, &blob)?;

    if options.write_mode == ImportWriteMode::PreserveIatSlots {
        layout.write_preserved_iat_slots(&mut image, section.virtual_address, pointer_size)?;
    }

    let import_size = u32::try_from(blob.len())
        .map_err(|_| ImportError::Overflow("converting import directory size to u32"))?;
    image.set_data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT, section.virtual_address, import_size)?;
    if options.clear_bound_imports {
        image.clear_data_directory_if_present(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)?;
    }
    if options.clear_delay_imports {
        image.clear_data_directory_if_present(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;
    }

    let (iat_rva, iat_size) = match layout.iat_directory(section.virtual_address, pointer_size)? {
        Some((rva, size)) => {
            image.set_data_directory(IMAGE_DIRECTORY_ENTRY_IAT, rva, size)?;
            (rva, size)
        }
        None => {
            image.set_data_directory(IMAGE_DIRECTORY_ENTRY_IAT, 0, 0)?;
            (0, 0)
        }
    };
    let code_patch_report = patch_direct_code_references(
        &mut image,
        &layout,
        section.virtual_address,
        &options.code_references,
        &options.code_stub_section_name,
        pointer_size,
    )?;

    Ok(RebuildImportsReport {
        image: image.into_data(),
        import_section_rva: section.virtual_address,
        import_section_size: import_size,
        iat_rva,
        iat_size,
        code_stub_section_rva: code_patch_report.section_rva,
        code_stub_section_size: code_patch_report.section_size,
        direct_imports_added,
        patchable_code_references,
        patched_code_references: code_patch_report.patched_references,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct CodePatchReport {
    section_rva: Option<u32>,
    section_size: u32,
    patched_references: usize,
}

fn add_direct_code_reference_imports(
    model: &mut ImportModel,
    mut identities: BTreeSet<ImportIdentity>,
    references: &[ImportCodeReference],
    pointer_size: usize,
) -> Result<usize, ImportError> {
    validate_pointer_size(pointer_size)?;

    let mut synthetic_rva = first_synthetic_thunk_rva(model, references, pointer_size)?;
    let mut added = 0usize;

    for reference in references.iter().filter(|reference| reference.kind.is_patchable_direct_branch()) {
        let identity = import_identity_from_code_reference(reference)?;
        if identities.contains(&identity) {
            continue;
        }

        while model.has_thunk_rva(synthetic_rva) {
            synthetic_rva = next_thunk_rva(synthetic_rva, pointer_size)?;
        }

        let target = import_target_from_code_reference(reference)?;
        model.upsert_module_range(&reference.module_name, synthetic_rva, synthetic_rva, pointer_size)?;
        model.add_function_with_evidence(
            &reference.module_name,
            synthetic_rva,
            target,
            true,
            false,
            vec![ImportEvidence::code_reference(
                reference,
                ImportEvidenceKind::DirectBranch,
                Some(synthetic_rva),
            )],
        )?;
        identities.insert(identity);
        synthetic_rva = next_thunk_rva(synthetic_rva, pointer_size)?;
        added += 1;
    }

    Ok(added)
}

fn import_model_identities(model: &ImportModel) -> BTreeSet<ImportIdentity> {
    model
        .modules
        .values()
        .flat_map(|module| {
            module.thunks.values().filter(|thunk| thunk.valid).map(|thunk| {
                import_identity_from_target(&module.name, &thunk.target)
            })
        })
        .collect()
}

fn first_synthetic_thunk_rva(
    model: &ImportModel,
    references: &[ImportCodeReference],
    pointer_size: usize,
) -> Result<u32, ImportError> {
    let max_thunk_rva = model
        .modules
        .values()
        .flat_map(|module| module.thunks.keys())
        .copied()
        .max()
        .unwrap_or(0);
    let max_reference_rva = references
        .iter()
        .map(|reference| reference.reference_rva)
        .max()
        .unwrap_or(0);
    let max_rva = max_thunk_rva.max(max_reference_rva);

    next_thunk_rva(max_rva, pointer_size)
}

fn next_thunk_rva(rva: u32, pointer_size: usize) -> Result<u32, ImportError> {
    let pointer_size = u32::try_from(pointer_size)
        .map_err(|_| ImportError::Overflow("converting pointer size to u32"))?;
    let next = rva
        .checked_add(pointer_size)
        .ok_or(ImportError::Overflow("allocating synthetic import thunk RVA"))?;

    Ok(align_up_u32(next, pointer_size)?)
}

fn align_up_u32(value: u32, alignment: u32) -> Result<u32, ImportError> {
    if alignment == 0 {
        return Err(ImportError::InvalidPointerSize(alignment as usize));
    }

    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .ok_or(ImportError::Overflow("aligning synthetic import thunk RVA"))
}

fn patch_direct_code_references(
    image: &mut Image,
    layout: &ImportLayout,
    import_section_rva: u32,
    references: &[ImportCodeReference],
    section_name: &str,
    pointer_size: usize,
) -> Result<CodePatchReport, ImportError> {
    let direct_references = references
        .iter()
        .filter(|reference| reference.kind.is_patchable_direct_branch())
        .collect::<Vec<_>>();
    if direct_references.is_empty() {
        return Ok(CodePatchReport::default());
    }

    let machine = ImportCodeMachine::from_pe_machine(image.machine())?;
    let image_base = image.image_base()?;
    let iat_slots = layout.iat_slot_map(import_section_rva, pointer_size)?;
    let identities = direct_references
        .iter()
        .map(|reference| import_identity_from_code_reference(reference))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let stub_size = code_stub_size(machine);
    let section_size = checked_mul(identities.len(), stub_size, "sizing import code stubs")?;
    let section = image.append_section_with_characteristics(
        section_name,
        section_size,
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    )?;
    let mut stubs = BTreeMap::new();
    let mut blob = vec![0u8; section_size];

    for (index, identity) in identities.iter().enumerate() {
        let Some(iat_rva) = iat_slots.get(identity).copied() else {
            continue;
        };
        let stub_offset = index * stub_size;
        let stub_rva = rva_from_offset(section.virtual_address, stub_offset)?;
        write_code_stub(
            &mut blob[stub_offset..stub_offset + stub_size],
            machine,
            image_base,
            stub_rva,
            iat_rva,
        )?;
        stubs.insert(identity.clone(), stub_rva);
    }

    image.write_bytes(section.raw_offset, &blob)?;

    let mut patched_references = 0usize;
    for reference in direct_references {
        let identity = import_identity_from_code_reference(reference)?;
        let Some(stub_rva) = stubs.get(&identity).copied() else {
            continue;
        };
        patch_direct_code_reference(image, image_base, machine, reference, stub_rva)?;
        patched_references += 1;
    }

    Ok(CodePatchReport {
        section_rva: Some(section.virtual_address),
        section_size: u32::try_from(section_size)
            .map_err(|_| ImportError::Overflow("converting import code stub size to u32"))?,
        patched_references,
    })
}

fn patch_direct_code_reference(
    image: &mut Image,
    image_base: u64,
    machine: ImportCodeMachine,
    reference: &ImportCodeReference,
    stub_rva: u32,
) -> Result<(), ImportError> {
    match machine {
        ImportCodeMachine::X86 | ImportCodeMachine::X64 => {
            let opcode = match reference.kind {
                ImportCodeReferenceKind::DirectCall => 0xe8,
                ImportCodeReferenceKind::DirectJump => 0xe9,
                _ => return Ok(()),
            };
            let reference_va = image_base
                .checked_add(reference.reference_rva as u64)
                .ok_or(ImportError::Overflow("computing direct code reference VA"))?;
            let stub_va = image_base
                .checked_add(stub_rva as u64)
                .ok_or(ImportError::Overflow("computing import code stub VA"))?;
            let displacement = rel32_displacement(reference_va, 5, stub_va)
                .ok_or(ImportError::CodeReferencePatchOutOfRange {
                    reference_rva: reference.reference_rva,
                    stub_rva,
                })?;
            let mut patch = [0u8; 5];

            patch[0] = opcode;
            patch[1..5].copy_from_slice(&displacement.to_le_bytes());
            image.write_bytes_rva(reference.reference_rva, &patch)?;
        }
        ImportCodeMachine::Arm64 => {
            let instruction = arm64_direct_branch_instruction(reference, image_base, stub_rva)?;
            image.write_u32_rva(reference.reference_rva, instruction)?;
        }
    }

    Ok(())
}

fn arm64_direct_branch_instruction(
    reference: &ImportCodeReference,
    image_base: u64,
    stub_rva: u32,
) -> Result<u32, ImportError> {
    let opcode = match reference.kind {
        ImportCodeReferenceKind::DirectCall => code::ARM64_BL_OPCODE,
        ImportCodeReferenceKind::DirectJump => code::ARM64_B_OPCODE,
        _ => return Err(ImportError::Overflow("encoding unsupported ARM64 code reference patch")),
    };
    let reference_va = image_base
        .checked_add(reference.reference_rva as u64)
        .ok_or(ImportError::Overflow("computing ARM64 direct code reference VA"))?;
    let stub_va = image_base
        .checked_add(stub_rva as u64)
        .ok_or(ImportError::Overflow("computing ARM64 import code stub VA"))?;
    let displacement = stub_va as i128 - reference_va as i128;
    if displacement % 4 != 0 {
        return Err(ImportError::CodeReferencePatchMisaligned {
            reference_rva: reference.reference_rva,
            stub_rva,
        });
    }
    if !(-(1i128 << 27)..(1i128 << 27)).contains(&displacement) {
        return Err(ImportError::CodeReferencePatchOutOfRange {
            reference_rva: reference.reference_rva,
            stub_rva,
        });
    }

    Ok(opcode | (((displacement / 4) as i32 as u32) & code::ARM64_BRANCH_IMM26_MASK))
}

fn write_code_stub(
    blob: &mut [u8],
    machine: ImportCodeMachine,
    image_base: u64,
    stub_rva: u32,
    iat_rva: u32,
) -> Result<(), ImportError> {
    let stub_va = image_base
        .checked_add(stub_rva as u64)
        .ok_or(ImportError::Overflow("computing import code stub VA"))?;
    let iat_va = image_base
        .checked_add(iat_rva as u64)
        .ok_or(ImportError::Overflow("computing import thunk VA"))?;

    match machine {
        ImportCodeMachine::X86 => {
            let iat_va = u32::try_from(iat_va)
                .map_err(|_| ImportError::Overflow("encoding x86 import code stub"))?;
            blob[0] = 0xff;
            blob[1] = 0x25;
            blob[2..6].copy_from_slice(&iat_va.to_le_bytes());
        }
        ImportCodeMachine::X64 => {
            let displacement = rel32_displacement(stub_va, 6, iat_va)
                .ok_or(ImportError::CodeReferencePatchOutOfRange {
                    reference_rva: stub_rva,
                    stub_rva: iat_rva,
                })?;
            blob[0] = 0xff;
            blob[1] = 0x25;
            blob[2..6].copy_from_slice(&displacement.to_le_bytes());
        }
        ImportCodeMachine::Arm64 => {
            let register = 16u32;
            let ldr_literal = code::ARM64_LDR_LITERAL_64_OPCODE | (4 << 5) | register;
            let ldr_pointer = code::ARM64_LDR_UNSIGNED_64_OPCODE | (register << 5) | register;
            let br = code::ARM64_BR_OPCODE | (register << 5);

            blob[0..4].copy_from_slice(&ldr_literal.to_le_bytes());
            blob[4..8].copy_from_slice(&ldr_pointer.to_le_bytes());
            blob[8..12].copy_from_slice(&br.to_le_bytes());
            blob[12..16].copy_from_slice(&ARM64_NOP.to_le_bytes());
            blob[16..24].copy_from_slice(&iat_va.to_le_bytes());
        }
    }

    Ok(())
}

fn code_stub_size(machine: ImportCodeMachine) -> usize {
    match machine {
        ImportCodeMachine::X86 | ImportCodeMachine::X64 => 6,
        ImportCodeMachine::Arm64 => 24,
    }
}

fn rel32_displacement(source_va: u64, instruction_size: u64, target_va: u64) -> Option<i32> {
    let instruction_end = source_va.checked_add(instruction_size)?;
    let displacement = target_va as i128 - instruction_end as i128;
    i32::try_from(displacement).ok()
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ImportIdentity {
    module_name: String,
    target: ImportTargetKey,
}

fn import_identity_from_code_reference(reference: &ImportCodeReference) -> Result<ImportIdentity, ImportError> {
    Ok(import_identity_from_target(
        &reference.module_name,
        &import_target_from_code_reference(reference)?,
    ))
}

fn import_identity_from_target(module_name: &str, target: &ImportTarget) -> ImportIdentity {
    ImportIdentity {
        module_name: module_key(module_name),
        target: import_target_key(target),
    }
}

#[derive(Clone)]
struct ImportLayout {
    modules: Vec<ImportModuleLayout>,
    size: usize,
}

#[derive(Clone)]
struct ImportModuleLayout {
    name: String,
    first_thunk: u32,
    descriptor_offset: usize,
    lookup_table_offset: usize,
    address_table_offset: Option<usize>,
    module_name_offset: usize,
    thunks: Vec<ImportThunkLayout>,
}

#[derive(Clone)]
pub(super) struct ImportThunkLayout {
    pub(super) rva: u32,
    pub(super) target: ImportTarget,
    pub(super) import_name_offset: Option<usize>,
}

fn rebuild_import_target(target: &ImportTarget, import_by_ordinal: bool) -> ImportTarget {
    match target {
        ImportTarget::Name { ordinal: Some(ordinal), .. } if import_by_ordinal => ImportTarget::Ordinal(*ordinal),
        _ => target.clone(),
    }
}

struct ImportRun<'a> {
    name: &'a str,
    thunks: Vec<&'a ImportThunk>,
    placement: ImportWriteMode,
}

fn import_runs<'a>(model: &'a ImportModel, additional_model: &'a ImportModel, pointer_size: usize, write_mode: ImportWriteMode) -> Result<Vec<ImportRun<'a>>, ImportError> {
    let modules = model.valid_modules().into_iter().map(|module| (module, write_mode))
        .chain(additional_model.valid_modules().into_iter().map(|module| (module, ImportWriteMode::NewIat)));
    let mut runs = Vec::new();
    let mut preserved_slots = BTreeSet::new();
    for (module, placement) in modules {
        let thunks = module.thunks.values().filter(|thunk| thunk.valid).collect::<Vec<_>>();
        let mut first = 0;
        if placement == ImportWriteMode::PreserveIatSlots {
            for (index, thunk) in thunks.iter().enumerate() {
                let end = rva_from_offset(thunk.rva, pointer_size)?;
                let overlap_start = thunk.rva.saturating_sub(pointer_size as u32 - 1);
                if preserved_slots.range(overlap_start..end).next().is_some() {
                    return Err(ImportError::InvalidPreservedIatLayout { module_name: module.name.clone() });
                }
                preserved_slots.insert(thunk.rva);
                if index > 0 && rva_from_offset(thunks[index - 1].rva, pointer_size)? != thunk.rva {
                    runs.push(ImportRun { name: &module.name, thunks: thunks[first..index].to_vec(), placement });
                    first = index;
                }
            }
        }
        runs.push(ImportRun { name: &module.name, thunks: thunks[first..].to_vec(), placement });
    }
    Ok(runs)
}

impl ImportLayout {
    fn new(
        model: &ImportModel,
        additional_model: &ImportModel,
        pointer_size: usize,
        write_mode: ImportWriteMode,
        import_by_ordinal: bool,
    ) -> Result<Self, ImportError> {
        // Each preserved run gets its own terminated ILT, including repeated DLL names.
        let modules = import_runs(model, additional_model, pointer_size, write_mode)?;
        if modules.is_empty() {
            return Err(ImportError::EmptyImportModel);
        }

        let mut cursor = checked_mul(modules.len() + 1, IMAGE_IMPORT_DESCRIPTOR_SIZE, "sizing import descriptors")?;
        let mut layouts = Vec::with_capacity(modules.len());

        for (index, module) in modules.iter().enumerate() {
            let valid_thunks = &module.thunks;
            let thunk_table_size = checked_mul(valid_thunks.len() + 1, pointer_size, "sizing import thunk table")?;
            let descriptor_offset = index * IMAGE_IMPORT_DESCRIPTOR_SIZE;
            let lookup_table_offset = cursor;
            cursor = checked_add(cursor, thunk_table_size, "placing import lookup table")?;

            let address_table_offset = if module.placement == ImportWriteMode::NewIat {
                let offset = cursor;
                cursor = checked_add(cursor, thunk_table_size, "placing import address table")?;
                Some(offset)
            } else {
                None
            };

            let module_name_offset = cursor;
            cursor = checked_add(cursor, module.name.len() + 1, "placing module name")?;
            cursor = align_2(cursor)?;

            let mut thunk_layouts = Vec::with_capacity(valid_thunks.len());
            for thunk in valid_thunks {
                let target = rebuild_import_target(&thunk.target, import_by_ordinal);
                let import_name_offset = match &target {
                    ImportTarget::Name { name, .. } => {
                        let offset = cursor;
                        cursor = checked_add(cursor, 2 + name.len() + 1, "placing import name")?;
                        cursor = align_2(cursor)?;
                        Some(offset)
                    }
                    ImportTarget::Ordinal(_) | ImportTarget::Unknown(_) => None,
                };

                thunk_layouts.push(ImportThunkLayout {
                    rva: thunk.rva,
                    target,
                    import_name_offset,
                });
            }

            layouts.push(ImportModuleLayout {
                name: module.name.to_string(),
                first_thunk: valid_thunks[0].rva,
                descriptor_offset,
                lookup_table_offset,
                address_table_offset,
                module_name_offset,
                thunks: thunk_layouts,
            });
        }

        Ok(Self {
            modules: layouts,
            size: cursor,
        })
    }

    fn write_blob(
        &self,
        base_rva: u32,
        pointer_size: usize,
    ) -> Result<Vec<u8>, ImportError> {
        let mut blob = vec![0u8; self.size];

        for module in &self.modules {
            let original_first_thunk = rva_from_offset(base_rva, module.lookup_table_offset)?;
            let first_thunk = match module.address_table_offset {
                Some(offset) => rva_from_offset(base_rva, offset)?,
                None => module.first_thunk,
            };
            let module_name_rva = rva_from_offset(base_rva, module.module_name_offset)?;

            write_u32(&mut blob, module.descriptor_offset, original_first_thunk)?;
            write_u32(&mut blob, module.descriptor_offset + 12, module_name_rva)?;
            write_u32(&mut blob, module.descriptor_offset + 16, first_thunk)?;
            write_cstr(&mut blob, module.module_name_offset, &module.name)?;

            for (index, thunk) in module.thunks.iter().enumerate() {
                let value = thunk_value(thunk, base_rva, pointer_size)?;
                let lookup_offset = module.lookup_table_offset + index * pointer_size;
                write_pointer(&mut blob, lookup_offset, pointer_size, value)?;

                if let Some(address_table_offset) = module.address_table_offset {
                    write_pointer(&mut blob, address_table_offset + index * pointer_size, pointer_size, value)?;
                }

                if let (Some(import_name_offset), ImportTarget::Name { hint, name, .. }) =
                    (thunk.import_name_offset, &thunk.target)
                {
                    write_u16(&mut blob, import_name_offset, *hint)?;
                    write_cstr(&mut blob, import_name_offset + 2, name)?;
                }
            }
        }

        Ok(blob)
    }

    fn write_preserved_iat_slots(
        &self,
        image: &mut Image,
        base_rva: u32,
        pointer_size: usize,
    ) -> Result<(), ImportError> {
        for module in self.modules.iter().filter(|module| module.address_table_offset.is_none()) {
            for thunk in &module.thunks {
                let value = thunk_value(thunk, base_rva, pointer_size)?;
                image.write_pointer_rva(thunk.rva, pointer_size, value)?;
            }

            // The ILT terminates this run. The next IAT-sized bytes may belong to another DLL or unrelated data.
        }

        Ok(())
    }

    fn iat_directory(
        &self,
        base_rva: u32,
        pointer_size: usize,
    ) -> Result<Option<(u32, u32)>, ImportError> {
        // The loader-written range must include captured slots, not just newly allocated tables.
        let mut range: Option<(u32, u32)> = None;
        for module in &self.modules {
            let start = match module.address_table_offset {
                Some(offset) => rva_from_offset(base_rva, offset)?,
                None => module.first_thunk,
            };
            let terminator = usize::from(module.address_table_offset.is_some());
            let size = checked_mul(module.thunks.len() + terminator, pointer_size, "sizing import address table")?;
            let end = rva_from_offset(start, size)?;
            range = Some(match range {
                Some((first, last)) => (first.min(start), last.max(end)),
                None => (start, end),
            });
        }
        Ok(range.map(|(start, end)| (start, end - start)))
    }

    fn iat_slot_map(
        &self,
        base_rva: u32,
        pointer_size: usize,
    ) -> Result<BTreeMap<ImportIdentity, u32>, ImportError> {
        let mut slots = BTreeMap::new();

        for module in &self.modules {
            for (index, thunk) in module.thunks.iter().enumerate() {
                let rva = match module.address_table_offset {
                    Some(address_table_offset) => {
                        let offset = checked_add(
                            address_table_offset,
                            checked_mul(index, pointer_size, "locating rebuilt IAT slot")?,
                            "locating rebuilt IAT slot",
                        )?;
                        rva_from_offset(base_rva, offset)?
                    }
                    None => thunk.rva,
                };

                slots
                    .entry(import_identity_from_target(&module.name, &thunk.target))
                    .or_insert(rva);
            }
        }

        Ok(slots)
    }
}
