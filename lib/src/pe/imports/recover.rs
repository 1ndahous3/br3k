use super::*;
use super::code::{self, ImportSymbolResolver, MappedThunkResolver};
use super::model::ImportModel;
use super::resolver::*;
use super::types::*;
use super::util::*;
use crate::pe::embedded;

pub fn recover_iat(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    pointer_size: usize,
    address_resolve_mode: ImportAddressResolveMode,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    recover_iat_with_options(
        model,
        iat_rva,
        iat_data,
        pointer_size,
        ImportAddressResolveOptions {
            mode: address_resolve_mode,
            resolve_forwarders: false,
            api_set_map: None,
        },
        exports,
    )
}

pub fn recover_iat_with_options(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    recover_iat_with_recovery_options(
        model,
        iat_rva,
        iat_data,
        pointer_size,
        RecoverIatOptions {
            address_resolve_options,
            keep_unresolved: false,
        },
        exports,
    )
}

pub fn recover_iat_with_recovery_options(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    pointer_size: usize,
    options: RecoverIatOptions,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    recover_iat_with_evidence(
        model,
        iat_rva,
        iat_data,
        pointer_size,
        options,
        ImportEvidenceKind::IatDirectory,
        exports,
    )
}

pub fn recover_iat_with_evidence(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    pointer_size: usize,
    options: RecoverIatOptions,
    evidence_kind: ImportEvidenceKind,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    let address_resolve_options = options.address_resolve_options.clone();
    let resolver = ImportAddressResolver::new(exports, address_resolve_options.clone());
    recover_iat_with_symbol_resolver(
        model,
        iat_rva,
        iat_data,
        pointer_size,
        options.keep_unresolved,
        evidence_kind,
        &address_resolve_options,
        &resolver,
    )
}

pub fn recover_iat_with_traced_thunks(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    mapped_image_data: &[u8],
    image_base: Option<u64>,
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    max_depth: usize,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    recover_iat_with_traced_thunks_and_recovery_options(
        model,
        iat_rva,
        iat_data,
        mapped_image_data,
        image_base,
        pointer_size,
        RecoverIatOptions {
            address_resolve_options,
            keep_unresolved: false,
        },
        max_depth,
        exports,
    )
}

pub fn recover_iat_with_traced_thunks_and_recovery_options(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    mapped_image_data: &[u8],
    image_base: Option<u64>,
    pointer_size: usize,
    options: RecoverIatOptions,
    max_depth: usize,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    recover_iat_with_traced_thunks_and_evidence(
        model,
        iat_rva,
        iat_data,
        mapped_image_data,
        image_base,
        pointer_size,
        options,
        max_depth,
        ImportEvidenceKind::ThunkTrace,
        exports,
    )
}

pub fn recover_iat_with_traced_thunks_and_evidence(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    mapped_image_data: &[u8],
    image_base: Option<u64>,
    pointer_size: usize,
    options: RecoverIatOptions,
    max_depth: usize,
    evidence_kind: ImportEvidenceKind,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    let address_resolve_options = options.address_resolve_options.clone();
    let resolver = MappedThunkResolver::new(
        mapped_image_data,
        image_base,
        pointer_size,
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options.clone()),
    )?;

    recover_iat_with_symbol_resolver(
        model,
        iat_rva,
        iat_data,
        pointer_size,
        options.keep_unresolved,
        evidence_kind,
        &address_resolve_options,
        &resolver,
    )
}

fn recover_iat_with_symbol_resolver<R: ImportSymbolResolver>(
    model: &mut ImportModel,
    iat_rva: u32,
    iat_data: &[u8],
    pointer_size: usize,
    keep_unresolved: bool,
    evidence_kind: ImportEvidenceKind,
    address_resolve_options: &ImportAddressResolveOptions,
    resolver: &R,
) -> Result<usize, ImportError> {
    validate_pointer_size(pointer_size)?;
    if iat_data.len() % pointer_size != 0 {
        return Err(ImportError::InvalidIatSize {
            size: iat_data.len(),
            pointer_size,
        });
    }

    let mut slots = Vec::with_capacity(iat_data.len() / pointer_size);

    for (index, chunk) in iat_data.chunks_exact(pointer_size).enumerate() {
        let slot_rva = iat_rva
            .checked_add(
                u32::try_from(checked_mul(index, pointer_size, "computing IAT slot RVA")?)
                    .map_err(|_| ImportError::Overflow("converting IAT slot offset to u32"))?,
            )
            .ok_or(ImportError::Overflow("computing IAT slot RVA"))?;
        let address = read_iat_pointer(chunk, pointer_size)?;

        slots.push(ImportAddressSlot {
            rva: slot_rva,
            address,
        });
    }

    recover_iat_slots_with_symbol_resolver(
        model,
        &slots,
        pointer_size,
        keep_unresolved,
        evidence_kind,
        address_resolve_options,
        resolver,
    )
}

pub fn recover_iat_slots_with_recovery_options(
    model: &mut ImportModel,
    slots: &[ImportAddressSlot],
    pointer_size: usize,
    options: RecoverIatOptions,
    exports: &[&ExportTable],
) -> Result<usize, ImportError> {
    let address_resolve_options = options.address_resolve_options.clone();
    let resolver = ImportAddressResolver::new(exports, address_resolve_options.clone());
    recover_iat_slots_with_symbol_resolver(
        model,
        slots,
        pointer_size,
        options.keep_unresolved,
        ImportEvidenceKind::ManualSlot,
        &address_resolve_options,
        &resolver,
    )
}

fn recover_iat_slots_with_symbol_resolver<R: ImportSymbolResolver>(
    model: &mut ImportModel,
    slots: &[ImportAddressSlot],
    pointer_size: usize,
    keep_unresolved: bool,
    evidence_kind: ImportEvidenceKind,
    address_resolve_options: &ImportAddressResolveOptions,
    resolver: &R,
) -> Result<usize, ImportError> {
    validate_pointer_size(pointer_size)?;

    let mut recovered = 0;
    let mut slot_map = BTreeMap::new();
    let mut modules = BTreeMap::<String, RecoveredImportModule>::new();
    let mut unresolved = Vec::new();

    for slot in slots {
        slot_map.insert(slot.rva, slot.address);
    }

    for (slot_rva, address) in slot_map {
        if address == 0 {
            continue;
        }

        let Some(symbol) = resolver.resolve_import_address(address)? else {
            if keep_unresolved && !model.has_thunk_rva(slot_rva) {
                let evidence = ImportEvidence::slot(
                    evidence_kind,
                    ImportResolutionKind::Unresolved,
                    slot_rva,
                    Some(address),
                );
                unresolved.push(RecoveredUnresolvedImportThunk {
                    rva: slot_rva,
                    address,
                    evidence,
                });
            }
            continue;
        };

        let target = import_target_from_export(&symbol)?;
        let resolution = resolution_from_symbol(&symbol, address, address_resolve_options);
        let evidence = ImportEvidence::slot(
            evidence_kind,
            resolution,
            slot_rva,
            Some(address),
        );
        let key = module_key(&symbol.module_name);
        let module = modules.entry(key).or_insert_with(|| RecoveredImportModule {
            name: symbol.module_name.clone(),
            first_thunk: slot_rva,
            last_thunk: slot_rva,
            thunks: Vec::new(),
        });

        module.first_thunk = module.first_thunk.min(slot_rva);
        module.last_thunk = module.last_thunk.max(slot_rva);
        module.thunks.push(RecoveredImportThunk { rva: slot_rva, target, evidence });
        recovered += 1;
    }

    for module in modules.values() {
        model.upsert_module_range(&module.name, module.first_thunk, module.last_thunk, pointer_size)?;

        for thunk in &module.thunks {
            model.add_function_with_evidence(
                &module.name,
                thunk.rva,
                thunk.target.clone(),
                true,
                true,
                vec![thunk.evidence.clone()],
            )?;
        }
    }
    add_unresolved_iat_slots(model, unresolved, pointer_size)?;

    Ok(recovered)
}

pub fn scan_iat_ranges(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_mode: ImportAddressResolveMode,
    exports: &[&ExportTable],
    min_entries: usize,
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    scan_iat_ranges_with_options(
        image_data,
        base_rva,
        pointer_size,
        ImportAddressResolveOptions {
            mode: address_resolve_mode,
            resolve_forwarders: false,
            api_set_map: None,
        },
        exports,
        min_entries,
    )
}

pub fn scan_iat_ranges_with_options(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    min_entries: usize,
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    validate_pointer_size(pointer_size)?;
    if min_entries == 0 {
        return Err(ImportError::InvalidMinIatEntries);
    }

    let resolver = ImportAddressResolver::new(exports, address_resolve_options);
    let runs = scan_iat_runs(image_data, pointer_size, &resolver)?;
    coalesce_iat_runs(base_rva, pointer_size, runs, min_entries)
}

pub fn scan_iat_ranges_with_traced_thunks(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    min_entries: usize,
    image_base: Option<u64>,
    max_depth: usize,
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    validate_pointer_size(pointer_size)?;
    if min_entries == 0 {
        return Err(ImportError::InvalidMinIatEntries);
    }

    let resolver = MappedThunkResolver::new(
        image_data,
        image_base,
        pointer_size,
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options),
    )?;
    let runs = scan_iat_runs(image_data, pointer_size, &resolver)?;
    coalesce_iat_runs(base_rva, pointer_size, runs, min_entries)
}

pub fn scan_iat_ranges_containing_rvas(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_mode: ImportAddressResolveMode,
    exports: &[&ExportTable],
    anchor_rvas: &[u32],
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    scan_iat_ranges_containing_rvas_with_options(
        image_data,
        base_rva,
        pointer_size,
        ImportAddressResolveOptions {
            mode: address_resolve_mode,
            resolve_forwarders: false,
            api_set_map: None,
        },
        exports,
        anchor_rvas,
    )
}

pub fn scan_iat_ranges_containing_rvas_with_options(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    anchor_rvas: &[u32],
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    let resolver = ImportAddressResolver::new(exports, address_resolve_options);
    scan_iat_ranges_containing_rvas_with_symbol_resolver(image_data, base_rva, pointer_size, &resolver, anchor_rvas)
}

pub fn scan_iat_ranges_containing_rvas_with_traced_thunks(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    image_base: Option<u64>,
    max_depth: usize,
    anchor_rvas: &[u32],
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    let resolver = MappedThunkResolver::new(
        image_data,
        image_base,
        pointer_size,
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options),
    )?;

    scan_iat_ranges_containing_rvas_with_symbol_resolver(image_data, base_rva, pointer_size, &resolver, anchor_rvas)
}

fn scan_iat_ranges_containing_rvas_with_symbol_resolver<R: ImportSymbolResolver>(
    image_data: &[u8],
    base_rva: u32,
    pointer_size: usize,
    resolver: &R,
    anchor_rvas: &[u32],
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    validate_pointer_size(pointer_size)?;
    if anchor_rvas.is_empty() {
        return Ok(Vec::new());
    }

    let excluded = embedded::mapped_exclusions(image_data);
    let mut ranges = BTreeMap::<usize, ImportAddressTableRange>::new();
    for anchor in anchor_rvas {
        let Some(offset) = anchor.checked_sub(base_rva).map(|offset| offset as usize) else { continue };
        if let Some((start, range)) = ranges.range(..=offset).next_back()
            && offset - start < range.size as usize && (offset - start) % pointer_size == 0 { continue; }
        let valid_slot = |offset: usize| -> Result<bool, ImportError> {
            if offset.saturating_add(pointer_size) > image_data.len() || embedded::intersects(&excluded, offset, pointer_size) {
                return Ok(false);
            }
            let address = read_iat_pointer(&image_data[offset..offset + pointer_size], pointer_size)?;
            Ok(address != 0 && resolver.resolve_import_address(address)?.is_some())
        };
        if !valid_slot(offset)? { continue; }
        let mut start = offset;
        while start >= pointer_size && valid_slot(start - pointer_size)? { start -= pointer_size; }
        let mut end = offset + pointer_size;
        while valid_slot(end)? { end += pointer_size; }
        if embedded::intersects(&excluded, end, pointer_size) || !is_zero_pointer_at(image_data, end, pointer_size)? { continue; }
        ranges.entry(start).or_insert(ImportAddressTableRange {
            rva: rva_from_offset(base_rva, start)?,
            size: u32::try_from(end - start).map_err(|_| ImportError::Overflow("sizing anchored IAT range"))?,
            entries: (end - start) / pointer_size,
        });
    }
    Ok(ranges.into_values().collect())
}

#[derive(Clone, Copy, Debug)]
struct ImportAddressTableRun {
    offset: usize,
    entries: usize,
}

#[derive(Clone, Copy, Debug)]
struct ImportAddressTableRangeBuilder {
    start: usize,
    end: usize,
    entries: usize,
    has_anchor: bool,
}

impl ImportAddressTableRangeBuilder {
    fn new(run: ImportAddressTableRun, pointer_size: usize, min_entries: usize) -> Result<Self, ImportError> {
        Ok(Self {
            start: run.offset,
            end: run_end(run, pointer_size)?,
            entries: run.entries,
            has_anchor: run.entries >= min_entries,
        })
    }

    fn can_absorb(&self, run: ImportAddressTableRun, max_gap: usize) -> bool {
        run.offset >= self.end && run.offset - self.end <= max_gap
    }

    fn absorb(&mut self, run: ImportAddressTableRun, pointer_size: usize, min_entries: usize) -> Result<(), ImportError> {
        self.end = run_end(run, pointer_size)?;
        self.entries += run.entries;
        self.has_anchor |= run.entries >= min_entries;
        Ok(())
    }

    fn finish(self, base_rva: u32) -> Result<Option<ImportAddressTableRange>, ImportError> {
        if !self.has_anchor {
            return Ok(None);
        }

        let size = self
            .end
            .checked_sub(self.start)
            .ok_or(ImportError::Overflow("sizing coalesced IAT scan range"))?;
        let size = u32::try_from(size)
            .map_err(|_| ImportError::Overflow("converting coalesced IAT scan range size to u32"))?;

        Ok(Some(ImportAddressTableRange {
            rva: rva_from_offset(base_rva, self.start)?,
            size,
            entries: self.entries,
        }))
    }
}

fn scan_iat_runs<R: ImportSymbolResolver>(
    image_data: &[u8],
    pointer_size: usize,
    resolver: &R,
) -> Result<Vec<ImportAddressTableRun>, ImportError> {
    let mut ranges = Vec::new();
    let mut offset = 0usize;
    let excluded = embedded::mapped_exclusions(image_data);

    while offset + pointer_size <= image_data.len() {
        let start = offset;
        let mut cursor = offset;
        let mut entries = 0usize;

        while cursor + pointer_size <= image_data.len() {
            if embedded::intersects(&excluded, cursor, pointer_size) { break; }
            let address = read_iat_pointer(&image_data[cursor..cursor + pointer_size], pointer_size)?;
            if address == 0 || resolver.resolve_import_address(address)?.is_none() {
                break;
            }

            entries += 1;
            cursor = checked_add(cursor, pointer_size, "scanning IAT range")?;
        }

        if entries != 0 && !embedded::intersects(&excluded, cursor, pointer_size) && is_zero_pointer_at(image_data, cursor, pointer_size)? {
            ranges.push(ImportAddressTableRun { offset: start, entries });
            offset = checked_add(cursor, pointer_size, "moving past IAT range terminator")?;
            continue;
        }

        offset = checked_add(start, pointer_size, "advancing IAT scanner")?;
    }

    Ok(ranges)
}

fn coalesce_iat_runs(
    base_rva: u32,
    pointer_size: usize,
    runs: Vec<ImportAddressTableRun>,
    min_entries: usize,
) -> Result<Vec<ImportAddressTableRange>, ImportError> {
    let max_gap = checked_mul(pointer_size, IAT_SCAN_MAX_GAP_POINTERS, "sizing IAT scan coalescing gap")?;
    let mut ranges = Vec::new();
    let mut builder: Option<ImportAddressTableRangeBuilder> = None;

    for run in runs {
        match builder {
            Some(mut current) if current.can_absorb(run, max_gap) => {
                current.absorb(run, pointer_size, min_entries)?;
                builder = Some(current);
            }
            Some(current) => {
                if let Some(range) = current.finish(base_rva)? {
                    ranges.push(range);
                }
                builder = Some(ImportAddressTableRangeBuilder::new(run, pointer_size, min_entries)?);
            }
            None => builder = Some(ImportAddressTableRangeBuilder::new(run, pointer_size, min_entries)?),
        }
    }

    if let Some(current) = builder {
        if let Some(range) = current.finish(base_rva)? {
            ranges.push(range);
        }
    }

    Ok(ranges)
}

fn run_end(run: ImportAddressTableRun, pointer_size: usize) -> Result<usize, ImportError> {
    checked_add(run.offset, checked_mul(run.entries, pointer_size, "sizing IAT scan run")?, "sizing IAT scan run")
}

pub fn rank_iat_ranges(
    ranges: Vec<ImportAddressTableRange>,
    anchor_rvas: &[u32],
) -> Result<Vec<ImportAddressTableRangeScore>, ImportError> {
    let mut scored = ranges
        .into_iter()
        .map(|range| score_iat_range(range, anchor_rvas))
        .collect::<Result<Vec<_>, _>>()?;

    scored.sort_by(|left, right| {
        right.score
            .cmp(&left.score)
            .then_with(|| right.anchor_count.cmp(&left.anchor_count))
            .then_with(|| compare_anchor_distance(left.nearest_anchor_distance, right.nearest_anchor_distance))
            .then_with(|| right.range.entries.cmp(&left.range.entries))
            .then_with(|| left.range.rva.cmp(&right.range.rva))
    });
    Ok(scored)
}

fn score_iat_range(
    range: ImportAddressTableRange,
    anchor_rvas: &[u32],
) -> Result<ImportAddressTableRangeScore, ImportError> {
    let anchor_count = range_anchor_count(&range, anchor_rvas)?;
    let nearest_anchor_distance = nearest_anchor_distance(&range, anchor_rvas)?;
    let entry_score = (range.entries.min(0xffff) as u32).saturating_mul(16);
    let anchor_score = (anchor_count.min(0xffff) as u32).saturating_mul(1000);
    let proximity_score = match nearest_anchor_distance {
        Some(0) => 500,
        Some(distance) => 256u32.saturating_sub((distance / 0x10).min(256)),
        None => 0,
    };

    Ok(ImportAddressTableRangeScore {
        range,
        score: anchor_score.saturating_add(proximity_score).saturating_add(entry_score),
        anchor_count,
        nearest_anchor_distance,
    })
}

fn range_anchor_count(
    range: &ImportAddressTableRange,
    anchor_rvas: &[u32],
) -> Result<usize, ImportError> {
    let end = iat_range_end(range)?;
    Ok(anchor_rvas.iter().filter(|rva| **rva >= range.rva && **rva < end).count())
}

fn nearest_anchor_distance(
    range: &ImportAddressTableRange,
    anchor_rvas: &[u32],
) -> Result<Option<u32>, ImportError> {
    let end = iat_range_end(range)?;
    let last_rva = end.saturating_sub(1);
    let mut nearest: Option<u32> = None;

    for anchor_rva in anchor_rvas {
        let distance = if *anchor_rva < range.rva {
            range.rva - *anchor_rva
        } else if *anchor_rva >= end {
            *anchor_rva - last_rva
        } else {
            0
        };

        nearest = Some(match nearest {
            Some(current) => current.min(distance),
            None => distance,
        });
    }

    Ok(nearest)
}

fn iat_range_end(range: &ImportAddressTableRange) -> Result<u32, ImportError> {
    range
        .rva
        .checked_add(range.size)
        .ok_or(ImportError::Overflow("sizing IAT range"))
}

fn compare_anchor_distance(left: Option<u32>, right: Option<u32>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

pub fn recover_iat_from_code_references(
    model: &mut ImportModel,
    references: &[ImportCodeReference],
    pointer_size: usize,
) -> Result<usize, ImportError> {
    validate_pointer_size(pointer_size)?;

    let mut recovered = 0;
    for reference in references {
        let Some(iat_rva) = reference.iat_rva else {
            continue;
        };
        if model.has_thunk_rva(iat_rva) {
            continue;
        }

        let target = import_target_from_code_reference(reference)?;
        model.upsert_module_range(&reference.module_name, iat_rva, iat_rva, pointer_size)?;
        model.add_function_with_evidence(
            &reference.module_name,
            iat_rva,
            target,
            true,
            false,
            vec![ImportEvidence::code_reference(
                reference,
                code_reference_evidence_kind(reference),
                reference.iat_rva,
            )],
        )?;
        recovered += 1;
    }

    Ok(recovered)
}

pub fn scan_mapped_export_code_references(
    image_data: &[u8],
    image_base: Option<u64>,
    address_resolve_mode: ImportAddressResolveMode,
    exports: &[&ExportTable],
) -> Result<Vec<ImportCodeReference>, ImportError> {
    scan_mapped_export_code_references_with_options(
        image_data,
        image_base,
        ImportAddressResolveOptions {
            mode: address_resolve_mode,
            resolve_forwarders: false,
            api_set_map: None,
        },
        exports,
    )
}

pub fn scan_mapped_export_code_references_with_options(
    image_data: &[u8],
    image_base: Option<u64>,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let resolver = ImportAddressResolver::new(exports, address_resolve_options);
    code::scan_mapped_export_code_references_with_resolver(image_data, image_base, &resolver)
}

pub fn scan_mapped_export_code_references_with_traced_thunks(
    image_data: &[u8],
    image_base: Option<u64>,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    max_depth: usize,
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let resolver = MappedThunkResolver::new(
        image_data,
        Some(image_base),
        image.pointer_size(),
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options),
    )?;

    code::scan_mapped_export_code_references_with_resolver(image_data, Some(image_base), &resolver)
}

pub fn scan_mapped_export_code_references_in_range(
    image_data: &[u8],
    image_base: Option<u64>,
    rva: u32,
    size: usize,
    address_resolve_mode: ImportAddressResolveMode,
    exports: &[&ExportTable],
) -> Result<Vec<ImportCodeReference>, ImportError> {
    scan_mapped_export_code_references_in_range_with_options(
        image_data,
        image_base,
        rva,
        size,
        ImportAddressResolveOptions {
            mode: address_resolve_mode,
            resolve_forwarders: false,
            api_set_map: None,
        },
        exports,
    )
}

pub fn scan_mapped_export_code_references_in_range_with_options(
    image_data: &[u8],
    image_base: Option<u64>,
    rva: u32,
    size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let resolver = ImportAddressResolver::new(exports, address_resolve_options);
    code::scan_mapped_export_code_references_in_range_with_resolver(image_data, image_base, rva, size, &resolver)
}

pub fn scan_mapped_export_code_references_in_range_with_traced_thunks(
    image_data: &[u8],
    image_base: Option<u64>,
    rva: u32,
    size: usize,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    max_depth: usize,
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let resolver = MappedThunkResolver::new(
        image_data,
        Some(image_base),
        image.pointer_size(),
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options),
    )?;

    code::scan_mapped_export_code_references_in_range_with_resolver(image_data, Some(image_base), rva, size, &resolver)
}

pub fn trace_mapped_export_code_references(
    image_data: &[u8],
    image_base: Option<u64>,
    trace_options: ImportCodeTraceOptions,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
) -> Result<ImportCodeTrace, ImportError> {
    let resolver = ImportAddressResolver::new(exports, address_resolve_options);
    code::trace_mapped_export_code_references_with_resolver(image_data, image_base, trace_options, &resolver)
}

pub fn trace_mapped_export_code_references_with_traced_thunks(
    image_data: &[u8],
    image_base: Option<u64>,
    trace_options: ImportCodeTraceOptions,
    address_resolve_options: ImportAddressResolveOptions,
    exports: &[&ExportTable],
    max_depth: usize,
) -> Result<ImportCodeTrace, ImportError> {
    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let resolver = MappedThunkResolver::new(
        image_data,
        Some(image_base),
        image.pointer_size(),
        max_depth,
        ImportAddressResolver::new(exports, address_resolve_options),
    )?;

    code::trace_mapped_export_code_references_with_resolver(image_data, Some(image_base), trace_options, &resolver)
}

#[derive(Debug)]
struct RecoveredImportModule {
    name: String,
    first_thunk: u32,
    last_thunk: u32,
    thunks: Vec<RecoveredImportThunk>,
}

#[derive(Debug)]
struct RecoveredImportThunk {
    rva: u32,
    target: ImportTarget,
    evidence: ImportEvidence,
}

#[derive(Clone, Debug)]
struct RecoveredUnresolvedImportThunk {
    rva: u32,
    address: u64,
    evidence: ImportEvidence,
}

fn add_unresolved_iat_slots(
    model: &mut ImportModel,
    mut slots: Vec<RecoveredUnresolvedImportThunk>,
    pointer_size: usize,
) -> Result<(), ImportError> {
    validate_pointer_size(pointer_size)?;
    if slots.is_empty() {
        return Ok(());
    }

    slots.sort_by_key(|slot| slot.rva);
    let pointer_size = u32::try_from(pointer_size)
        .map_err(|_| ImportError::Overflow("converting pointer size to u32"))?;
    let mut run = Vec::<RecoveredUnresolvedImportThunk>::new();

    for slot in slots {
        let continues_run = match run.last().and_then(|last| last.rva.checked_add(pointer_size)) {
            Some(next_rva) => next_rva == slot.rva,
            None => false,
        };
        if !run.is_empty() && !continues_run {
            add_unresolved_iat_run(model, &run, pointer_size)?;
            run.clear();
        }

        run.push(slot);
    }

    if !run.is_empty() {
        add_unresolved_iat_run(model, &run, pointer_size)?;
    }

    Ok(())
}

fn add_unresolved_iat_run(
    model: &mut ImportModel,
    slots: &[RecoveredUnresolvedImportThunk],
    pointer_size: u32,
) -> Result<(), ImportError> {
    let Some(first) = slots.first() else {
        return Ok(());
    };
    let last = slots
        .last()
        .ok_or(ImportError::Overflow("sizing unresolved IAT run"))?;
    let name = model.cut_module_name(first.rva);
    let mut thunks = BTreeMap::new();

    for slot in slots {
        if model.has_thunk_rva(slot.rva) {
            continue;
        }

        thunks.insert(
            slot.rva,
            ImportThunk {
                rva: slot.rva,
                target: ImportTarget::Unknown(slot.address),
                valid: false,
                evidence: vec![slot.evidence.clone()],
            },
        );
    }

    if thunks.is_empty() {
        return Ok(());
    }

    model.modules.insert(
        module_key(&name),
        ImportModule {
            name,
            first_thunk: first.rva,
            nb_thunks: thunk_count(first.rva, last.rva, pointer_size)?,
            thunks,
        },
    );

    Ok(())
}

fn code_reference_evidence_kind(reference: &ImportCodeReference) -> ImportEvidenceKind {
    if reference.kind.is_patchable_direct_branch() {
        ImportEvidenceKind::DirectBranch
    } else {
        ImportEvidenceKind::CodeReference
    }
}

fn resolution_from_symbol(
    symbol: &ExportSymbol,
    requested_address: u64,
    options: &ImportAddressResolveOptions,
) -> ImportResolutionKind {
    if symbol.forwarder.is_some() {
        return ImportResolutionKind::Forwarded;
    }

    if options.mode == ImportAddressResolveMode::Nearest && symbol.address != requested_address {
        return ImportResolutionKind::Nearest;
    }

    ImportResolutionKind::Exact
}
