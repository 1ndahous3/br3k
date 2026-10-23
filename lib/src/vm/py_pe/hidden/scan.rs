use crate::vm::prelude::*;

use super::{
    artifact_score, exception_text, hidden_reason, readable_region, section_coverage_count,
    PeHiddenModuleArtifact, PeHiddenModuleCandidate, PeHiddenModuleReason,
    PeHiddenModuleScanOptions, PeHiddenModuleScanResult, PAGE_PROTECTION_BASE_MASK,
};

use crate::pe::format::{self, HeaderArtifact};
use crate::sysapi::{self, MemoryRegion};
use crate::vm::py_pe::types::HiddenModuleReasonKind;
use crate::vm::py_proc::{read_process_memory, CProcessModule, Process};

use std::collections::{BTreeMap, BTreeSet};

use windows_sys::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
};

#[derive(FromArgs)]
pub struct ManualHiddenModuleCandidateArgs {
    #[pyarg(any)]
    process: PyRef<Process>,
    #[pyarg(any)]
    base_address: u64,
    #[pyarg(any)]
    size: usize,
}

pub(crate) fn find_hidden_modules_inner(
    process: &Process,
    modules: Vec<CProcessModule>,
    options: PeHiddenModuleScanOptions,
    vm: &VirtualMachine,
) -> PyResult<PeHiddenModuleScanResult> {
    let process_handle = **process.process_handle.borrow();
    if process_handle.is_null() {
        return Err(vm.new_system_error("Process is not opened"));
    }

    let regions = sysapi::enumerate_memory_regions(process_handle)
        .map_err(map_to_py_system_error(vm, "Unable to enumerate process memory regions"))?;
    let ranges = module_ranges(&modules);
    let groups = grouped_regions(&regions);
    let committed = regions
        .iter()
        .filter(|region| region.is_committed())
        .cloned()
        .collect::<Vec<_>>();
    let executable = executable_regions(&committed);
    let orphan_executable = executable
        .iter()
        .filter(|region| {
            !allocation_matches_known_module(region_key(region), &ranges)
                && !region_intersects_known_module(region, &ranges)
        })
        .cloned()
        .collect::<Vec<_>>();
    let candidate_allocations = orphan_executable
        .iter()
        .map(region_key)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut candidates = Vec::new();

    for alloc_base in &candidate_allocations {
        let Some(group) = groups.get(alloc_base) else {
            continue;
        };
        if let Some(candidate) = build_candidate(process, *alloc_base, group, &ranges, &options, vm) {
            candidates.push(candidate);
        }
    }

    candidates.sort_by_key(|candidate| (-candidate.score, candidate.allocation_base));

    Ok(PeHiddenModuleScanResult {
        modules,
        regions,
        committed,
        executable,
        orphan_executable,
        candidate_allocations,
        candidates,
        options,
    })
}

pub fn manual_hidden_module_candidate(args: ManualHiddenModuleCandidateArgs, vm: &VirtualMachine) -> PyResult<PeHiddenModuleCandidate> {
    let process_handle = **args.process.process_handle.borrow();
    if process_handle.is_null() {
        return Err(vm.new_system_error("Process is not opened"));
    }

    let regions = sysapi::enumerate_memory_regions(process_handle)
        .map_err(map_to_py_system_error(vm, "Unable to enumerate process memory regions"))?;
    let selected = matching_regions_for_target(&regions, args.base_address, args.size);
    if selected.is_empty() {
        return Err(vm.new_value_error(format!(
            "No memory regions intersect base={:#x} size={:#x}",
            args.base_address,
            args.size,
        )));
    }

    Ok(PeHiddenModuleCandidate {
        allocation_base: args.base_address,
        orphan_exec_regions: executable_regions(&selected),
        regions: selected,
        read_errors: Vec::new(),
        artifacts: Vec::new(),
        score: 0,
        reasons: vec![hidden_reason(HiddenModuleReasonKind::ManualSelection)],
    })
}

fn build_candidate(
    process: &Process,
    alloc_base: u64,
    regions: &[MemoryRegion],
    known_ranges: &[ModuleRange],
    options: &PeHiddenModuleScanOptions,
    vm: &VirtualMachine,
) -> Option<PeHiddenModuleCandidate> {
    if allocation_matches_known_module(alloc_base, known_ranges) {
        return None;
    }

    let orphan_exec_regions = executable_regions(regions)
        .into_iter()
        .filter(|region| !region_intersects_known_module(region, known_ranges))
        .collect::<Vec<_>>();
    if orphan_exec_regions.is_empty() {
        return None;
    }

    let (chunks, read_errors) = read_group_chunks(process, regions, options.max_allocation_scan_bytes, vm);
    let artifacts = scan_pe_artifacts(&chunks, alloc_base, regions, options.max_artifacts_per_candidate);
    let score = score_candidate(alloc_base, &orphan_exec_regions, known_ranges, &artifacts);
    let mut reasons = region_reasons(alloc_base, regions, &orphan_exec_regions, known_ranges);

    reasons.extend(artifacts.iter().cloned().map(|artifact| artifact.reason()));

    Some(PeHiddenModuleCandidate {
        allocation_base: alloc_base,
        regions: regions.to_vec(),
        orphan_exec_regions,
        read_errors,
        artifacts,
        score,
        reasons,
    })
}

fn scan_pe_artifacts(
    chunks: &[MemoryChunk],
    alloc_base: u64,
    regions: &[MemoryRegion],
    max_artifacts: usize,
) -> Vec<PeHiddenModuleArtifact> {
    let mut artifacts = Vec::new();
    let mut seen = BTreeSet::new();

    for chunk in chunks {
        for artifact in format::scan_header_artifacts(&chunk.data, chunk.base, alloc_base) {
            let key = (artifact.kind as u32, artifact.address);
            if !seen.insert(key) {
                continue;
            }

            artifacts.push(make_artifact(artifact, alloc_base, regions));
        }
    }

    artifacts.sort_by_key(|artifact| (-artifact.score, artifact.address, artifact.kind as u32));
    artifacts.truncate(max_artifacts);
    artifacts
}

fn make_artifact(
    artifact: HeaderArtifact,
    alloc_base: u64,
    regions: &[MemoryRegion],
) -> PeHiddenModuleArtifact {
    let sections = artifact.sections;
    let coverage_count = section_coverage_count(alloc_base, regions, &sections);
    let score = artifact_score(artifact.kind, &sections, coverage_count);

    PeHiddenModuleArtifact {
        kind: artifact.kind,
        address: artifact.address,
        offset: artifact.offset,
        score,
        sections,
        coverage_count,
        machine: artifact.machine_name.map(str::to_string),
        is_dll: artifact.is_dll,
        section_table_offset: artifact.section_table_offset,
        e_lfanew: artifact.e_lfanew,
    }
}

fn region_reasons(
    alloc_base: u64,
    regions: &[MemoryRegion],
    orphan_exec_regions: &[MemoryRegion],
    known_ranges: &[ModuleRange],
) -> Vec<PeHiddenModuleReason> {
    let mut reasons = Vec::new();

    if !allocation_matches_known_module(alloc_base, known_ranges) {
        reasons.push(hidden_reason(HiddenModuleReasonKind::OutsidePebModuleList));
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_image) {
        reasons.push(hidden_reason(HiddenModuleReasonKind::DetachedImageRegion));
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_private) {
        reasons.push(hidden_reason(HiddenModuleReasonKind::PrivateExecutableRegion));
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_mapped) {
        reasons.push(hidden_reason(HiddenModuleReasonKind::MappedExecutableRegion));
    }
    if orphan_exec_regions
        .iter()
        .any(|region| is_writable_executable_protection(region.protect))
    {
        reasons.push(hidden_reason(HiddenModuleReasonKind::WritableExecutableProtection));
    }
    if executable_regions(regions).len() != orphan_exec_regions.len() {
        reasons.push(hidden_reason(HiddenModuleReasonKind::MixedExecutableAndNonExecutableRegions));
    }

    reasons
}

fn score_candidate(
    alloc_base: u64,
    orphan_exec_regions: &[MemoryRegion],
    known_ranges: &[ModuleRange],
    artifacts: &[PeHiddenModuleArtifact],
) -> i32 {
    let mut score = region_score(orphan_exec_regions, known_ranges, alloc_base);
    let mut kind_scores = BTreeMap::<u32, i32>::new();

    for artifact in artifacts {
        kind_scores
            .entry(artifact.kind as u32)
            .and_modify(|score| *score = (*score).max(artifact.score))
            .or_insert(artifact.score);
    }

    score += kind_scores.values().sum::<i32>();
    score
}

fn region_score(
    orphan_exec_regions: &[MemoryRegion],
    known_ranges: &[ModuleRange],
    alloc_base: u64,
) -> i32 {
    let mut score = 0;

    if !orphan_exec_regions.is_empty() {
        score += 2;
    }
    if !allocation_matches_known_module(alloc_base, known_ranges) {
        score += 1;
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_image) {
        score += 3;
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_private) {
        score += 2;
    }
    if orphan_exec_regions.iter().any(MemoryRegion::is_mapped) {
        score += 1;
    }
    if orphan_exec_regions
        .iter()
        .any(|region| is_writable_executable_protection(region.protect))
    {
        score += 1;
    }

    score
}

fn read_group_chunks(
    process: &Process,
    regions: &[MemoryRegion],
    max_bytes: usize,
    vm: &VirtualMachine,
) -> (Vec<MemoryChunk>, Vec<String>) {
    let mut chunks = Vec::new();
    let mut errors = Vec::new();
    let mut remaining = max_bytes;

    for region in regions {
        if remaining == 0 {
            break;
        }
        if !readable_region(region) {
            continue;
        }

        let size = region.region_size.min(remaining);
        match read_process_memory(process, region.base_address, size, vm) {
            Ok(data) => {
                chunks.push(MemoryChunk {
                    base: region.base_address,
                    data,
                });
                remaining -= size;
            }
            Err(error) => errors.push(format!(
                "{:#x} size={:#x}: {}",
                region.base_address,
                size,
                exception_text(error, vm),
            )),
        }
    }

    (chunks, errors)
}

fn grouped_regions(regions: &[MemoryRegion]) -> BTreeMap<u64, Vec<MemoryRegion>> {
    let mut groups = BTreeMap::<u64, Vec<MemoryRegion>>::new();

    for region in regions {
        if !region.is_committed() {
            continue;
        }

        groups
            .entry(region_key(region))
            .or_default()
            .push(region.clone());
    }

    for group in groups.values_mut() {
        group.sort_by_key(|region| region.base_address);
    }

    groups
}

fn executable_regions(regions: &[MemoryRegion]) -> Vec<MemoryRegion> {
    regions
        .iter()
        .filter(|region| region.is_committed() && region.is_executable() && !region.is_guarded())
        .cloned()
        .collect()
}

fn is_writable_executable_protection(protect: u32) -> bool {
    matches!(
        protect & PAGE_PROTECTION_BASE_MASK,
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn region_key(region: &MemoryRegion) -> u64 {
    if region.allocation_base == 0 {
        region.base_address
    } else {
        region.allocation_base
    }
}

fn matching_regions_for_target(
    regions: &[MemoryRegion],
    base_address: u64,
    size: usize,
) -> Vec<MemoryRegion> {
    let end_address = base_address.saturating_add(size as u64);
    let mut selected = regions
        .iter()
        .filter(|region| region.base_address < end_address && region.end_address() > base_address)
        .cloned()
        .collect::<Vec<_>>();

    selected.sort_by_key(|region| region.base_address);
    selected
}

fn module_ranges(modules: &[CProcessModule]) -> Vec<ModuleRange> {
    modules
        .iter()
        .map(|module| ModuleRange {
            start: module.dll_base,
            end: module.dll_base.saturating_add(module.size_of_image as u64),
        })
        .collect()
}

fn region_intersects_known_module(region: &MemoryRegion, ranges: &[ModuleRange]) -> bool {
    let start = region.base_address;
    let end = region.end_address();

    ranges
        .iter()
        .any(|range| start < range.end && end > range.start)
}

fn allocation_matches_known_module(allocation_base: u64, ranges: &[ModuleRange]) -> bool {
    ranges
        .iter()
        .any(|range| allocation_base >= range.start && allocation_base < range.end)
}

#[derive(Clone, Copy, Debug)]
struct ModuleRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Debug)]
struct MemoryChunk {
    base: u64,
    data: Vec<u8>,
}
