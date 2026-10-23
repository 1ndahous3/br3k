use crate::vm::prelude::*;

use crate::pe::format::{self, HeaderArtifactKind};
use crate::pe::image::SectionInfo;
use crate::sysapi::MemoryRegion;
use crate::vm::py_pe::image::{section_info_to_py, PeSection};
use crate::vm::py_pe::types::{FindingKind, HiddenModuleReasonKind};
use crate::vm::py_proc::{CProcessMemoryRegion, CProcessModule};

use windows_sys::Win32::System::Memory::{PAGE_GUARD, PAGE_NOACCESS};

const PAGE_PROTECTION_BASE_MASK: u32 = 0xff;

pub mod scan;

pub(crate) use scan::find_hidden_modules_inner;
pub use scan::{ManualHiddenModuleCandidateArgs, manual_hidden_module_candidate};

#[derive(FromArgs)]
pub struct HiddenModuleScanOptionsNewArgs {
    #[pyarg(named, optional)]
    min_score: OptionalArg<i32>,
    #[pyarg(named, optional)]
    max_allocation_scan_bytes: OptionalArg<usize>,
    #[pyarg(named, optional)]
    max_artifacts_per_candidate: OptionalArg<usize>,
    #[pyarg(named, optional)]
    show_all_executable_regions: OptionalArg<bool>,
}

#[py_api]
#[derive(FromArgs)]
pub struct HiddenModuleArtifactNewArgs {
    #[pyi(ty = "br3k.pe.headers.ArtifactKind")]
    #[pyarg(any)]
    kind: PyObjectRef,
    #[pyarg(any)]
    address: u64,
    #[pyarg(any)]
    offset: u64,
    #[pyarg(any)]
    score: i32,
    #[pyarg(any)]
    sections: Vec<PyRef<PeSection>>,
    #[pyarg(any)]
    coverage_count: usize,
    #[pyarg(named, optional)]
    machine: OptionalArg<PyObjectRef>,
    #[pyarg(named, optional)]
    is_dll: OptionalArg<bool>,
    #[pyarg(named, optional)]
    section_table_offset: OptionalArg<u64>,
    #[pyarg(named, optional)]
    e_lfanew: OptionalArg<u32>,
}

#[derive(FromArgs)]
pub struct CandidateByBaseArgs {
    #[pyarg(any)]
    base_address: u64,
}

/// One reportable executable-memory or hidden-image finding. Scores are heuristic, not verdicts.
#[pyclass(module = "br3k.pe.analysis", name = "ScanFinding")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeScanFinding {
    kind: FindingKind,
    address: u64,
    size: u64,
    score: i32,
    reason: String,
    region: Option<MemoryRegion>,
    candidate: Option<PeHiddenModuleCandidate>,
}

#[pyclass]
impl PeScanFinding {
    /// Typed category for programmatic filtering.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::FindingKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Absolute target virtual address of the finding or artifact.
    #[pygetset]
    fn address(&self) -> u64 {
        self.address
    }

    /// Range length in bytes.
    #[pygetset]
    fn size(&self) -> u64 {
        self.size
    }

    /// Heuristic evidence score; higher values indicate stronger matching evidence.
    #[pygetset]
    fn score(&self) -> i32 {
        self.score
    }

    /// Display explanation of the finding.
    #[pygetset]
    fn reason(&self) -> String {
        self.reason.clone()
    }

    /// Associated memory-region snapshot, when available.
    #[pygetset]
    fn region(&self, vm: &VirtualMachine) -> Option<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        match &self.region {
            Some(region) => Some(CProcessMemoryRegion { data: region.clone() }.into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Associated hidden-image candidate, when applicable.
    #[pygetset]
    fn candidate(&self, vm: &VirtualMachine) -> Option<PyRef<PeHiddenModuleCandidate>> {
        match &self.candidate {
            Some(candidate) => Some(candidate.clone().into_ref(&vm.ctx)),
            None => None,
        }
    }
}

/// A half-open target virtual-address range [start, end).
#[pyclass(module = "br3k.pe.analysis", name = "MemoryRange")]
#[derive(Clone, Copy, Debug, PyPayload)]
pub struct PeMemoryRange {
    start: u64,
    end: u64,
}

#[pyclass]
impl PeMemoryRange {
    /// Inclusive start virtual address.
    #[pygetset]
    fn start(&self) -> u64 {
        self.start
    }

    /// Exclusive end virtual address.
    #[pygetset]
    fn end(&self) -> u64 {
        self.end
    }

    /// Range length in bytes.
    #[pygetset]
    fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Bounds and reporting threshold for hidden-image scans.
///
/// Defaults: min_score=5, max_allocation_scan_bytes=64 MiB,
/// max_artifacts_per_candidate=24, show_all_executable_regions=False.
#[pyclass(module = "br3k.pe.analysis", name = "HiddenModuleScanOptions")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHiddenModuleScanOptions {
    min_score: i32,
    max_allocation_scan_bytes: usize,
    max_artifacts_per_candidate: usize,
    show_all_executable_regions: bool,
}

impl Default for PeHiddenModuleScanOptions {
    fn default() -> Self {
        Self {
            min_score: 5,
            max_allocation_scan_bytes: 0x4000000,
            max_artifacts_per_candidate: 24,
            show_all_executable_regions: false,
        }
    }
}

impl Constructor for PeHiddenModuleScanOptions {
    type Args = HiddenModuleScanOptionsNewArgs;

    /// Create scan bounds and thresholds, overriding only supplied defaults.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        let mut options = Self::default();

        if let Some(value) = args.min_score.present() {
            options.min_score = value;
        }
        if let Some(value) = args.max_allocation_scan_bytes.present() {
            options.max_allocation_scan_bytes = value;
        }
        if let Some(value) = args.max_artifacts_per_candidate.present() {
            options.max_artifacts_per_candidate = value;
        }
        if let Some(value) = args.show_all_executable_regions.present() {
            options.show_all_executable_regions = value;
        }

        Ok(options)
    }
}

#[pyclass(with(Constructor))]
impl PeHiddenModuleScanOptions {
    /// Minimum score used by visible_candidates(); default 5.
    #[pygetset]
    fn min_score(&self) -> i32 {
        self.min_score
    }

    /// Maximum bytes inspected per allocation; default 64 MiB.
    #[pygetset]
    fn max_allocation_scan_bytes(&self) -> usize {
        self.max_allocation_scan_bytes
    }

    /// Maximum retained header artifacts per candidate; default 24.
    #[pygetset]
    fn max_artifacts_per_candidate(&self) -> usize {
        self.max_artifacts_per_candidate
    }

    /// Whether reporting bypasses the minimum-score filter.
    #[pygetset]
    fn show_all_executable_regions(&self) -> bool {
        self.show_all_executable_regions
    }
}

/// Typed evidence explaining a candidate's score, optionally linked to a header artifact.
#[pyclass(module = "br3k.pe.analysis", name = "HiddenModuleReason")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHiddenModuleReason {
    kind: HiddenModuleReasonKind,
    artifact: Option<PeHiddenModuleArtifact>,
}

#[pyclass]
impl PeHiddenModuleReason {
    /// Typed category for programmatic filtering.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::HiddenModuleReasonKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Header evidence supporting this reason, or None for region-only evidence.
    #[pygetset]
    fn artifact(&self, vm: &VirtualMachine) -> Option<PyRef<PeHiddenModuleArtifact>> {
        match &self.artifact {
            Some(artifact) => Some(artifact.clone().into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Format the typed reason and any artifact context for display.
    #[pymethod]
    fn text(&self) -> String {
        match self.kind {
            HiddenModuleReasonKind::OutsidePebModuleList => "allocation is not covered by the PEB module list".to_string(),
            HiddenModuleReasonKind::DetachedImageRegion => "detached executable MEM_IMAGE region".to_string(),
            HiddenModuleReasonKind::PrivateExecutableRegion => "executable MEM_PRIVATE region".to_string(),
            HiddenModuleReasonKind::MappedExecutableRegion => "executable MEM_MAPPED region outside known modules".to_string(),
            HiddenModuleReasonKind::WritableExecutableProtection => "writable executable protection".to_string(),
            HiddenModuleReasonKind::MixedExecutableAndNonExecutableRegions => "allocation mixes executable and non-executable regions".to_string(),
            HiddenModuleReasonKind::ManualSelection => "manually selected memory range".to_string(),
            HiddenModuleReasonKind::HeaderArtifact => self
                .artifact
                .as_ref()
                .map(PeHiddenModuleArtifact::reason_text_value)
                .unwrap_or_else(|| "header artifact".to_string()),
        }
    }
}

/// A PE-shaped header or section-table fragment inside a candidate allocation.
#[pyclass(module = "br3k.pe.analysis", name = "HiddenModuleArtifact")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHiddenModuleArtifact {
    kind: HeaderArtifactKind,
    address: u64,
    offset: u64,
    score: i32,
    sections: Vec<SectionInfo>,
    coverage_count: usize,
    machine: Option<String>,
    is_dll: Option<bool>,
    section_table_offset: Option<u64>,
    e_lfanew: Option<u32>,
}

impl Constructor for PeHiddenModuleArtifact {
    type Args = HiddenModuleArtifactNewArgs;

    /// Create an explicit artifact record; validates enum and machine values, not the target's contents.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let value = super::namespaces::enum_value(args.kind, "HeaderArtifactKind", vm)?;
        let kind = HeaderArtifactKind::from_repr(value).ok_or_else(|| vm.new_value_error("Invalid header artifact kind"))?;

        Ok(Self {
            kind,
            address: args.address,
            offset: args.offset,
            score: args.score,
            sections: args.sections.iter().map(|section| section.to_section_info()).collect(),
            coverage_count: args.coverage_count,
            machine: optional_machine_name(args.machine, vm)?,
            is_dll: args.is_dll.present(),
            section_table_offset: args.section_table_offset.present(),
            e_lfanew: args.e_lfanew.present(),
        })
    }
}

#[pyclass(with(Constructor))]
impl PeHiddenModuleArtifact {
    /// Typed category for programmatic filtering.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::format::HeaderArtifactKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Absolute target virtual address of the finding or artifact.
    #[pygetset]
    fn address(&self) -> u64 {
        self.address
    }

    /// Byte offset of the artifact from the candidate allocation base.
    #[pygetset]
    fn offset(&self) -> u64 {
        self.offset
    }

    /// Heuristic evidence score; higher values indicate stronger matching evidence.
    #[pygetset]
    fn score(&self) -> i32 {
        self.score
    }

    /// Section records inferred from the artifact.
    #[pygetset]
    fn sections(&self, vm: &VirtualMachine) -> PyListOf<PyRef<super::sections::PeSection>> {
        sections_to_py(&self.sections, vm)
    }

    /// Number of inferred section records.
    #[pygetset]
    fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Number of inferred section starts covered by observed allocation regions.
    #[pygetset]
    fn coverage_count(&self) -> usize {
        self.coverage_count
    }

    /// Detected architecture name, or None when unknown.
    #[pygetset]
    fn machine(&self) -> Option<String> {
        self.machine.clone()
    }

    /// Detected DLL flag, or None when the file header was unavailable.
    #[pygetset]
    fn is_dll(&self) -> Option<bool> {
        self.is_dll
    }

    /// Detected section-table byte offset within the allocation, when known.
    #[pygetset]
    fn section_table_offset(&self) -> Option<u64> {
        self.section_table_offset
    }

    /// Detected DOS-header e_lfanew value, when available.
    #[pygetset]
    fn e_lfanew(&self) -> Option<u32> {
        self.e_lfanew
    }

    /// Return a typed HeaderArtifact reason referring to this artifact.
    #[pymethod]
    fn reason(&self) -> PeHiddenModuleReason {
        PeHiddenModuleReason {
            kind: HiddenModuleReasonKind::HeaderArtifact,
            artifact: Some(self.clone()),
        }
    }

    /// Describe the artifact kind and allocation-relative location.
    #[pymethod]
    fn reason_text(&self) -> String {
        self.reason_text_value()
    }

    /// Format inferred section names and extents for display.
    #[pymethod]
    fn section_summary(&self) -> String {
        self.sections
            .iter()
            .map(format::section_summary)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl PeHiddenModuleArtifact {
    fn reason_text_value(&self) -> String {
        match self.kind {
            HeaderArtifactKind::MzPe => format!("intact MZ/PE header at allocation+{:#x}", self.offset),
            HeaderArtifactKind::NtHeaders => format!("NT headers at allocation+{:#x}", self.offset),
            HeaderArtifactKind::FileHeader => format!("PE file header without nearby PE signature at allocation+{:#x}", self.offset),
            HeaderArtifactKind::SectionTable => format!("section-table shaped data at allocation+{:#x}", self.offset),
        }
    }
}

/// An allocation containing unexplained executable regions or PE-shaped evidence.
///
/// This is a candidate, not proof of a manually mapped DLL. Use its regions,
/// read errors, and ranked artifacts to assess capture and recovery quality.
#[pyclass(module = "br3k.pe.analysis", name = "HiddenModuleCandidate")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHiddenModuleCandidate {
    allocation_base: u64,
    regions: Vec<MemoryRegion>,
    orphan_exec_regions: Vec<MemoryRegion>,
    read_errors: Vec<String>,
    artifacts: Vec<PeHiddenModuleArtifact>,
    score: i32,
    reasons: Vec<PeHiddenModuleReason>,
}

impl PeHiddenModuleCandidate {
    pub(crate) fn capture_regions(&self) -> Vec<MemoryRegion> { self.regions.clone() }
    pub(crate) fn capture_range(&self) -> Result<(u64, u32), format::FormatError> {
        Ok((self.allocation_base, u32::try_from(self.span_size()).map_err(|_| format::FormatError::Overflow("sizing capture"))?))
    }

    fn guessed_image_size_value(&self) -> Result<u32, format::FormatError> {
        if let Some(artifact) = self.artifacts.first() {
            return format::image_size_from_sections(
                &artifact.sections,
                self.span_size().saturating_sub(artifact.offset) as usize,
            );
        }

        u32::try_from(self.span_size())
            .map_err(|_| format::FormatError::Overflow("checking hidden module span size"))
    }
}

#[pyclass]
impl PeHiddenModuleCandidate {
    /// Absolute base address used to group the candidate allocation.
    #[pygetset]
    fn allocation_base(&self) -> u64 {
        self.allocation_base
    }

    /// Memory regions retained in this snapshot.
    #[pygetset]
    fn regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.regions, vm)
    }

    /// Candidate executable regions not covered by loader-listed modules.
    #[pygetset]
    fn orphan_exec_regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.orphan_exec_regions, vm)
    }

    /// Errors encountered while inspecting candidate memory.
    #[pygetset]
    fn read_errors(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        string_list_to_py(&self.read_errors, vm)
    }

    /// Ranked PE-shaped artifacts found in the allocation.
    #[pygetset]
    fn artifacts(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleArtifact>> {
        hidden_artifacts_to_py(&self.artifacts, vm)
    }

    /// Heuristic evidence score; higher values indicate stronger matching evidence.
    #[pygetset]
    fn score(&self) -> i32 {
        self.score
    }

    /// Typed evidence contributing to the candidate score.
    #[pygetset]
    fn reasons(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleReason>> {
        hidden_reasons_to_py(&self.reasons, vm)
    }

    /// Return the half-open extent covering the candidate regions.
    #[pymethod]
    fn span(&self) -> PeMemoryRange {
        allocation_span(&self.regions)
    }

    /// Return the candidate's full region-span length in bytes.
    #[pymethod]
    fn span_size(&self) -> u64 {
        self.span().size()
    }

    /// Return the first ranked artifact, or None when no header evidence was found.
    #[pymethod]
    fn best_artifact(&self, vm: &VirtualMachine) -> Option<PyRef<PeHiddenModuleArtifact>> {
        match self.artifacts.first() {
            Some(artifact) => Some(artifact.clone().into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Estimate image size from the best artifact's sections, falling back to the allocation span.
    ///
    /// This is a recovery hint; overflow raises ValueError.
    #[pymethod]
    fn guessed_image_size(&self, vm: &VirtualMachine) -> PyResult<u32> {
        self.guessed_image_size_value()
            .map_err(map_to_py_value_error(vm, "Unable to guess hidden module image size"))
    }
}

/// Hidden-image scan snapshot, with unfiltered candidates and thresholded reporting views.
#[pyclass(module = "br3k.pe.analysis", name = "HiddenModuleScanResult")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHiddenModuleScanResult {
    modules: Vec<CProcessModule>,
    regions: Vec<MemoryRegion>,
    committed: Vec<MemoryRegion>,
    executable: Vec<MemoryRegion>,
    orphan_executable: Vec<MemoryRegion>,
    candidate_allocations: Vec<u64>,
    candidates: Vec<PeHiddenModuleCandidate>,
    options: PeHiddenModuleScanOptions,
}

#[pyclass]
impl PeHiddenModuleScanResult {
    /// Loader-module snapshot used to identify regions outside known images.
    #[pygetset]
    fn modules(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessModule>> {
        process_modules_to_py(&self.modules, vm)
    }

    /// Memory regions retained in this snapshot.
    #[pygetset]
    fn regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.regions, vm)
    }

    /// Regions classified as committed.
    #[pygetset]
    fn committed(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.committed, vm)
    }

    /// Executable regions retained by the scan.
    #[pygetset]
    fn executable(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.executable, vm)
    }

    /// Executable regions outside loader-listed module coverage.
    #[pygetset]
    fn orphan_executable(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        memory_regions_to_py(&self.orphan_executable, vm)
    }

    /// Allocation bases selected for candidate inspection.
    #[pygetset]
    fn candidate_allocations(&self, vm: &VirtualMachine) -> PyListOf<PyRef<rustpython_vm::builtins::PyInt>> {
        let allocations = self.candidate_allocations
            .iter()
            .map(|value| vm.ctx.new_int(*value))
            .collect::<Vec<_>>();

        PyListOf::new(allocations, vm)
    }

    /// All retained candidates, before the reporting score filter.
    #[pygetset]
    fn candidates(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleCandidate>> {
        hidden_candidates_to_py(&self.candidates, vm)
    }

    /// Options used to produce this scan.
    #[pygetset]
    fn options(&self, vm: &VirtualMachine) -> PyRef<PeHiddenModuleScanOptions> {
        self.options.clone().into_ref(&vm.ctx)
    }

    /// Return candidates meeting min_score, or all candidates when show_all_executable_regions is enabled.
    #[pymethod]
    fn visible_candidates(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleCandidate>> {
        let candidates = self.candidates
            .iter()
            .filter(|candidate| {
                candidate.score >= self.options.min_score || self.options.show_all_executable_regions
            })
            .cloned()
            .map(|candidate| candidate.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        PyListOf::new(candidates, vm)
    }

    /// Find a candidate by exact allocation base; return None when absent.
    #[pymethod]
    fn candidate_by_base(&self, args: CandidateByBaseArgs, vm: &VirtualMachine) -> Option<PyRef<PeHiddenModuleCandidate>> {
        match self.candidates
            .iter()
            .find(|candidate| candidate.allocation_base == args.base_address) {
            Some(candidate) => Some(candidate.clone().into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Build reportable findings from this scan's evidence and reporting options.
    #[pymethod]
    fn findings(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeScanFinding>> {
        scan_findings_to_py(&scan_findings(self), vm)
    }
}

fn section_coverage_count(
    alloc_base: u64,
    regions: &[MemoryRegion],
    sections: &[SectionInfo],
) -> usize {
    sections
        .iter()
        .filter(|section| section_start_covered(alloc_base, regions, section))
        .count()
}

fn section_start_covered(
    alloc_base: u64,
    regions: &[MemoryRegion],
    section: &SectionInfo,
) -> bool {
    let address = alloc_base.saturating_add(section.virtual_address as u64);

    regions
        .iter()
        .any(|region| address >= region.base_address && address < region.end_address())
}

fn artifact_score(
    kind: HeaderArtifactKind,
    sections: &[SectionInfo],
    coverage_count: usize,
) -> i32 {
    let mut score = match kind {
        HeaderArtifactKind::MzPe => 7,
        HeaderArtifactKind::NtHeaders => 5,
        HeaderArtifactKind::FileHeader => 4,
        HeaderArtifactKind::SectionTable => 3,
    };

    score += sections.len().min(4) as i32;
    if coverage_count >= sections.len().min(2) {
        score += 2;
    }

    score
}

fn readable_region(region: &MemoryRegion) -> bool {
    region.is_committed()
        && region.protect & PAGE_GUARD == 0
        && region.protect & PAGE_PROTECTION_BASE_MASK != PAGE_NOACCESS
}

fn allocation_span(regions: &[MemoryRegion]) -> PeMemoryRange {
    let start = regions
        .iter()
        .map(|region| region.base_address)
        .min()
        .unwrap_or(0);
    let end = regions
        .iter()
        .map(MemoryRegion::end_address)
        .max()
        .unwrap_or(start);

    PeMemoryRange { start, end }
}

fn hidden_reason(kind: HiddenModuleReasonKind) -> PeHiddenModuleReason {
    PeHiddenModuleReason {
        kind,
        artifact: None,
    }
}

fn optional_machine_name(
    value: OptionalArg<PyObjectRef>,
    vm: &VirtualMachine,
) -> PyResult<Option<String>> {
    let Some(value) = value.present() else {
        return Ok(None);
    };
    if vm.is_none(&value) {
        return Ok(None);
    }
    if let Ok(machine) = PyStrRef::try_from_object(vm, value.clone()) {
        return Ok(Some(machine.to_string()));
    }
    if let Ok(machine) = u16::try_from_object(vm, value) {
        return format::machine_name(machine)
            .map(|name| Some(name.to_string()))
            .ok_or_else(|| vm.new_value_error(format!("Unsupported PE machine value: 0x{machine:x}")));
    }

    Err(vm.new_type_error("PE machine must be a string, integer, or None".to_string()))
}

fn exception_text(error: PyBaseExceptionRef, vm: &VirtualMachine) -> String {
    error
        .as_object()
        .str(vm)
        .map(|text| text.to_string())
        .unwrap_or_else(|_| format!("{error:?}"))
}

pub(crate) fn process_modules_to_py(modules: &[CProcessModule], vm: &VirtualMachine) -> PyListOf<PyRef<CProcessModule>> {
    let modules = modules
        .iter()
        .cloned()
        .map(|module| module.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(modules, vm)
}

pub(crate) fn memory_regions_to_py(regions: &[MemoryRegion], vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
    let regions = regions
        .iter()
        .cloned()
        .map(|region| CProcessMemoryRegion { data: region }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(regions, vm)
}

fn sections_to_py(sections: &[SectionInfo], vm: &VirtualMachine) -> PyListOf<PyRef<super::sections::PeSection>> {
    let sections = sections
        .iter()
        .cloned()
        .map(|section| section_info_to_py(section, vm))
        .collect::<Vec<_>>();

    PyListOf::new(sections, vm)
}

fn hidden_artifacts_to_py(artifacts: &[PeHiddenModuleArtifact], vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleArtifact>> {
    let artifacts = artifacts
        .iter()
        .cloned()
        .map(|artifact| artifact.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(artifacts, vm)
}

fn hidden_reasons_to_py(reasons: &[PeHiddenModuleReason], vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleReason>> {
    let reasons = reasons
        .iter()
        .cloned()
        .map(|reason| reason.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(reasons, vm)
}

pub(crate) fn hidden_candidates_to_py(candidates: &[PeHiddenModuleCandidate], vm: &VirtualMachine) -> PyListOf<PyRef<PeHiddenModuleCandidate>> {
    let candidates = candidates
        .iter()
        .cloned()
        .map(|candidate| candidate.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(candidates, vm)
}

fn string_list_to_py(items: &[String], vm: &VirtualMachine) -> PyListOf<PyStrRef> {
    let items = items
        .iter()
        .map(|item| vm.ctx.new_str(item.as_str()))
        .collect::<Vec<_>>();

    PyListOf::new(items, vm)
}

fn scan_findings(result: &PeHiddenModuleScanResult) -> Vec<PeScanFinding> {
    let mut findings = Vec::new();

    for candidate in result.visible_candidate_values() {
        let span = candidate.span();
        let reason = candidate
            .reasons
            .first()
            .map(PeHiddenModuleReason::text)
            .unwrap_or_else(|| "hidden-module candidate".to_string());

        findings.push(PeScanFinding {
            kind: FindingKind::HiddenModuleCandidate,
            address: candidate.allocation_base,
            size: span.size(),
            score: candidate.score,
            reason,
            region: None,
            candidate: Some(candidate.clone()),
        });
    }

    for region in &result.orphan_executable {
        findings.push(region_finding(
            FindingKind::OrphanExecutableRegion,
            region,
            "executable region outside loaded module ranges",
        ));

        if region.is_private() {
            findings.push(region_finding(
                FindingKind::PrivateExecutableRegion,
                region,
                "executable MEM_PRIVATE region",
            ));
        }
        if region.is_mapped() {
            findings.push(region_finding(
                FindingKind::MappedExecutableRegion,
                region,
                "executable MEM_MAPPED region outside loaded modules",
            ));
        }
        if region.is_image() {
            findings.push(region_finding(
                FindingKind::DetachedImageRegion,
                region,
                "detached executable MEM_IMAGE region",
            ));
        }
        if region.is_writable_executable() {
            findings.push(region_finding(
                FindingKind::WritableExecutableRegion,
                region,
                "writable executable protection",
            ));
        }
    }

    findings.sort_by_key(|finding| (-finding.score, finding.address, finding.kind as u32));
    findings
}

fn region_finding(
    kind: FindingKind,
    region: &MemoryRegion,
    reason: &'static str,
) -> PeScanFinding {
    PeScanFinding {
        kind,
        address: region.base_address,
        size: region.region_size as u64,
        score: 1,
        reason: reason.to_string(),
        region: Some(region.clone()),
        candidate: None,
    }
}

pub(crate) fn scan_findings_to_py(findings: &[PeScanFinding], vm: &VirtualMachine) -> PyListOf<PyRef<PeScanFinding>> {
    let findings = findings
        .iter()
        .cloned()
        .map(|finding| finding.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(findings, vm)
}

impl PeHiddenModuleScanResult {
    pub(crate) fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub(crate) fn region_count(&self) -> usize {
        self.regions.len()
    }

    pub(crate) fn executable_region_count(&self) -> usize {
        self.executable.len()
    }

    pub(crate) fn orphan_executable_region_count(&self) -> usize {
        self.orphan_executable.len()
    }

    pub(crate) fn executable_region_values(&self) -> &[MemoryRegion] {
        &self.executable
    }

    pub(crate) fn region_values(&self) -> &[MemoryRegion] {
        &self.regions
    }

    pub(crate) fn orphan_executable_region_values(&self) -> &[MemoryRegion] {
        &self.orphan_executable
    }

    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn findings_values(&self) -> Vec<PeScanFinding> {
        scan_findings(self)
    }

    pub(crate) fn visible_candidate_values(&self) -> Vec<&PeHiddenModuleCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| {
                candidate.score >= self.options.min_score || self.options.show_all_executable_regions
            })
            .collect()
    }
}
