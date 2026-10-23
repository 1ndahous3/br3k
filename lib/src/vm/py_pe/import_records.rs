use crate::vm::prelude::*;

use crate::pe::imports::{
    ImportAddressTableRangeScore, ImportEntry, ImportEvidence,
    ImportEvidenceKind, ImportIssue, ImportIssueKind, ImportIssueSeverity, ImportModuleEntry,
    ImportResolutionKind, RebuildImportsReport,
};

/// Rebuilt import bytes and a report of generated sections, IAT layout, and patched references.
#[pyclass(module = "br3k.pe.imports", name = "Rebuild")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportRebuild {
    data: PyRef<PyBytes>,
    import_section_rva: u32,
    import_section_size: u32,
    iat_rva: u32,
    iat_size: u32,
    code_stub_section_rva: Option<u32>,
    code_stub_section_size: u32,
    direct_imports_added: usize,
    patchable_code_references: usize,
    patched_code_references: usize,
}

#[pyclass]
impl PeImportRebuild {
    /// Python bytes produced by the import rebuild.
    #[pygetset]
    fn data(&self) -> PyRef<PyBytes> {
        self.data.clone()
    }

    /// RVA of the section containing rebuilt import metadata.
    #[pygetset]
    fn import_section_rva(&self) -> u32 {
        self.import_section_rva
    }

    /// Size of the rebuilt import section in bytes.
    #[pygetset]
    fn import_section_size(&self) -> u32 {
        self.import_section_size
    }

    /// Image-relative address of the IAT or associated IAT slot.
    #[pygetset]
    fn iat_rva(&self) -> u32 {
        self.iat_rva
    }

    /// Rebuilt IAT size in bytes.
    #[pygetset]
    fn iat_size(&self) -> u32 {
        self.iat_size
    }

    /// RVA of a generated code-stub section, or None when no section was required.
    #[pygetset]
    fn code_stub_section_rva(&self) -> Option<u32> {
        self.code_stub_section_rva
    }

    /// Generated code-stub section size in bytes.
    #[pygetset]
    fn code_stub_section_size(&self) -> u32 {
        self.code_stub_section_size
    }

    /// Number of direct code targets added to the import model.
    #[pygetset]
    fn direct_imports_added(&self) -> usize {
        self.direct_imports_added
    }

    /// Number of code references considered patchable.
    #[pygetset]
    fn patchable_code_references(&self) -> usize {
        self.patchable_code_references
    }

    /// Number of code references actually patched.
    #[pygetset]
    fn patched_code_references(&self) -> usize {
        self.patched_code_references
    }
}

/// A candidate contiguous IAT range in image-relative coordinates.
#[pyclass(module = "br3k.pe.imports", name = "AddressTableRange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportAddressTableRange {
    rva: u32,
    size: u32,
    entries: usize,
}

#[pyclass]
impl PeImportAddressTableRange {
    /// Image-relative start address of the IAT range or import slot.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.rva
    }

    /// Candidate IAT range size in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.size
    }

    /// Number of candidate import entries in the range.
    #[pygetset]
    fn entries(&self) -> usize {
        self.entries
    }
}

/// Candidate IAT range ranked using anchors and recovered-entry evidence.
#[pyclass(module = "br3k.pe.imports", name = "AddressTableRangeScore")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportAddressTableRangeScore {
    rva: u32,
    size: u32,
    entries: usize,
    score: u32,
    anchor_count: usize,
    nearest_anchor_distance: Option<u32>,
}

#[pyclass]
impl PeImportAddressTableRangeScore {
    /// Image-relative start address of the IAT range or import slot.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.rva
    }

    /// Candidate IAT range size in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.size
    }

    /// Number of candidate import entries in the range.
    #[pygetset]
    fn entries(&self) -> usize {
        self.entries
    }

    /// Heuristic ranking score for the candidate range.
    #[pygetset]
    fn score(&self) -> u32 {
        self.score
    }

    /// Number of relevant anchors contributing to range ranking.
    #[pygetset]
    fn anchor_count(&self) -> usize {
        self.anchor_count
    }

    /// Byte distance to the nearest anchor, or None when none is available.
    #[pygetset]
    fn nearest_anchor_distance(&self) -> Option<u32> {
        self.nearest_anchor_distance
    }
}

/// One module group in an editable/recovered import model, with thunk and validity counts.
#[pyclass(module = "br3k.pe.imports", name = "Module")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportModule {
    module_name: String,
    first_thunk: u32,
    nb_thunks: u32,
    function_count: usize,
    valid_function_count: usize,
}

#[pyclass]
impl PeImportModule {
    /// DLL name associated with this import group or entry.
    #[pygetset]
    fn module_name(&self) -> String {
        self.module_name.clone()
    }

    /// RVA of the module group's first thunk.
    #[pygetset]
    fn first_thunk(&self) -> u32 {
        self.first_thunk
    }

    /// Thunk count recorded for the module group.
    #[pygetset]
    fn nb_thunks(&self) -> u32 {
        self.nb_thunks
    }

    /// Number of functions in the module group.
    #[pygetset]
    fn function_count(&self) -> usize {
        self.function_count
    }

    /// Number of functions marked valid in the group.
    #[pygetset]
    fn valid_function_count(&self) -> usize {
        self.valid_function_count
    }
}

/// One modeled import, including target identity and accumulated recovery evidence.
#[pyclass(module = "br3k.pe.imports", name = "Function")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportFunction {
    module_name: String,
    rva: u32,
    name: Option<String>,
    ordinal: Option<u16>,
    hint: Option<u16>,
    valid: bool,
    address: Option<u64>,
    confidence: u8,
    evidence: Vec<ImportEvidence>,
}

#[pyclass]
impl PeImportFunction {
    /// DLL name associated with this import group or entry.
    #[pygetset]
    fn module_name(&self) -> String {
        self.module_name.clone()
    }

    /// Image-relative start address of the IAT range or import slot.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.rva
    }

    /// Import name when available; None for ordinal-only or unresolved entries.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Import ordinal when present.
    #[pygetset]
    fn ordinal(&self) -> Option<u16> {
        self.ordinal
    }

    /// PE import-name hint, when available.
    #[pygetset]
    fn hint(&self) -> Option<u16> {
        self.hint
    }

    /// Whether the model marks this import valid for reconstruction.
    #[pygetset]
    fn valid(&self) -> bool {
        self.valid
    }

    /// Recovered target virtual address, when known.
    #[pygetset]
    fn address(&self) -> Option<u64> {
        self.address
    }

    /// Accumulated heuristic confidence; not a calibrated probability.
    #[pygetset]
    fn confidence(&self) -> u8 {
        self.confidence
    }

    /// Typed provenance records contributing to this import.
    #[pygetset]
    fn evidence(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeImportEvidence>> {
        let evidence = self
            .evidence
            .iter()
            .cloned()
            .map(|evidence| import_evidence_to_py(evidence, vm))
            .collect::<Vec<_>>();

        PyListOf::new(evidence, vm)
    }

    /// Whether no target address has been resolved.
    #[pygetset]
    fn unresolved(&self) -> bool {
        self.address.is_none()
    }
}

/// Provenance for a recovered import. Confidence is a heuristic score, not a probability.
#[pyclass(module = "br3k.pe.imports", name = "Evidence")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportEvidence {
    kind: ImportEvidenceKind,
    resolution: ImportResolutionKind,
    confidence: u8,
    source_rva: u32,
    target_address: Option<u64>,
    reference_rva: Option<u32>,
    iat_rva: Option<u32>,
}

#[pyclass]
impl PeImportEvidence {
    /// Typed evidence or issue category.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportEvidenceKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Method used to resolve the target from the evidence.
    #[pygetset]
    fn resolution(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportResolutionKind>> {
        PyEnumValue::new(self.resolution, vm)
    }

    /// Accumulated heuristic confidence; not a calibrated probability.
    #[pygetset]
    fn confidence(&self) -> u8 {
        self.confidence
    }

    /// Image-relative location where this evidence was found.
    #[pygetset]
    fn source_rva(&self) -> u32 {
        self.source_rva
    }

    /// Resolved target virtual address, when known.
    #[pygetset]
    fn target_address(&self) -> Option<u64> {
        self.target_address
    }

    /// RVA of the supporting code reference, when applicable.
    #[pygetset]
    fn reference_rva(&self) -> Option<u32> {
        self.reference_rva
    }

    /// Image-relative address of the IAT or associated IAT slot.
    #[pygetset]
    fn iat_rva(&self) -> Option<u32> {
        self.iat_rva
    }

    /// Format provenance, confidence, and known locations for display.
    #[pymethod]
    fn summary(&self) -> String {
        let mut parts = vec![
            self.kind.as_str().to_string(),
            self.resolution.as_str().to_string(),
            format!("confidence={}", self.confidence),
            format!("source_rva=0x{:x}", self.source_rva),
        ];

        if let Some(target_address) = self.target_address {
            parts.push(format!("target=0x{target_address:x}"));
        }
        if let Some(reference_rva) = self.reference_rva {
            parts.push(format!("ref=0x{reference_rva:x}"));
        }
        if let Some(iat_rva) = self.iat_rva {
            parts.push(format!("iat=0x{iat_rva:x}"));
        }

        parts.join(" ")
    }
}

/// Typed inconsistency in an import model, optionally relating adjacent entries.
#[pyclass(module = "br3k.pe.imports", name = "Issue")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportIssue {
    kind: ImportIssueKind,
    severity: ImportIssueSeverity,
    rva: u32,
    module_name: String,
    name: Option<String>,
    ordinal: Option<u16>,
    address: Option<u64>,
    next_rva: Option<u32>,
    next_module_name: Option<String>,
}

#[pyclass]
impl PeImportIssue {
    /// Typed evidence or issue category.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportIssueKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Typed severity of the model inconsistency.
    #[pygetset]
    fn severity(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportIssueSeverity>> {
        PyEnumValue::new(self.severity, vm)
    }

    /// Image-relative start address of the IAT range or import slot.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.rva
    }

    /// DLL name associated with this import group or entry.
    #[pygetset]
    fn module_name(&self) -> String {
        self.module_name.clone()
    }

    /// Import name when available; None for ordinal-only or unresolved entries.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Import ordinal when present.
    #[pygetset]
    fn ordinal(&self) -> Option<u16> {
        self.ordinal
    }

    /// Recovered target virtual address, when known.
    #[pygetset]
    fn address(&self) -> Option<u64> {
        self.address
    }

    /// RVA of the adjacent or conflicting entry, when relevant.
    #[pygetset]
    fn next_rva(&self) -> Option<u32> {
        self.next_rva
    }

    /// Module name of the adjacent or conflicting entry, when relevant.
    #[pygetset]
    fn next_module_name(&self) -> Option<String> {
        self.next_module_name.clone()
    }
}

pub(crate) fn import_address_table_range_score_to_py(
    range: ImportAddressTableRangeScore,
    vm: &VirtualMachine,
) -> PyRef<PeImportAddressTableRangeScore> {
    PeImportAddressTableRangeScore {
        rva: range.range.rva,
        size: range.range.size,
        entries: range.range.entries,
        score: range.score,
        anchor_count: range.anchor_count,
        nearest_anchor_distance: range.nearest_anchor_distance,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_module_entry_to_py(
    entry: ImportModuleEntry,
    vm: &VirtualMachine,
) -> PyRef<PeImportModule> {
    PeImportModule {
        module_name: entry.module_name,
        first_thunk: entry.first_thunk,
        nb_thunks: entry.nb_thunks,
        function_count: entry.function_count,
        valid_function_count: entry.valid_function_count,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_entry_to_py(entry: ImportEntry, vm: &VirtualMachine) -> PyRef<PeImportFunction> {
    PeImportFunction {
        module_name: entry.module_name,
        rva: entry.rva,
        name: entry.name,
        ordinal: entry.ordinal,
        hint: entry.hint,
        valid: entry.valid,
        address: entry.address,
        confidence: entry.confidence,
        evidence: entry.evidence,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_evidence_to_py(evidence: ImportEvidence, vm: &VirtualMachine) -> PyRef<PeImportEvidence> {
    PeImportEvidence {
        kind: evidence.kind,
        resolution: evidence.resolution,
        confidence: evidence.confidence,
        source_rva: evidence.source_rva,
        target_address: evidence.target_address,
        reference_rva: evidence.reference_rva,
        iat_rva: evidence.iat_rva,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_issue_to_py(issue: ImportIssue, vm: &VirtualMachine) -> PyRef<PeImportIssue> {
    PeImportIssue {
        kind: issue.kind,
        severity: issue.severity,
        rva: issue.rva,
        module_name: issue.module_name,
        name: issue.name,
        ordinal: issue.ordinal,
        address: issue.address,
        next_rva: issue.next_rva,
        next_module_name: issue.next_module_name,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_rebuild_to_py(
    report: RebuildImportsReport,
    vm: &VirtualMachine,
) -> PyRef<PeImportRebuild> {
    PeImportRebuild {
        data: vm.ctx.new_bytes(report.image),
        import_section_rva: report.import_section_rva,
        import_section_size: report.import_section_size,
        iat_rva: report.iat_rva,
        iat_size: report.iat_size,
        code_stub_section_rva: report.code_stub_section_rva,
        code_stub_section_size: report.code_stub_section_size,
        direct_imports_added: report.direct_imports_added,
        patchable_code_references: report.patchable_code_references,
        patched_code_references: report.patched_code_references,
    }
    .into_ref(&vm.ctx)
}
