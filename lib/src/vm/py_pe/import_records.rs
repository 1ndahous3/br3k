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
    /// Python bytes produced by the import rebuild.
    #[pymember]
    data: PyRef<PyBytes>,
    /// RVA of the section containing rebuilt import metadata.
    #[pymember]
    import_section_rva: u32,
    /// Size of the rebuilt import section in bytes.
    #[pymember]
    import_section_size: u32,
    /// Image-relative address of the IAT or associated IAT slot.
    #[pymember]
    iat_rva: u32,
    /// Rebuilt IAT size in bytes.
    #[pymember]
    iat_size: u32,
    /// RVA of a generated code-stub section, or None when no section was required.
    #[pymember]
    code_stub_section_rva: Option<PyRef<PyInt>>,
    /// Generated code-stub section size in bytes.
    #[pymember]
    code_stub_section_size: u32,
    /// Number of direct code targets added to the import model.
    #[pymember]
    direct_imports_added: PyRef<PyInt>,
    /// Number of code references considered patchable.
    #[pymember]
    patchable_code_references: PyRef<PyInt>,
    /// Number of code references actually patched.
    #[pymember]
    patched_code_references: PyRef<PyInt>,
}

#[pyclass]
impl PeImportRebuild {}

/// A candidate contiguous IAT range in image-relative coordinates.
#[pyclass(module = "br3k.pe.imports", name = "AddressTableRange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportAddressTableRange {
    /// Image-relative start address of the IAT range or import slot.
    #[pymember]
    rva: u32,
    /// Candidate IAT range size in bytes.
    #[pymember]
    size: u32,
    /// Number of candidate import entries in the range.
    #[pymember]
    entries: PyRef<PyInt>,
}

#[pyclass]
impl PeImportAddressTableRange {}

/// Candidate IAT range ranked using anchors and recovered-entry evidence.
#[pyclass(module = "br3k.pe.imports", name = "AddressTableRangeScore")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportAddressTableRangeScore {
    /// Image-relative start address of the IAT range or import slot.
    #[pymember]
    rva: u32,
    /// Candidate IAT range size in bytes.
    #[pymember]
    size: u32,
    /// Number of candidate import entries in the range.
    #[pymember]
    entries: PyRef<PyInt>,
    /// Heuristic ranking score for the candidate range.
    #[pymember]
    score: u32,
    /// Number of relevant anchors contributing to range ranking.
    #[pymember]
    anchor_count: PyRef<PyInt>,
    /// Byte distance to the nearest anchor, or None when none is available.
    #[pymember]
    nearest_anchor_distance: Option<PyRef<PyInt>>,
}

#[pyclass]
impl PeImportAddressTableRangeScore {}

/// One module group in an editable/recovered import model, with thunk and validity counts.
#[pyclass(module = "br3k.pe.imports", name = "Module")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportModule {
    /// DLL name associated with this import group or entry.
    #[pymember]
    module_name: PyStrRef,
    /// RVA of the module group's first thunk.
    #[pymember]
    first_thunk: u32,
    /// Thunk count recorded for the module group.
    #[pymember]
    nb_thunks: u32,
    /// Number of functions in the module group.
    #[pymember]
    function_count: PyRef<PyInt>,
    /// Number of functions marked valid in the group.
    #[pymember]
    valid_function_count: PyRef<PyInt>,
}

#[pyclass]
impl PeImportModule {}

/// One modeled import, including target identity and accumulated recovery evidence.
#[pyclass(module = "br3k.pe.imports", name = "Function")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportFunction {
    /// DLL name associated with this import group or entry.
    #[pymember]
    module_name: PyStrRef,
    /// Image-relative start address of the IAT range or import slot.
    #[pymember]
    rva: u32,
    /// Import name when available; None for ordinal-only or unresolved entries.
    #[pymember]
    name: Option<PyStrRef>,
    /// Import ordinal when present.
    #[pymember]
    ordinal: Option<PyRef<PyInt>>,
    /// PE import-name hint, when available.
    #[pymember]
    hint: Option<PyRef<PyInt>>,
    /// Whether the model marks this import valid for reconstruction.
    #[pymember]
    valid: bool,
    /// Recovered target virtual address, when known.
    #[pymember]
    address: Option<PyRef<PyInt>>,
    /// Accumulated heuristic confidence; not a calibrated probability.
    #[pymember]
    confidence: u8,
    evidence: Vec<ImportEvidence>,
}

#[pyclass]
impl PeImportFunction {
    /// Typed provenance records contributing to this import.
    #[pygetset]
    fn evidence(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeImportEvidence>> {
        let evidence = zelf
            .evidence
            .iter()
            .cloned()
            .map(|evidence| import_evidence_to_py(evidence, vm))
            .collect::<Vec<_>>();

        PyListOf::new(evidence, vm)
    }

    /// Whether no target address has been resolved.
    #[pygetset]
    fn unresolved(zelf: &Py<Self>) -> bool {
        zelf.address.is_none()
    }
}

/// Provenance for a recovered import. Confidence is a heuristic score, not a probability.
#[pyclass(module = "br3k.pe.imports", name = "Evidence")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportEvidence {
    kind: ImportEvidenceKind,
    resolution: ImportResolutionKind,
    /// Accumulated heuristic confidence; not a calibrated probability.
    #[pymember]
    confidence: u8,
    /// Image-relative location where this evidence was found.
    #[pymember]
    source_rva: u32,
    /// Resolved target virtual address, when known.
    #[pymember]
    target_address: Option<PyRef<PyInt>>,
    /// RVA of the supporting code reference, when applicable.
    #[pymember]
    reference_rva: Option<PyRef<PyInt>>,
    /// Image-relative address of the IAT or associated IAT slot.
    #[pymember]
    iat_rva: Option<PyRef<PyInt>>,
}

#[pyclass]
impl PeImportEvidence {
    /// Typed evidence or issue category.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportEvidenceKind>> {
        PyEnumValue::new(zelf.kind, vm)
    }

    /// Method used to resolve the target from the evidence.
    #[pygetset]
    fn resolution(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportResolutionKind>> {
        PyEnumValue::new(zelf.resolution, vm)
    }

    /// Format provenance, confidence, and known locations for display.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        let mut parts = vec![
            zelf.kind.as_str().to_string(),
            zelf.resolution.as_str().to_string(),
            format!("confidence={}", zelf.confidence),
            format!("source_rva=0x{:x}", zelf.source_rva),
        ];

        if let Some(target_address) = &zelf.target_address {
            parts.push(format!("target=0x{:x}", target_address.as_bigint()));
        }
        if let Some(reference_rva) = &zelf.reference_rva {
            parts.push(format!("ref=0x{:x}", reference_rva.as_bigint()));
        }
        if let Some(iat_rva) = &zelf.iat_rva {
            parts.push(format!("iat=0x{:x}", iat_rva.as_bigint()));
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
    /// Image-relative start address of the IAT range or import slot.
    #[pymember]
    rva: u32,
    /// DLL name associated with this import group or entry.
    #[pymember]
    module_name: PyStrRef,
    /// Import name when available; None for ordinal-only or unresolved entries.
    #[pymember]
    name: Option<PyStrRef>,
    /// Import ordinal when present.
    #[pymember]
    ordinal: Option<PyRef<PyInt>>,
    /// Recovered target virtual address, when known.
    #[pymember]
    address: Option<PyRef<PyInt>>,
    /// RVA of the adjacent or conflicting entry, when relevant.
    #[pymember]
    next_rva: Option<PyRef<PyInt>>,
    /// Module name of the adjacent or conflicting entry, when relevant.
    #[pymember]
    next_module_name: Option<PyStrRef>,
}

#[pyclass]
impl PeImportIssue {
    /// Typed evidence or issue category.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportIssueKind>> {
        PyEnumValue::new(zelf.kind, vm)
    }

    /// Typed severity of the model inconsistency.
    #[pygetset]
    fn severity(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportIssueSeverity>> {
        PyEnumValue::new(zelf.severity, vm)
    }
}

pub(crate) fn import_address_table_range_score_to_py(
    range: ImportAddressTableRangeScore,
    vm: &VirtualMachine,
) -> PyRef<PeImportAddressTableRangeScore> {
    PeImportAddressTableRangeScore {
        rva: range.range.rva,
        size: range.range.size,
        entries: vm.ctx.new_int(range.range.entries),
        score: range.score,
        anchor_count: vm.ctx.new_int(range.anchor_count),
        nearest_anchor_distance: range.nearest_anchor_distance.map(|value| vm.ctx.new_int(value)),
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_module_entry_to_py(
    entry: ImportModuleEntry,
    vm: &VirtualMachine,
) -> PyRef<PeImportModule> {
    PeImportModule {
        module_name: vm.ctx.new_str(entry.module_name),
        first_thunk: entry.first_thunk,
        nb_thunks: entry.nb_thunks,
        function_count: vm.ctx.new_int(entry.function_count),
        valid_function_count: vm.ctx.new_int(entry.valid_function_count),
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_entry_to_py(entry: ImportEntry, vm: &VirtualMachine) -> PyRef<PeImportFunction> {
    PeImportFunction {
        module_name: vm.ctx.new_str(entry.module_name),
        rva: entry.rva,
        name: entry.name.map(|value| vm.ctx.new_str(value)),
        ordinal: entry.ordinal.map(|value| vm.ctx.new_int(value)),
        hint: entry.hint.map(|value| vm.ctx.new_int(value)),
        valid: entry.valid,
        address: entry.address.map(|value| vm.ctx.new_int(value)),
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
        target_address: evidence.target_address.map(|value| vm.ctx.new_int(value)),
        reference_rva: evidence.reference_rva.map(|value| vm.ctx.new_int(value)),
        iat_rva: evidence.iat_rva.map(|value| vm.ctx.new_int(value)),
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_issue_to_py(issue: ImportIssue, vm: &VirtualMachine) -> PyRef<PeImportIssue> {
    PeImportIssue {
        kind: issue.kind,
        severity: issue.severity,
        rva: issue.rva,
        module_name: vm.ctx.new_str(issue.module_name),
        name: issue.name.map(|value| vm.ctx.new_str(value)),
        ordinal: issue.ordinal.map(|value| vm.ctx.new_int(value)),
        address: issue.address.map(|value| vm.ctx.new_int(value)),
        next_rva: issue.next_rva.map(|value| vm.ctx.new_int(value)),
        next_module_name: issue.next_module_name.map(|value| vm.ctx.new_str(value)),
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
        code_stub_section_rva: report.code_stub_section_rva.map(|value| vm.ctx.new_int(value)),
        code_stub_section_size: report.code_stub_section_size,
        direct_imports_added: vm.ctx.new_int(report.direct_imports_added),
        patchable_code_references: vm.ctx.new_int(report.patchable_code_references),
        patched_code_references: vm.ctx.new_int(report.patched_code_references),
    }
    .into_ref(&vm.ctx)
}
