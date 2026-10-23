use crate::vm::prelude::*;

use crate::pe::exports::ExportTable;
use crate::pe::imports::{
    ImportAddressResolveMode, ImportAddressResolveOptions, ImportCodeReference,
    ImportCodeReferenceKind, ImportCodeTrace,
};
use crate::vm::py_pe::exports::PeExportMap;

#[derive(FromArgs)]
pub struct ScanArgs {
    #[pyarg(any)]
    pub symbols: PyRef<PeExportMap>,
    #[pyarg(named, optional)]
    pub nearest: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub forwarders: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub trace_mapped_thunks: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub max_trace_depth: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct RangeArgs {
    #[pyarg(any)]
    pub rva: u32,
    #[pyarg(any)]
    pub size: usize,
    #[pyarg(any)]
    pub symbols: PyRef<PeExportMap>,
    #[pyarg(named, optional)]
    pub nearest: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub forwarders: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub trace_mapped_thunks: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub max_trace_depth: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct TraceArgs {
    #[pyarg(any)]
    pub start_rva: u32,
    #[pyarg(any)]
    pub symbols: PyRef<PeExportMap>,
    #[pyarg(named, optional)]
    pub nearest: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub forwarders: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub trace_mapped_thunks: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub max_trace_depth: OptionalArg<usize>,
    #[pyarg(named, optional)]
    pub max_blocks: OptionalArg<usize>,
    #[pyarg(named, optional)]
    pub max_bytes: OptionalArg<usize>,
    #[pyarg(named, optional)]
    pub follow_calls: OptionalArg<bool>,
}

/// One statically recognized API-reference pattern and its resolved export evidence. It does not prove the instruction executes.
#[pyclass(module = "br3k.pe.code", name = "Reference")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportCodeReference {
    reference_rva: u32,
    kind: ImportCodeReferenceKind,
    target_address: u64,
    export_address: u64,
    iat_rva: Option<u32>,
    module_name: String,
    name: Option<String>,
    ordinal: u32,
}

#[pyclass]
impl PeImportCodeReference {
    pub(crate) fn to_import_code_reference(&self) -> ImportCodeReference {
        ImportCodeReference {
            reference_rva: self.reference_rva,
            kind: self.kind,
            target_address: self.target_address,
            export_address: self.export_address,
            iat_rva: self.iat_rva,
            module_name: self.module_name.clone(),
            name: self.name.clone(),
            ordinal: self.ordinal,
        }
    }

    /// RVA of the instruction or code pattern containing the reference.
    #[pygetset]
    fn reference_rva(&self) -> u32 {
        self.reference_rva
    }

    /// Architecture-specific kind of recognized API-reference pattern.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportCodeReferenceKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Target virtual address obtained from the recognized pattern before export matching.
    #[pygetset]
    fn target_address(&self) -> u64 {
        self.target_address
    }

    /// Virtual address of the export selected by resolution.
    #[pygetset]
    fn export_address(&self) -> u64 {
        self.export_address
    }

    /// RVA of the associated IAT slot, or None for a reference without an identified slot.
    #[pygetset]
    fn iat_rva(&self) -> Option<u32> {
        self.iat_rva
    }

    /// Module name associated with the resolved export.
    #[pygetset]
    fn module_name(&self) -> String {
        self.module_name.clone()
    }

    /// Export name when available; ordinal-only exports return None.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Resolved export ordinal.
    #[pygetset]
    fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Whether this reference carries an identified IAT slot RVA.
    #[pygetset]
    fn uses_iat(&self) -> bool {
        self.iat_rva.is_some()
    }

    /// Whether the recognized branch kind has a supported rewrite form. Placement and range checks may still reject a build.
    #[pygetset]
    fn patchable_direct_branch(&self) -> bool {
        self.kind.is_patchable_direct_branch()
    }
}

/// API references and work counters from a bounded static code trace. Not a runtime execution trace.
#[pyclass(module = "br3k.pe.code", name = "Trace")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportCodeTrace {
    references: PyListOf<PyRef<PeImportCodeReference>>,
    visited_blocks: usize,
    scanned_bytes: usize,
}

#[pyclass]
impl PeImportCodeTrace {
    /// API-reference records collected by the trace.
    #[pygetset]
    fn references(&self) -> PyListOf<PyRef<PeImportCodeReference>> {
        self.references.clone()
    }

    /// Number of code blocks visited before traversal ended or reached its limits.
    #[pygetset]
    fn visited_blocks(&self) -> usize {
        self.visited_blocks
    }

    /// Number of bytes examined during bounded traversal.
    #[pygetset]
    fn scanned_bytes(&self) -> usize {
        self.scanned_bytes
    }
}

pub(crate) fn export_tables(symbols: &PeExportMap) -> Vec<&ExportTable> {
    symbols.map().tables().collect()
}

pub(crate) fn address_resolve_options(
    nearest: OptionalArg<bool>,
    forwarders: OptionalArg<bool>,
) -> ImportAddressResolveOptions {
    let mode = if nearest.unwrap_or(false) {
        ImportAddressResolveMode::Nearest
    } else {
        ImportAddressResolveMode::Exact
    };

    ImportAddressResolveOptions {
        mode,
        resolve_forwarders: forwarders.unwrap_or(false),
        api_set_map: None,
    }
}

pub(crate) fn import_code_reference_to_py(
    reference: ImportCodeReference,
    vm: &VirtualMachine,
) -> PyRef<PeImportCodeReference> {
    PeImportCodeReference {
        reference_rva: reference.reference_rva,
        kind: reference.kind,
        target_address: reference.target_address,
        export_address: reference.export_address,
        iat_rva: reference.iat_rva,
        module_name: reference.module_name,
        name: reference.name,
        ordinal: reference.ordinal,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn import_code_trace_to_py(trace: ImportCodeTrace, vm: &VirtualMachine) -> PyRef<PeImportCodeTrace> {
    let references = trace
        .references
        .into_iter()
        .map(|reference| import_code_reference_to_py(reference, vm))
        .collect::<Vec<_>>();

    PeImportCodeTrace {
        references: PyListOf::new(references, vm),
        visited_blocks: trace.visited_blocks,
        scanned_bytes: trace.scanned_bytes,
    }
    .into_ref(&vm.ctx)
}
