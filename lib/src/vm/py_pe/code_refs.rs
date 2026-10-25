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
    /// RVA of the instruction or code pattern containing the reference.
    #[pymember]
    reference_rva: u32,
    kind: ImportCodeReferenceKind,
    /// Target virtual address obtained from the recognized pattern before export matching.
    #[pymember]
    target_address: u64,
    /// Virtual address of the export selected by resolution.
    #[pymember]
    export_address: u64,
    /// RVA of the associated IAT slot, or None for a reference without an identified slot.
    #[pymember]
    iat_rva: Option<PyRef<PyInt>>,
    /// Module name associated with the resolved export.
    #[pymember]
    module_name: PyStrRef,
    /// Export name when available; ordinal-only exports return None.
    #[pymember]
    name: Option<PyStrRef>,
    /// Resolved export ordinal.
    #[pymember]
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
            iat_rva: self.iat_rva.as_ref().map(|value| value.as_u32_mask()),
            module_name: self.module_name.to_string(),
            name: self.name.as_ref().map(ToString::to_string),
            ordinal: self.ordinal,
        }
    }

    /// Architecture-specific kind of recognized API-reference pattern.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportCodeReferenceKind>> {
        PyEnumValue::new(zelf.kind, vm)
    }

    /// Whether this reference carries an identified IAT slot RVA.
    #[pygetset]
    fn uses_iat(zelf: &Py<Self>) -> bool {
        zelf.iat_rva.is_some()
    }

    /// Whether the recognized branch kind has a supported rewrite form. Placement and range checks may still reject a build.
    #[pygetset]
    fn patchable_direct_branch(zelf: &Py<Self>) -> bool {
        zelf.kind.is_patchable_direct_branch()
    }
}

/// API references and work counters from a bounded static code trace. Not a runtime execution trace.
#[py_api]
#[pyclass(module = "br3k.pe.code", name = "Trace")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportCodeTrace {
    /// API-reference records collected by the trace.
    #[pyi(ty = "list[br3k.pe.code.Reference]")]
    #[pymember]
    references: PyListRef,
    /// Number of code blocks visited before traversal ended or reached its limits.
    #[pymember]
    visited_blocks: PyRef<PyInt>,
    /// Number of bytes examined during bounded traversal.
    #[pymember]
    scanned_bytes: PyRef<PyInt>,
}

#[pyclass]
impl PeImportCodeTrace {}

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
        iat_rva: reference.iat_rva.map(|value| vm.ctx.new_int(value)),
        module_name: vm.ctx.new_str(reference.module_name),
        name: reference.name.map(|value| vm.ctx.new_str(value)),
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
        references: PyListOf::new(references, vm).into(),
        visited_blocks: vm.ctx.new_int(trace.visited_blocks),
        scanned_bytes: vm.ctx.new_int(trace.scanned_bytes),
    }
    .into_ref(&vm.ctx)
}
