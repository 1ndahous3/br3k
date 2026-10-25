use crate::vm::prelude::*;

use crate::pe::diagnostics::comparison as raw;
use super::owned::PeImage;
use std::sync::Arc;

/// Matched immutable capture/reference inputs with shared relocation normalization and coverage.
///
/// captured must have mapped layout and reference must have file layout. Machine,
/// timestamp, and SizeOfImage must match. Components run on demand against this
/// same pair. Unequal bytes are not by themselves evidence of malicious modification.
#[pyclass(module = "br3k.pe.analysis", name = "Comparison")]
#[derive(Clone, Debug, PyPayload)]
pub struct Comparison { inner: Arc<raw::Comparison> }

impl Comparison {
    pub(crate) fn new(captured: crate::pe::image::Image, reference: crate::pe::image::Image, vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self { inner: Arc::new(raw::Comparison::new(captured, reference).map_err(map_to_py_value_error(vm, "Unable to compare images"))?) })
    }
}

impl Constructor for Comparison {
    type Args = (PyRef<PeImage>, PyRef<PeImage>);
    /// Create a comparison of a mapped capture and its matching file-layout reference.
    fn py_new(_cls: &Py<PyType>, (captured, reference): Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        Self::new(captured.image.clone(), reference.image.clone(), vm)
    }
}

#[pyclass(with(Constructor))]
impl Comparison {
    /// Mapped image snapshot being examined.
    #[pygetset]
    fn captured(zelf: &Py<Self>) -> PeImage { PeImage::from_image(zelf.inner.captured.clone()) }
    /// File-layout reference image used as the baseline.
    #[pygetset]
    fn reference(zelf: &Py<Self>) -> PeImage { PeImage::from_image(zelf.inner.reference.clone()) }
    /// Whether the shared section/normalization context has no diagnostics.
    /// This does not certify optional components that have not run yet.
    #[pygetset]
    fn complete(zelf: &Py<Self>) -> bool { zelf.inner.complete() }
    /// Section comparison results using the shared relocation normalization.
    #[pygetset]
    fn sections(zelf: &Py<Self>) -> super::PeImageComparison { super::PeImageComparison::from_comparison(zelf.inner.sections.clone()) }
    /// On-demand comparison of exported entry-point bytes.
    #[pygetset]
    fn exports(zelf: &Py<Self>) -> Exports { Exports { inner: zelf.inner.clone() } }
    /// On-demand bounded comparison of changed byte ranges.
    #[pygetset]
    fn bytes(zelf: &Py<Self>) -> Bytes { Bytes { inner: zelf.inner.clone() } }
    /// On-demand comparison of IAT targets against supplied symbols.
    #[pygetset]
    fn imports(zelf: &Py<Self>) -> Imports { Imports { inner: zelf.inner.clone() } }
    /// On-demand comparison of resource metadata and payloads.
    #[pygetset]
    fn resources(zelf: &Py<Self>) -> Resources { Resources { inner: zelf.inner.clone() } }
    /// Coverage and normalization diagnostics for the shared comparison context.
    #[pygetset]
    fn diagnostics(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::diagnostic::Diagnostic>> {
        super::diagnostic::to_py(&zelf.inner.diagnostics, vm)
    }
}

/// Resource path, metadata, and payload comparison for one matched image pair.
#[pyclass(module = "br3k.pe.analysis", name = "ResourceComparison")]
#[derive(Clone, Debug, PyPayload)]
pub struct Resources { inner: Arc<raw::Comparison> }
#[pyclass]
impl Resources {
    /// Compare typed leaf paths and payload bytes, including equal-size changes.
    /// Malformed or unreadable resources raise ValueError, not an empty result.
    #[pymethod]
    fn changes(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<ResourceChange>>> {
        let changes = crate::pe::diagnostics::resources::compare(&zelf.inner.captured, &zelf.inner.reference)
            .map_err(map_to_py_value_error(vm, "Unable to compare resource payloads"))?;
        Ok(PyListOf::new(changes.into_iter().map(|change| ResourceChange { change }.into_ref(&vm.ctx)).collect(), vm))
    }
}

/// One resource leaf difference between reference-file and captured-image data.
#[pyclass(module = "br3k.pe.resources", name = "Change")]
#[derive(Clone, Debug, PyPayload)]
pub struct ResourceChange { change: crate::pe::diagnostics::resources::ResourceChange }
#[pyclass]
impl ResourceChange {
    /// Whether the resource was added, removed, or changed.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::diagnostics::resources::ResourceChangeKind>> { PyEnumValue::new(zelf.change.kind, vm) }
    /// Typed resource-tree path identifying this leaf.
    #[pygetset]
    fn path(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::image_resources::PeResourcePathEntry>> {
        PyListOf::new(zelf.change.path.iter().map(|entry| super::image_resources::resource_path_entry_to_py(entry, vm)).collect(), vm)
    }
    /// Reference resource entry, or None for an added leaf.
    #[pygetset]
    fn before(zelf: &Py<Self>, vm: &VirtualMachine) -> Option<PyRef<super::image_resources::PeResourceDataEntry>> { zelf.change.before.clone().map(|entry| super::image_resources::resource_data_entry_to_py(entry, vm)) }
    /// Captured resource entry, or None for a removed leaf.
    #[pygetset]
    fn after(zelf: &Py<Self>, vm: &VirtualMachine) -> Option<PyRef<super::image_resources::PeResourceDataEntry>> { zelf.change.after.clone().map(|entry| super::image_resources::resource_data_entry_to_py(entry, vm)) }
    /// Reference payload fingerprint, or None when no reference leaf exists.
    #[pygetset]
    fn before_hash(zelf: &Py<Self>) -> Option<u64> { zelf.change.before_hash }
    /// Captured payload fingerprint, or None when no captured leaf exists.
    #[pygetset]
    fn after_hash(zelf: &Py<Self>) -> Option<u64> { zelf.change.after_hash }
}

/// Export-entry byte comparisons for a matched image pair, with aliases grouped by RVA.
#[pyclass(module = "br3k.pe.analysis", name = "ExportChanges")]
#[derive(Clone, Debug, PyPayload)]
pub struct Exports { inner: Arc<raw::Comparison> }
#[pyclass]
impl Exports {
    /// Compare 16-byte export entries, grouping aliases by RVA. Read errors are not clean results.
    #[pymethod]
    fn changes(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<ExportChange>>> {
        let changes = zelf.inner.export_changes(16).map_err(map_to_py_value_error(vm, "Unable to compare export entries"))?;
        Ok(PyListOf::new(changes.into_iter().map(|change| ExportChange { change }.into_ref(&vm.ctx)).collect(), vm))
    }
}

/// Changed bytes at an exported entry point. A difference is evidence to inspect, not a hook classification.
#[pyclass(module = "br3k.pe.analysis", name = "ExportChange")]
#[derive(Clone, Debug, PyPayload)]
pub struct ExportChange { change: raw::ExportChange }
#[pyclass]
impl ExportChange {
    /// RVA shared by the exported entry point and its aliases.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 { zelf.change.rva }
    /// Name of the section containing the entry point.
    #[pygetset]
    fn section(zelf: &Py<Self>) -> String { zelf.change.section.clone() }
    /// All export names associated with this changed RVA.
    #[pygetset]
    fn names(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        PyListOf::new(zelf.change.names.iter().map(|name| vm.ctx.new_str(name.clone())).collect(), vm)
    }
    /// Reference bytes after relocation normalization.
    #[pygetset]
    fn before(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> { vm.ctx.new_bytes(zelf.change.before.clone()) }
    /// Original reference-file evidence before normalization.
    #[pygetset]
    fn raw_before(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> { vm.ctx.new_bytes(zelf.change.raw_before.clone()) }
    /// Original captured bytes at the exported entry point.
    #[pygetset]
    fn after(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> { vm.ctx.new_bytes(zelf.change.after.clone()) }
}

/// Byte differences use the same relocation normalization and section correspondence as the summary.
#[pyclass(module = "br3k.pe.analysis", name = "ByteComparison")]
#[derive(Clone, Debug, PyPayload)]
pub struct Bytes { inner: Arc<raw::Comparison> }
#[pyclass]
impl Bytes {
    /// Compare bounded changed ranges. Check the returned truncated flag before
    /// treating the range list as exhaustive; missing bytes raise ValueError.
    #[pymethod]
    fn changes(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<super::diagnostics::PeImageByteChanges> {
        Ok(super::diagnostics::PeImageByteChanges { changes: zelf.inner.byte_changes(Default::default()).map_err(map_to_py_value_error(vm, "Unable to compare bytes"))? })
    }
}

/// IAT comparison against expected targets resolved from a supplied symbol index.
#[pyclass(module = "br3k.pe.analysis", name = "ImportComparison")]
#[derive(Clone, Debug, PyPayload)]
pub struct Imports { inner: Arc<raw::Comparison> }
#[pyclass]
impl Imports {
    /// Compare live slots and retain unresolved expectations in result diagnostics.
    /// An empty change list alone does not imply a complete or clean IAT check.
    #[pymethod]
    fn changes(zelf: &Py<Self>, symbols: PyRef<super::PeExportMap>, vm: &VirtualMachine) -> PyResult<ImportChanges> {
        Ok(ImportChanges { report: zelf.inner.import_changes(symbols.map()).map_err(map_to_py_value_error(vm, "Unable to compare import addresses"))? })
    }
}

/// Changed IAT targets and unresolved expectations. Empty changes alone do not imply a clean IAT.
#[pyclass(module = "br3k.pe.analysis", name = "ImportChanges")]
#[derive(Clone, Debug, PyPayload)]
pub struct ImportChanges { report: crate::pe::diagnostics::ImportComparison }
#[pyclass]
impl ImportChanges {
    /// Whether the IAT comparison finished without unresolved-expectation diagnostics.
    #[pygetset]
    fn complete(zelf: &Py<Self>) -> bool { zelf.report.diagnostics.is_empty() }
    /// Unresolved expectations or incomplete checks encountered during IAT comparison.
    #[pygetset]
    fn diagnostics(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::diagnostic::Diagnostic>> { super::diagnostic::to_py(&zelf.report.diagnostics, vm) }
    /// IAT entries whose observed targets differ from resolved expectations.
    #[pygetset]
    fn changes(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::diagnostics::PeImportAddressChange>> {
        PyListOf::new(zelf.report.changes.iter().cloned().map(|change| super::diagnostics::PeImportAddressChange { change }.into_ref(&vm.ctx)).collect(), vm)
    }
}
