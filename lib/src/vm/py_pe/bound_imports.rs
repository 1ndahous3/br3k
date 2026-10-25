use crate::vm::prelude::*;

use crate::pe::bound_imports::{BoundForwarderRef, BoundImportCheck, BoundImportDescriptor};
use crate::vm::py_pe::exports::{export_table_source_to_py, PeExportMap};

#[derive(FromArgs)]
pub struct BoundImportChecksArgs {
    #[pyarg(any)]
    pub export_map: PyRef<PeExportMap>,
}

/// Bound-import dependency check against known export-table timestamps and sources.
#[pyclass(module = "br3k.pe.imports", name = "BoundCheck")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeBoundImportCheck {
    check: BoundImportCheck,
}

#[pyclass]
impl PeBoundImportCheck {
    /// Image-relative location of the bound record being described or checked.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 { zelf.check.rva }

    /// DLL name of the bound dependency.
    #[pygetset]
    fn dll_name(zelf: &Py<Self>) -> String { zelf.check.dll_name.clone() }

    /// Typed distinction between a bound import and a bound forwarder.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::bound_imports::BoundImportKind>> {
        PyEnumValue::new(zelf.check.kind, vm)
    }

    /// Typed result of the dependency/timestamp check.
    #[pygetset]
    fn status(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::bound_imports::BoundImportStatus>> {
        PyEnumValue::new(zelf.check.status, vm)
    }

    /// Timestamp declared by the bound record, when usable.
    #[pygetset]
    fn expected_timestamp(zelf: &Py<Self>) -> Option<u32> { zelf.check.expected_timestamp }

    /// Timestamp from the matched dependency image, when available.
    #[pygetset]
    fn dependency_timestamp(zelf: &Py<Self>) -> Option<u32> { zelf.check.dependency_timestamp }

    /// Export-table source used for the dependency check, when available.
    #[pygetset]
    fn dependency_source(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<Option<PyEnumValue<crate::pe::export_map::ExportTableSource>>> {
        export_table_source_to_py(zelf.check.dependency_source, vm)
    }

    /// Raw reserved forwarder field, when applicable.
    #[pygetset]
    fn reserved(zelf: &Py<Self>) -> Option<u16> { zelf.check.reserved }

    /// Forwarder dependencies or their validation results.
    #[pygetset]
    fn forwarders(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeBoundImportCheck>> { bound_import_checks_to_py(&zelf.check.forwarders, vm) }

    /// Return whether this record and its forwarders match the known dependencies.
    #[pymethod]
    fn matches_dependencies(zelf: &Py<Self>) -> bool { zelf.check.matches_dependencies() }
}

pub(crate) fn bound_import_checks_to_py(checks: &[BoundImportCheck], vm: &VirtualMachine) -> PyListOf<PyRef<PeBoundImportCheck>> {
    PyListOf::new(checks.iter().cloned().map(|check| PeBoundImportCheck { check }.into_ref(&vm.ctx)).collect(), vm)
}

/// Parsed bound-import forwarder reference with DLL name and binding timestamp.
#[pyclass(module = "br3k.pe.imports", name = "BoundForwarder")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeBoundForwarderRef {
    forwarder: BoundForwarderRef,
}

#[pyclass]
impl PeBoundForwarderRef {
    /// Image-relative location of the bound record being described or checked.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 {
        zelf.forwarder.rva
    }

    /// DLL-name offset relative to the bound-import directory base.
    #[pygetset]
    fn module_name_offset(zelf: &Py<Self>) -> u16 {
        zelf.forwarder.module_name_offset
    }

    /// DLL name of the bound dependency.
    #[pygetset]
    fn dll_name(zelf: &Py<Self>) -> String {
        zelf.forwarder.dll_name.clone()
    }

    /// Timestamp stored when the dependency was bound.
    #[pygetset]
    fn time_date_stamp(zelf: &Py<Self>) -> u32 {
        zelf.forwarder.time_date_stamp
    }

    /// Raw reserved forwarder field, when applicable.
    #[pygetset]
    fn reserved(zelf: &Py<Self>) -> u16 {
        zelf.forwarder.reserved
    }
}

/// Parsed bound-import descriptor and its forwarder dependencies.
#[pyclass(module = "br3k.pe.imports", name = "BoundDescriptor")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeBoundImportDescriptor {
    descriptor: BoundImportDescriptor,
}

#[pyclass]
impl PeBoundImportDescriptor {
    /// RVA of the bound-import descriptor.
    #[pygetset]
    fn descriptor_rva(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.descriptor_rva
    }

    /// DLL-name offset relative to the bound-import directory base.
    #[pygetset]
    fn module_name_offset(zelf: &Py<Self>) -> u16 {
        zelf.descriptor.module_name_offset
    }

    /// DLL name of the bound dependency.
    #[pygetset]
    fn dll_name(zelf: &Py<Self>) -> String {
        zelf.descriptor.dll_name.clone()
    }

    /// Timestamp stored when the dependency was bound.
    #[pygetset]
    fn time_date_stamp(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.time_date_stamp
    }

    /// Forwarder dependencies or their validation results.
    #[pygetset]
    fn forwarders(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeBoundForwarderRef>> {
        let forwarders = zelf.descriptor.forwarders.iter().cloned()
            .map(|forwarder| PeBoundForwarderRef { forwarder }.into_ref(&vm.ctx))
            .collect();
        PyListOf::new(forwarders, vm)
    }
}

pub(crate) fn bound_import_descriptors_to_py(descriptors: Vec<BoundImportDescriptor>, vm: &VirtualMachine) -> PyListOf<PyRef<PeBoundImportDescriptor>> {
    let descriptors = descriptors.into_iter()
        .map(|descriptor| PeBoundImportDescriptor { descriptor }.into_ref(&vm.ctx))
        .collect();
    PyListOf::new(descriptors, vm)
}
