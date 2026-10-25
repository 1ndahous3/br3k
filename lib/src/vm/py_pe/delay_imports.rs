use crate::vm::prelude::*;

use crate::pe::delay_imports::{
    DelayImportCandidate, DelayImportDescriptor, DelayImportFunction, DelayImportRebuild, DelayImportRecovery,
};

#[derive(FromArgs)]
pub struct RecoverDelayImportsArgs {
    #[pyarg(named, optional)]
    pub reference: OptionalArg<PyRef<super::owned::PeImage>>,
}

/// A plausible delay-import directory recovered from image bytes.
#[pyclass(module = "br3k.pe.imports", name = "DelayCandidate")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDelayImportCandidate {
    candidate: DelayImportCandidate,
}

#[pyclass]
impl PeDelayImportCandidate {
    /// Image-relative address of the delay-import directory.
    #[pygetset]
    fn directory_rva(zelf: &Py<Self>) -> u32 { zelf.candidate.directory_rva }

    /// Delay-import directory size in bytes.
    #[pygetset]
    fn directory_size(zelf: &Py<Self>) -> u32 { zelf.candidate.directory_size }

    /// Decoded descriptors belonging to this candidate directory.
    #[pygetset]
    fn descriptors(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportDescriptor>> { delay_import_descriptors_to_py(&zelf.candidate.descriptors, vm) }
}

/// Delay-import discovery status, bounded scan evidence, and candidate selection.
#[pyclass(module = "br3k.pe.imports", name = "DelayRecovery")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDelayImportRecovery {
    pub(crate) recovery: DelayImportRecovery,
}

#[pyclass]
impl PeDelayImportRecovery {
    /// Typed recovery/ambiguity status; inspect before consuming a candidate.
    #[pygetset]
    fn status(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::delay_imports::DelayImportRecoveryStatus>> {
        PyEnumValue::new(zelf.recovery.status, vm)
    }

    /// Number of bytes inspected during discovery.
    #[pygetset]
    fn scanned_bytes(zelf: &Py<Self>) -> usize { zelf.recovery.scanned_bytes }

    /// Additional recovery explanation or failure detail, when available.
    #[pygetset]
    fn diagnostic(zelf: &Py<Self>) -> Option<String> { zelf.recovery.diagnostic.clone() }

    /// Plausible recovered directories; multiple candidates may be ambiguous.
    #[pygetset]
    fn candidates(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportCandidate>> {
        PyListOf::new(zelf.recovery.candidates.iter().cloned()
            .map(|candidate| PeDelayImportCandidate { candidate }.into_ref(&vm.ctx)).collect(), vm)
    }

    /// Return the unambiguously selected candidate, or None when none is selected.
    #[pymethod]
    fn selected(zelf: &Py<Self>, vm: &VirtualMachine) -> Option<PyRef<PeDelayImportCandidate>> {
        match zelf.recovery.selected() {
            Some(candidate) => Some(PeDelayImportCandidate { candidate: candidate.clone() }.into_ref(&vm.ctx)),
            None => None,
        }
    }
}

/// Parsed delayed import preserving its raw thunk value and decoded name or ordinal.
#[pyclass(module = "br3k.pe.imports", name = "DelayFunction")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDelayImportFunction {
    function: DelayImportFunction,
}

#[pyclass]
impl PeDelayImportFunction {
    /// Zero-based position in the containing descriptor or thunk table.
    #[pygetset]
    fn index(zelf: &Py<Self>) -> usize {
        zelf.function.index
    }

    /// RVA of the import-name table or this function's slot within it.
    #[pygetset]
    fn import_name_table_rva(zelf: &Py<Self>) -> u32 {
        zelf.function.import_name_table_rva
    }

    /// RVA of the delay IAT or the corresponding function slot.
    #[pygetset]
    fn import_address_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.function.import_address_table_rva
    }

    /// Uninterpreted import-name-table thunk value.
    #[pygetset]
    fn raw_value(zelf: &Py<Self>) -> u64 {
        zelf.function.raw_value
    }

    /// RVA of the import-by-name record, when decoded.
    #[pygetset]
    fn name_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.function.name_rva
    }

    /// Import-name hint, when available.
    #[pygetset]
    fn hint(zelf: &Py<Self>) -> Option<u16> {
        zelf.function.hint
    }

    /// Decoded import name, when present.
    #[pygetset]
    fn name(zelf: &Py<Self>) -> Option<String> {
        zelf.function.name.clone()
    }

    /// Decoded import ordinal, when present.
    #[pygetset]
    fn ordinal(zelf: &Py<Self>) -> Option<u16> {
        zelf.function.ordinal
    }

    /// Whether this thunk encodes an ordinal import.
    #[pygetset]
    fn by_ordinal(zelf: &Py<Self>) -> bool {
        zelf.function.ordinal.is_some()
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        match (&zelf.function.name, zelf.function.ordinal) {
            (Some(name), _) => format!(
                "#{index} {name} hint={hint} int=0x{int_rva:x} iat={iat}",
                index = zelf.function.index,
                hint = zelf.function.hint.unwrap_or(0),
                int_rva = zelf.function.import_name_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
            ),
            (None, Some(ordinal)) => format!(
                "#{index} ordinal={ordinal} int=0x{int_rva:x} iat={iat}",
                index = zelf.function.index,
                int_rva = zelf.function.import_name_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
            ),
            (None, None) => format!(
                "#{index} raw=0x{raw:x} int=0x{int_rva:x} iat={iat}",
                index = zelf.function.index,
                raw = zelf.function.raw_value,
                int_rva = zelf.function.import_name_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
            ),
        }
    }
}

/// Parsed delay-load descriptor. Address fields are normalized to RVAs when possible.
#[pyclass(module = "br3k.pe.imports", name = "DelayDescriptor")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDelayImportDescriptor {
    descriptor: DelayImportDescriptor,
}

impl PeDelayImportDescriptor {
    pub(crate) fn descriptor_clone(&self) -> DelayImportDescriptor {
        self.descriptor.clone()
    }
}

#[pyclass]
impl PeDelayImportDescriptor {
    /// Zero-based position in the containing descriptor or thunk table.
    #[pygetset]
    fn index(zelf: &Py<Self>) -> usize {
        zelf.descriptor.index
    }

    /// Image-relative address of this delay-load descriptor.
    #[pygetset]
    fn descriptor_rva(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.descriptor_rva
    }

    /// Raw delay-load descriptor attribute flags.
    #[pygetset]
    fn attributes(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.attributes
    }

    /// Whether descriptor addresses were encoded as RVAs rather than VAs.
    #[pygetset]
    fn rva_based(zelf: &Py<Self>) -> bool {
        zelf.descriptor.rva_based
    }

    /// RVA of the DLL-name string, when available.
    #[pygetset]
    fn dll_name_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.dll_name_rva
    }

    /// Decoded dependency DLL name, when available.
    #[pygetset]
    fn dll_name(zelf: &Py<Self>) -> Option<String> {
        zelf.descriptor.dll_name.clone()
    }

    /// RVA of the delay-loader module-handle storage.
    #[pygetset]
    fn module_handle_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.module_handle_rva
    }

    /// RVA of the delay IAT or the corresponding function slot.
    #[pygetset]
    fn import_address_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.import_address_table_rva
    }

    /// RVA of the import-name table or this function's slot within it.
    #[pygetset]
    fn import_name_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.import_name_table_rva
    }

    /// RVA of the bound delay IAT, when present.
    #[pygetset]
    fn bound_import_address_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.bound_import_address_table_rva
    }

    /// RVA of the unload-information table, when present.
    #[pygetset]
    fn unload_information_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.unload_information_table_rva
    }

    /// Binding timestamp stored in the descriptor.
    #[pygetset]
    fn time_date_stamp(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.time_date_stamp
    }

    /// Number of decoded or rebuilt delayed imports.
    #[pygetset]
    fn import_count(zelf: &Py<Self>) -> usize {
        zelf.descriptor.import_count()
    }

    /// Functions decoded from this delay-load descriptor.
    #[pygetset]
    fn imports(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportFunction>> {
        delay_import_functions_to_py(&zelf.descriptor.imports, vm)
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "{} imports={} rva=0x{:x} iat={} int={}",
            zelf.descriptor
                .dll_name
                .as_deref()
                .unwrap_or("<unnamed>"),
            zelf.descriptor.import_count(),
            zelf.descriptor.descriptor_rva,
            optional_rva_text(zelf.descriptor.import_address_table_rva),
            optional_rva_text(zelf.descriptor.import_name_table_rva),
        )
    }
}

/// Rebuilt delay-import bytes and generated section/directory extents.
#[pyclass(module = "br3k.pe.imports", name = "DelayRebuild")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDelayImportRebuild {
    result: DelayImportRebuild,
}

#[pyclass]
impl PeDelayImportRebuild {
    /// Independent bytes produced by the delay-import rebuild.
    #[pygetset]
    fn image(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(zelf.result.image.clone())
    }

    /// RVA of the section containing rebuilt delay-import metadata.
    #[pygetset]
    fn section_rva(zelf: &Py<Self>) -> u32 {
        zelf.result.section_rva
    }

    /// Generated section size in bytes.
    #[pygetset]
    fn section_size(zelf: &Py<Self>) -> u32 {
        zelf.result.section_size
    }

    /// Image-relative address of the delay-import directory.
    #[pygetset]
    fn directory_rva(zelf: &Py<Self>) -> u32 {
        zelf.result.directory_rva
    }

    /// Delay-import directory size in bytes.
    #[pygetset]
    fn directory_size(zelf: &Py<Self>) -> u32 {
        zelf.result.directory_size
    }

    /// Number of rebuilt delay-load descriptors.
    #[pygetset]
    fn descriptor_count(zelf: &Py<Self>) -> usize {
        zelf.result.descriptor_count
    }

    /// Number of decoded or rebuilt delayed imports.
    #[pygetset]
    fn import_count(zelf: &Py<Self>) -> usize {
        zelf.result.import_count
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "section=0x{:x}/0x{:x} directory=0x{:x}/0x{:x} descriptors={} imports={}",
            zelf.result.section_rva,
            zelf.result.section_size,
            zelf.result.directory_rva,
            zelf.result.directory_size,
            zelf.result.descriptor_count,
            zelf.result.import_count
        )
    }
}

pub(crate) fn delay_import_descriptors_to_py(
    descriptors: &[DelayImportDescriptor],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeDelayImportDescriptor>> {
    let descriptors = descriptors
        .iter()
        .cloned()
        .map(|descriptor| PeDelayImportDescriptor { descriptor }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(descriptors, vm)
}

fn delay_import_functions_to_py(
    functions: &[DelayImportFunction],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeDelayImportFunction>> {
    let functions = functions
        .iter()
        .cloned()
        .map(|function| PeDelayImportFunction { function }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(functions, vm)
}

pub(crate) fn delay_import_rebuild_to_py(
    result: DelayImportRebuild,
    vm: &VirtualMachine,
) -> PyRef<PeDelayImportRebuild> {
    PeDelayImportRebuild { result }.into_ref(&vm.ctx)
}

fn optional_rva_text(rva: Option<u32>) -> String {
    match rva {
        Some(rva) => format!("0x{rva:x}"),
        None => "none".to_string(),
    }
}
