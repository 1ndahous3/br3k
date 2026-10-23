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
    fn directory_rva(&self) -> u32 { self.candidate.directory_rva }

    /// Delay-import directory size in bytes.
    #[pygetset]
    fn directory_size(&self) -> u32 { self.candidate.directory_size }

    /// Decoded descriptors belonging to this candidate directory.
    #[pygetset]
    fn descriptors(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportDescriptor>> { delay_import_descriptors_to_py(&self.candidate.descriptors, vm) }
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
    fn status(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::delay_imports::DelayImportRecoveryStatus>> {
        PyEnumValue::new(self.recovery.status, vm)
    }

    /// Number of bytes inspected during discovery.
    #[pygetset]
    fn scanned_bytes(&self) -> usize { self.recovery.scanned_bytes }

    /// Additional recovery explanation or failure detail, when available.
    #[pygetset]
    fn diagnostic(&self) -> Option<String> { self.recovery.diagnostic.clone() }

    /// Plausible recovered directories; multiple candidates may be ambiguous.
    #[pygetset]
    fn candidates(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportCandidate>> {
        PyListOf::new(self.recovery.candidates.iter().cloned()
            .map(|candidate| PeDelayImportCandidate { candidate }.into_ref(&vm.ctx)).collect(), vm)
    }

    /// Return the unambiguously selected candidate, or None when none is selected.
    #[pymethod]
    fn selected(&self, vm: &VirtualMachine) -> Option<PyRef<PeDelayImportCandidate>> {
        match self.recovery.selected() {
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
    fn index(&self) -> usize {
        self.function.index
    }

    /// RVA of the import-name table or this function's slot within it.
    #[pygetset]
    fn import_name_table_rva(&self) -> u32 {
        self.function.import_name_table_rva
    }

    /// RVA of the delay IAT or the corresponding function slot.
    #[pygetset]
    fn import_address_table_rva(&self) -> Option<u32> {
        self.function.import_address_table_rva
    }

    /// Uninterpreted import-name-table thunk value.
    #[pygetset]
    fn raw_value(&self) -> u64 {
        self.function.raw_value
    }

    /// RVA of the import-by-name record, when decoded.
    #[pygetset]
    fn name_rva(&self) -> Option<u32> {
        self.function.name_rva
    }

    /// Import-name hint, when available.
    #[pygetset]
    fn hint(&self) -> Option<u16> {
        self.function.hint
    }

    /// Decoded import name, when present.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.function.name.clone()
    }

    /// Decoded import ordinal, when present.
    #[pygetset]
    fn ordinal(&self) -> Option<u16> {
        self.function.ordinal
    }

    /// Whether this thunk encodes an ordinal import.
    #[pygetset]
    fn by_ordinal(&self) -> bool {
        self.function.ordinal.is_some()
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(&self) -> String {
        match (&self.function.name, self.function.ordinal) {
            (Some(name), _) => format!(
                "#{index} {name} hint={hint} int=0x{int_rva:x} iat={iat}",
                index = self.function.index,
                hint = self.function.hint.unwrap_or(0),
                int_rva = self.function.import_name_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
            ),
            (None, Some(ordinal)) => format!(
                "#{index} ordinal={ordinal} int=0x{int_rva:x} iat={iat}",
                index = self.function.index,
                int_rva = self.function.import_name_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
            ),
            (None, None) => format!(
                "#{index} raw=0x{raw:x} int=0x{int_rva:x} iat={iat}",
                index = self.function.index,
                raw = self.function.raw_value,
                int_rva = self.function.import_name_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
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
    fn index(&self) -> usize {
        self.descriptor.index
    }

    /// Image-relative address of this delay-load descriptor.
    #[pygetset]
    fn descriptor_rva(&self) -> u32 {
        self.descriptor.descriptor_rva
    }

    /// Raw delay-load descriptor attribute flags.
    #[pygetset]
    fn attributes(&self) -> u32 {
        self.descriptor.attributes
    }

    /// Whether descriptor addresses were encoded as RVAs rather than VAs.
    #[pygetset]
    fn rva_based(&self) -> bool {
        self.descriptor.rva_based
    }

    /// RVA of the DLL-name string, when available.
    #[pygetset]
    fn dll_name_rva(&self) -> Option<u32> {
        self.descriptor.dll_name_rva
    }

    /// Decoded dependency DLL name, when available.
    #[pygetset]
    fn dll_name(&self) -> Option<String> {
        self.descriptor.dll_name.clone()
    }

    /// RVA of the delay-loader module-handle storage.
    #[pygetset]
    fn module_handle_rva(&self) -> Option<u32> {
        self.descriptor.module_handle_rva
    }

    /// RVA of the delay IAT or the corresponding function slot.
    #[pygetset]
    fn import_address_table_rva(&self) -> Option<u32> {
        self.descriptor.import_address_table_rva
    }

    /// RVA of the import-name table or this function's slot within it.
    #[pygetset]
    fn import_name_table_rva(&self) -> Option<u32> {
        self.descriptor.import_name_table_rva
    }

    /// RVA of the bound delay IAT, when present.
    #[pygetset]
    fn bound_import_address_table_rva(&self) -> Option<u32> {
        self.descriptor.bound_import_address_table_rva
    }

    /// RVA of the unload-information table, when present.
    #[pygetset]
    fn unload_information_table_rva(&self) -> Option<u32> {
        self.descriptor.unload_information_table_rva
    }

    /// Binding timestamp stored in the descriptor.
    #[pygetset]
    fn time_date_stamp(&self) -> u32 {
        self.descriptor.time_date_stamp
    }

    /// Number of decoded or rebuilt delayed imports.
    #[pygetset]
    fn import_count(&self) -> usize {
        self.descriptor.import_count()
    }

    /// Functions decoded from this delay-load descriptor.
    #[pygetset]
    fn imports(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeDelayImportFunction>> {
        delay_import_functions_to_py(&self.descriptor.imports, vm)
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{} imports={} rva=0x{:x} iat={} int={}",
            self.descriptor
                .dll_name
                .as_deref()
                .unwrap_or("<unnamed>"),
            self.descriptor.import_count(),
            self.descriptor.descriptor_rva,
            optional_rva_text(self.descriptor.import_address_table_rva),
            optional_rva_text(self.descriptor.import_name_table_rva),
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
    fn image(&self, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(self.result.image.clone())
    }

    /// RVA of the section containing rebuilt delay-import metadata.
    #[pygetset]
    fn section_rva(&self) -> u32 {
        self.result.section_rva
    }

    /// Generated section size in bytes.
    #[pygetset]
    fn section_size(&self) -> u32 {
        self.result.section_size
    }

    /// Image-relative address of the delay-import directory.
    #[pygetset]
    fn directory_rva(&self) -> u32 {
        self.result.directory_rva
    }

    /// Delay-import directory size in bytes.
    #[pygetset]
    fn directory_size(&self) -> u32 {
        self.result.directory_size
    }

    /// Number of rebuilt delay-load descriptors.
    #[pygetset]
    fn descriptor_count(&self) -> usize {
        self.result.descriptor_count
    }

    /// Number of decoded or rebuilt delayed imports.
    #[pygetset]
    fn import_count(&self) -> usize {
        self.result.import_count
    }

    /// Format import identities, table locations, or rebuild counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "section=0x{:x}/0x{:x} directory=0x{:x}/0x{:x} descriptors={} imports={}",
            self.result.section_rva,
            self.result.section_size,
            self.result.directory_rva,
            self.result.directory_size,
            self.result.descriptor_count,
            self.result.import_count
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
