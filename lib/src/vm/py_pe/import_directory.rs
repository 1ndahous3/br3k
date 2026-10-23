use crate::vm::prelude::*;

use crate::pe::imports::{ImportDescriptor, ImportDescriptorFunction};

/// A parsed import lookup/address-table entry, preserving raw values and decoded identity.
#[pyclass(module = "br3k.pe.imports", name = "DescriptorFunction")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportDescriptorFunction {
    function: ImportDescriptorFunction,
}

#[pyclass]
impl PeImportDescriptorFunction {
    /// Zero-based position in the containing descriptor or import table.
    #[pygetset]
    fn index(&self) -> usize {
        self.function.index
    }

    /// RVA of this import's lookup-table slot.
    #[pygetset]
    fn import_lookup_table_rva(&self) -> u32 {
        self.function.import_lookup_table_rva
    }

    /// RVA of the corresponding IAT slot, when available.
    #[pygetset]
    fn import_address_table_rva(&self) -> Option<u32> {
        self.function.import_address_table_rva
    }

    /// Uninterpreted lookup-slot value from the image.
    #[pygetset]
    fn raw_lookup_value(&self) -> u64 {
        self.function.raw_lookup_value
    }

    /// Uninterpreted IAT-slot value, when readable.
    #[pygetset]
    fn raw_address_value(&self) -> Option<u64> {
        self.function.raw_address_value
    }

    /// RVA of the IMAGE_IMPORT_BY_NAME record, for named imports.
    #[pygetset]
    fn name_rva(&self) -> Option<u32> {
        self.function.name_rva
    }

    /// Import-name hint, when decoded.
    #[pygetset]
    fn hint(&self) -> Option<u16> {
        self.function.hint
    }

    /// Decoded import name, when present.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.function.name.clone()
    }

    /// Decoded ordinal for ordinal-based imports.
    #[pygetset]
    fn ordinal(&self) -> Option<u16> {
        self.function.ordinal
    }

    /// Whether this entry uses an ordinal instead of a name.
    #[pygetset]
    fn by_ordinal(&self) -> bool {
        self.function.ordinal.is_some()
    }

    /// Format the descriptor or import identity and table locations.
    #[pymethod]
    fn summary(&self) -> String {
        match (&self.function.name, self.function.ordinal) {
            (Some(name), _) => format!(
                "#{index} {name} hint={hint} ilt=0x{ilt_rva:x} iat={iat}",
                index = self.function.index,
                hint = self.function.hint.unwrap_or(0),
                ilt_rva = self.function.import_lookup_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
            ),
            (None, Some(ordinal)) => format!(
                "#{index} ordinal={ordinal} ilt=0x{ilt_rva:x} iat={iat}",
                index = self.function.index,
                ilt_rva = self.function.import_lookup_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
            ),
            (None, None) => format!(
                "#{index} raw=0x{raw:x} ilt=0x{ilt_rva:x} iat={iat}",
                index = self.function.index,
                raw = self.function.raw_lookup_value,
                ilt_rva = self.function.import_lookup_table_rva,
                iat = optional_rva_text(self.function.import_address_table_rva),
            ),
        }
    }
}

/// A parsed IMAGE_IMPORT_DESCRIPTOR and its decoded lookup entries.
///
/// Optional addresses/names indicate unavailable or absent metadata; this is a
/// snapshot of declared imports, not the editable recovery model.
#[pyclass(module = "br3k.pe.imports", name = "Descriptor")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportDescriptor {
    descriptor: ImportDescriptor,
}

#[pyclass]
impl PeImportDescriptor {
    /// Whether imports were decoded from the original lookup table or an IAT fallback.
    #[pygetset]
    fn lookup_kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportLookupKind>> {
        PyEnumValue::new(self.descriptor.lookup_kind, vm)
    }

    /// Zero-based position in the containing descriptor or import table.
    #[pygetset]
    fn index(&self) -> usize {
        self.descriptor.index
    }

    /// RVA of this IMAGE_IMPORT_DESCRIPTOR.
    #[pygetset]
    fn descriptor_rva(&self) -> u32 {
        self.descriptor.descriptor_rva
    }

    /// OriginalFirstThunk RVA, when nonzero/available.
    #[pygetset]
    fn original_first_thunk_rva(&self) -> Option<u32> {
        self.descriptor.original_first_thunk_rva
    }

    /// Raw import-descriptor TimeDateStamp field.
    #[pygetset]
    fn time_date_stamp(&self) -> u32 {
        self.descriptor.time_date_stamp
    }

    /// Raw ForwarderChain field.
    #[pygetset]
    fn forwarder_chain(&self) -> u32 {
        self.descriptor.forwarder_chain
    }

    /// RVA of the descriptor's DLL-name string, when available.
    #[pygetset]
    fn dll_name_rva(&self) -> Option<u32> {
        self.descriptor.dll_name_rva
    }

    /// Decoded DLL name, when available.
    #[pygetset]
    fn dll_name(&self) -> Option<String> {
        self.descriptor.dll_name.clone()
    }

    /// FirstThunk RVA naming the IAT, when available.
    #[pygetset]
    fn first_thunk_rva(&self) -> Option<u32> {
        self.descriptor.first_thunk_rva
    }

    /// Number of decoded imports in this descriptor.
    #[pygetset]
    fn import_count(&self) -> usize {
        self.descriptor.import_count()
    }

    /// Decoded import entries belonging to this descriptor.
    #[pygetset]
    fn imports(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeImportDescriptorFunction>> {
        import_descriptor_functions_to_py(&self.descriptor.imports, vm)
    }

    /// Format the descriptor or import identity and table locations.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{} imports={} rva=0x{:x} oft={} ft={}",
            self.descriptor.dll_name.as_deref().unwrap_or("<unnamed>"),
            self.descriptor.import_count(),
            self.descriptor.descriptor_rva,
            optional_rva_text(self.descriptor.original_first_thunk_rva),
            optional_rva_text(self.descriptor.first_thunk_rva),
        )
    }
}

pub(crate) fn import_descriptors_to_py(
    descriptors: &[ImportDescriptor],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeImportDescriptor>> {
    let descriptors = descriptors
        .iter()
        .cloned()
        .map(|descriptor| PeImportDescriptor { descriptor }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(descriptors, vm)
}

fn import_descriptor_functions_to_py(
    functions: &[ImportDescriptorFunction],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeImportDescriptorFunction>> {
    let functions = functions
        .iter()
        .cloned()
        .map(|function| PeImportDescriptorFunction { function }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(functions, vm)
}

fn optional_rva_text(rva: Option<u32>) -> String {
    match rva {
        Some(rva) => format!("0x{rva:x}"),
        None => "none".to_string(),
    }
}
