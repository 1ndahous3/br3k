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
    fn index(zelf: &Py<Self>) -> usize {
        zelf.function.index
    }

    /// RVA of this import's lookup-table slot.
    #[pygetset]
    fn import_lookup_table_rva(zelf: &Py<Self>) -> u32 {
        zelf.function.import_lookup_table_rva
    }

    /// RVA of the corresponding IAT slot, when available.
    #[pygetset]
    fn import_address_table_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.function.import_address_table_rva
    }

    /// Uninterpreted lookup-slot value from the image.
    #[pygetset]
    fn raw_lookup_value(zelf: &Py<Self>) -> u64 {
        zelf.function.raw_lookup_value
    }

    /// Uninterpreted IAT-slot value, when readable.
    #[pygetset]
    fn raw_address_value(zelf: &Py<Self>) -> Option<u64> {
        zelf.function.raw_address_value
    }

    /// RVA of the IMAGE_IMPORT_BY_NAME record, for named imports.
    #[pygetset]
    fn name_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.function.name_rva
    }

    /// Import-name hint, when decoded.
    #[pygetset]
    fn hint(zelf: &Py<Self>) -> Option<u16> {
        zelf.function.hint
    }

    /// Decoded import name, when present.
    #[pygetset]
    fn name(zelf: &Py<Self>) -> Option<String> {
        zelf.function.name.clone()
    }

    /// Decoded ordinal for ordinal-based imports.
    #[pygetset]
    fn ordinal(zelf: &Py<Self>) -> Option<u16> {
        zelf.function.ordinal
    }

    /// Whether this entry uses an ordinal instead of a name.
    #[pygetset]
    fn by_ordinal(zelf: &Py<Self>) -> bool {
        zelf.function.ordinal.is_some()
    }

    /// Format the descriptor or import identity and table locations.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        match (&zelf.function.name, zelf.function.ordinal) {
            (Some(name), _) => format!(
                "#{index} {name} hint={hint} ilt=0x{ilt_rva:x} iat={iat}",
                index = zelf.function.index,
                hint = zelf.function.hint.unwrap_or(0),
                ilt_rva = zelf.function.import_lookup_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
            ),
            (None, Some(ordinal)) => format!(
                "#{index} ordinal={ordinal} ilt=0x{ilt_rva:x} iat={iat}",
                index = zelf.function.index,
                ilt_rva = zelf.function.import_lookup_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
            ),
            (None, None) => format!(
                "#{index} raw=0x{raw:x} ilt=0x{ilt_rva:x} iat={iat}",
                index = zelf.function.index,
                raw = zelf.function.raw_lookup_value,
                ilt_rva = zelf.function.import_lookup_table_rva,
                iat = optional_rva_text(zelf.function.import_address_table_rva),
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
    fn lookup_kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::imports::ImportLookupKind>> {
        PyEnumValue::new(zelf.descriptor.lookup_kind, vm)
    }

    /// Zero-based position in the containing descriptor or import table.
    #[pygetset]
    fn index(zelf: &Py<Self>) -> usize {
        zelf.descriptor.index
    }

    /// RVA of this IMAGE_IMPORT_DESCRIPTOR.
    #[pygetset]
    fn descriptor_rva(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.descriptor_rva
    }

    /// OriginalFirstThunk RVA, when nonzero/available.
    #[pygetset]
    fn original_first_thunk_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.original_first_thunk_rva
    }

    /// Raw import-descriptor TimeDateStamp field.
    #[pygetset]
    fn time_date_stamp(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.time_date_stamp
    }

    /// Raw ForwarderChain field.
    #[pygetset]
    fn forwarder_chain(zelf: &Py<Self>) -> u32 {
        zelf.descriptor.forwarder_chain
    }

    /// RVA of the descriptor's DLL-name string, when available.
    #[pygetset]
    fn dll_name_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.dll_name_rva
    }

    /// Decoded DLL name, when available.
    #[pygetset]
    fn dll_name(zelf: &Py<Self>) -> Option<String> {
        zelf.descriptor.dll_name.clone()
    }

    /// FirstThunk RVA naming the IAT, when available.
    #[pygetset]
    fn first_thunk_rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.descriptor.first_thunk_rva
    }

    /// Number of decoded imports in this descriptor.
    #[pygetset]
    fn import_count(zelf: &Py<Self>) -> usize {
        zelf.descriptor.import_count()
    }

    /// Decoded import entries belonging to this descriptor.
    #[pygetset]
    fn imports(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeImportDescriptorFunction>> {
        import_descriptor_functions_to_py(&zelf.descriptor.imports, vm)
    }

    /// Format the descriptor or import identity and table locations.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "{} imports={} rva=0x{:x} oft={} ft={}",
            zelf.descriptor.dll_name.as_deref().unwrap_or("<unnamed>"),
            zelf.descriptor.import_count(),
            zelf.descriptor.descriptor_rva,
            optional_rva_text(zelf.descriptor.original_first_thunk_rva),
            optional_rva_text(zelf.descriptor.first_thunk_rva),
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
