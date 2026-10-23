use super::DiagnosticsError;
use crate::pe::export_map::{ExportMap, ExportMapSymbol, ExportTableSource};
use crate::pe::image::Image;
use crate::pe::imports::ImportDescriptorFunction;
use crate::pe::diagnostic::{Diagnostic, Stage};

#[derive(Clone, Debug)]
pub struct ImportComparison {
    pub changes: Vec<ImportAddressChange>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportAddressChange {
    pub module_name: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
    pub expected_address: u64,
    pub expected_module_name: String,
    pub expected_name: Option<String>,
    pub expected_ordinal: u32,
    pub expected_source: ExportTableSource,
    pub actual_address: u64,
    pub actual_module_name: Option<String>,
    pub actual_name: Option<String>,
    pub actual_ordinal: Option<u32>,
    pub actual_source: Option<ExportTableSource>,
}

pub fn import_address_changes(
    mapped_data: &[u8],
    disk_data: &[u8],
    export_map: &ExportMap,
) -> Result<Vec<ImportAddressChange>, DiagnosticsError> {
    let mapped_image = Image::parse(mapped_data.to_vec())?;
    let disk_image = Image::parse(disk_data.to_vec())?;
    Ok(compare_imports(&mapped_image, &disk_image, export_map)?.changes)
}

pub(super) fn compare_imports(mapped_image: &Image, disk_image: &Image, export_map: &ExportMap) -> Result<ImportComparison, DiagnosticsError> {
    let mapped_pointer_size = mapped_image.pointer_size();
    let disk_pointer_size = disk_image.pointer_size();
    if mapped_pointer_size != disk_pointer_size {
        return Err(DiagnosticsError::PointerSizeMismatch {
            mapped: mapped_pointer_size,
            disk: disk_pointer_size,
        });
    }

    let descriptors = disk_image.imports()?;
    let mut changes = Vec::new();
    let mut diagnostics = Vec::new();

    for descriptor in descriptors {
        let module_name = descriptor
            .dll_name
            .clone()
            .unwrap_or_else(|| format!("?descriptor_{}", descriptor.index));

        for import in descriptor.imports {
            let Some(iat_rva) = import.import_address_table_rva else {
                continue;
            };
            let Some(expected) = expected_import_symbol(export_map, &module_name, &import) else {
                let mut diagnostic = Diagnostic::warning(Stage::Imports, format!("Unable to resolve expected import in {module_name}"));
                diagnostic.rva = Some(iat_rva);
                diagnostics.push(diagnostic);
                continue;
            };
            let actual_address = read_mapped_pointer(&mapped_image, iat_rva, mapped_pointer_size)?;
            if actual_address == expected.symbol.address {
                continue;
            }

            let actual = export_map.resolve_public_va_with_source(actual_address);
            changes.push(ImportAddressChange {
                module_name: module_name.clone(),
                name: import.name,
                ordinal: import.ordinal,
                iat_rva,
                expected_address: expected.symbol.address,
                expected_module_name: expected.symbol.module_name,
                expected_name: expected.symbol.name,
                expected_ordinal: expected.symbol.ordinal,
                expected_source: expected.source,
                actual_address,
                actual_module_name: actual.as_ref().map(|actual| actual.symbol.module_name.clone()),
                actual_name: actual.as_ref().and_then(|actual| actual.symbol.name.clone()),
                actual_ordinal: actual.as_ref().map(|actual| actual.symbol.ordinal),
                actual_source: actual.map(|actual| actual.source),
            });
        }
    }

    changes.sort_by_key(|change| (change.iat_rva, change.module_name.clone(), change.name.clone()));
    Ok(ImportComparison { changes, diagnostics })
}

fn expected_import_symbol(
    export_map: &ExportMap,
    module_name: &str,
    import: &ImportDescriptorFunction,
) -> Option<ExportMapSymbol> {
    let resolved = match (&import.name, import.ordinal) {
        (Some(name), _) => export_map.resolve_module_name_with_source(module_name, name),
        (None, Some(ordinal)) => export_map.resolve_module_ordinal_with_source(module_name, ordinal as u32),
        (None, None) => None,
    }?;

    match resolved.symbol.forwarder.as_deref() {
        Some(forwarder) => export_map.resolve_forwarder_with_source(forwarder).or(Some(resolved)),
        None => Some(resolved),
    }
}

fn read_mapped_pointer(
    image: &Image,
    rva: u32,
    pointer_size: usize,
) -> Result<u64, DiagnosticsError> {
    let data = image.read_mapped_bytes_rva(rva, pointer_size)?;

    match pointer_size {
        4 => Ok(u32::from_le_bytes(data.as_slice().try_into().unwrap()) as u64),
        8 => Ok(u64::from_le_bytes(data.as_slice().try_into().unwrap())),
        _ => Err(DiagnosticsError::Overflow("reading PE pointer with unsupported size")),
    }
}
