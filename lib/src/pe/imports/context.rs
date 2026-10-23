use super::{ImportEvidence, ImportEvidenceKind, ImportError, ImportModel, ImportResolutionKind, ImportTarget};
use crate::pe::export_map::ExportMap;
use crate::pe::image::Image;
use std::collections::BTreeMap;

pub fn apply_import_context(model: &mut ImportModel, mapped_image: &Image, exports: &ExportMap) -> Result<usize, ImportError> {
    let descriptors = mapped_image.mapped_imports()?;
    let excluded = crate::pe::embedded::mapped_exclusions(mapped_image.data());
    let mut prior_evidence = model.imports().into_iter().map(|entry| (entry.rva, entry.evidence)).collect::<BTreeMap<_, _>>();
    let mut applied = 0;
    for descriptor in descriptors {
        let Some(module_name) = descriptor.dll_name else { continue };
        let has_lookup_table = descriptor.original_first_thunk_rva.is_some();
        for function in descriptor.imports {
            let (Some(rva), Some(address)) = (function.import_address_table_rva, function.raw_address_value) else { continue };
            if crate::pe::embedded::intersects(&excluded, rva as usize, mapped_image.pointer_size()) { continue; }
            let target = if has_lookup_table {
                let symbol = match (&function.name, function.ordinal) {
                    (Some(name), _) => exports.resolve_module_name(&module_name, name),
                    (_, Some(ordinal)) => exports.resolve_module_ordinal(&module_name, ordinal as u32),
                    _ => None,
                };
                let Some(symbol) = symbol else { continue };
                let resolved_address = match symbol.forwarder.as_deref() {
                    Some(forwarder) => exports.resolve_forwarder(forwarder).map(|symbol| symbol.address),
                    None => Some(symbol.address),
                };
                if resolved_address != Some(address) { continue; }
                match (function.name, function.ordinal) {
                    (Some(name), _) => ImportTarget::Name {
                        name, hint: function.hint.unwrap_or(0), ordinal: u16::try_from(symbol.ordinal).ok(),
                    },
                    (_, Some(ordinal)) => ImportTarget::Ordinal(ordinal),
                    _ => continue,
                }
            } else {
                // The DLL name survives, but the original choice of name/ordinal does not.
                let Some(candidate) = exports.resolve_public_va_for_module(address, &module_name) else { continue };
                let symbol = candidate.symbol;
                match (symbol.name, u16::try_from(symbol.ordinal).ok()) {
                    (Some(name), ordinal) => ImportTarget::Name { name, hint: 0, ordinal },
                    (None, Some(ordinal)) => ImportTarget::Ordinal(ordinal),
                    _ => continue,
                }
            };
            let mut evidence = prior_evidence.remove(&rva).unwrap_or_default();
            while model.has_thunk_rva(rva) { model.remove_function(rva)?; }
            let kind = if has_lookup_table { ImportEvidenceKind::ImportDeclaration } else { ImportEvidenceKind::ImportModuleContext };
            evidence.push(ImportEvidence::slot(kind, ImportResolutionKind::Exact, rva, Some(address)));
            model.upsert_module_range(&module_name, rva, rva, mapped_image.pointer_size())?;
            model.add_function_with_evidence(&module_name, rva, target, true, true, evidence)?;
            applied += 1;
        }
    }
    Ok(applied)
}
