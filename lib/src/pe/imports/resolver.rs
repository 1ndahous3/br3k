use super::*;
use super::code::ImportSymbolResolver;
use super::types::*;
use crate::pe::export_map::ExportMap;

pub(super) fn module_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

pub(super) struct ImportAddressResolver {
    export_map: ExportMap,
    options: ImportAddressResolveOptions,
}

impl ImportAddressResolver {
    pub(super) fn new(exports: &[&ExportTable], options: ImportAddressResolveOptions) -> Self {
        let tables = exports.iter().map(|table| (*table).clone()).collect::<Vec<_>>();
        let export_map = match options.api_set_map.clone() {
            Some(api_set_map) => ExportMap::with_api_set_map(tables, api_set_map),
            None => ExportMap::new(tables),
        };

        Self {
            export_map,
            options,
        }
    }

    fn resolve(&self, address: u64) -> Option<ExportSymbol> {
        if self.options.resolve_forwarders {
            if let Some(symbol) = self.export_map.resolve_public_va(address) {
                return Some(symbol);
            }
        }

        let exact_symbol = self.export_map
            .resolve_va(address)
            .filter(|symbol| symbol.forwarder.is_none());
        if exact_symbol.is_some() || self.options.mode == ImportAddressResolveMode::Exact {
            return exact_symbol;
        }

        let nearest_symbol = self.export_map.resolve_nearest_va(address);
        if let Some(symbol) = nearest_symbol {
            if self.options.resolve_forwarders {
                if let Some(forwarded_symbol) = self.export_map.resolve_public_va(symbol.address) {
                    return Some(forwarded_symbol);
                }
            }

            return Some(symbol);
        }

        None
    }
}

impl ImportSymbolResolver for ImportAddressResolver {
    fn resolve_import_address(&self, address: u64) -> Result<Option<ExportSymbol>, ImportError> {
        Ok(self.resolve(address))
    }
}

pub(super) fn import_target_from_export(symbol: &ExportSymbol) -> Result<ImportTarget, ImportError> {
    match &symbol.name {
        Some(name) => {
            let ordinal = u16::try_from(symbol.ordinal)
                .map_err(|_| ImportError::Overflow("converting export ordinal to import ordinal"))?;

            Ok(ImportTarget::Name {
                hint: 0,
                ordinal: Some(ordinal),
                name: name.clone(),
            })
        }
        None => Ok(ImportTarget::Ordinal(
            u16::try_from(symbol.ordinal)
                .map_err(|_| ImportError::Overflow("converting export ordinal to import ordinal"))?,
        )),
    }
}

pub(super) fn import_target_from_code_reference(reference: &ImportCodeReference) -> Result<ImportTarget, ImportError> {
    match &reference.name {
        Some(name) => {
            let ordinal = u16::try_from(reference.ordinal)
                .map_err(|_| ImportError::Overflow("converting code reference ordinal to import ordinal"))?;

            Ok(ImportTarget::Name {
                hint: 0,
                ordinal: Some(ordinal),
                name: name.clone(),
            })
        }
        None => Ok(ImportTarget::Ordinal(
            u16::try_from(reference.ordinal)
                .map_err(|_| ImportError::Overflow("converting code reference ordinal to import ordinal"))?,
        )),
    }
}
