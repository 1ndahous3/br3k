use crate::pe::api_set::ApiSetMap;
use crate::pe::exports::{ExportSymbol, ExportTable};

use std::collections::BTreeMap;
use std::sync::Arc;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Provenance of an export table in the symbol index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ExportTableSource {
    /// Source provenance was not recorded.
    #[default]
    Unknown,
    /// Exports were parsed from file-layout bytes.
    Disk,
    /// Exports were parsed from mapped process bytes.
    Mapped,
}

impl ExportTableSource {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Debug)]
pub struct ExportTableRecord {
    pub table: ExportTable,
    pub source: ExportTableSource,
}

#[derive(Clone, Debug)]
pub struct ExportMapSymbol {
    pub symbol: ExportSymbol,
    pub source: ExportTableSource,
}

#[derive(Clone, Debug, Default)]
pub struct ExportMap {
    records: Arc<Vec<ExportTableRecord>>,
    api_set_map: Arc<ApiSetMap>,
    forwarded_exports: Arc<BTreeMap<u64, Vec<ExportMapSymbol>>>,
}

impl ExportMap {
    pub fn new(tables: Vec<ExportTable>) -> Self {
        Self::with_api_set_map(tables, ApiSetMap::default())
    }

    pub fn with_api_set_map(
        tables: Vec<ExportTable>,
        api_set_map: ApiSetMap,
    ) -> Self {
        let records = tables
            .into_iter()
            .map(|table| ExportTableRecord {
                table,
                source: ExportTableSource::Unknown,
            })
            .collect();

        Self::with_records(records, api_set_map)
    }

    pub fn with_records(
        records: Vec<ExportTableRecord>,
        api_set_map: ApiSetMap,
    ) -> Self {
        let mut export_map = Self {
            records: Arc::new(records),
            api_set_map: Arc::new(api_set_map),
            forwarded_exports: Arc::new(BTreeMap::new()),
        };
        export_map.forwarded_exports = Arc::new(export_map.build_forwarded_exports());

        export_map
    }

    pub fn tables(&self) -> impl ExactSizeIterator<Item = &ExportTable> {
        self.records.iter().map(|record| &record.table)
    }

    pub fn records(&self) -> &[ExportTableRecord] {
        &self.records
    }

    pub fn api_set_map(&self) -> &ApiSetMap {
        &self.api_set_map
    }

    pub fn resolve_va(&self, address: u64) -> Option<ExportSymbol> {
        self.resolve_va_with_source(address)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_va_with_source(&self, address: u64) -> Option<ExportMapSymbol> {
        self.records
            .iter()
            .find_map(|record| {
                record.table.resolve_va(address).map(|symbol| ExportMapSymbol {
                    symbol,
                    source: record.source,
                })
            })
    }

    pub fn resolve_all_va(&self, address: u64) -> Vec<ExportSymbol> {
        self.resolve_all_va_with_source(address)
            .into_iter()
            .map(|resolved| resolved.symbol)
            .collect()
    }

    pub fn resolve_all_va_with_source(&self, address: u64) -> Vec<ExportMapSymbol> {
        self.records
            .iter()
            .flat_map(|record| {
                record
                    .table
                    .resolve_all_va(address)
                    .into_iter()
                    .map(|symbol| ExportMapSymbol {
                        symbol,
                        source: record.source,
                    })
            })
            .collect()
    }

    pub fn resolve_nearest_va(&self, address: u64) -> Option<ExportSymbol> {
        self.resolve_nearest_va_with_source(address)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_nearest_va_with_source(&self, address: u64) -> Option<ExportMapSymbol> {
        self.records
            .iter()
            .find_map(|record| {
                record.table.resolve_nearest_va(address).map(|symbol| ExportMapSymbol {
                    symbol,
                    source: record.source,
                })
            })
    }

    pub fn resolve_public_va(&self, address: u64) -> Option<ExportSymbol> {
        self.resolve_public_va_with_source(address)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_public_va_with_source(&self, address: u64) -> Option<ExportMapSymbol> {
        self.forwarded_exports
            .get(&address)
            .and_then(|symbols| symbols.first()).cloned()
            .or_else(|| self.resolve_va_with_source(address))
    }

    pub fn public_candidates(&self, address: u64) -> Vec<ExportMapSymbol> {
        let mut symbols = self.forwarded_exports.get(&address).cloned().unwrap_or_default();
        symbols.extend(self.resolve_all_va_with_source(address).into_iter().filter(|symbol| symbol.symbol.forwarder.is_none()));
        symbols
    }

    pub fn resolve_public_va_for_module(&self, address: u64, module_name: &str) -> Option<ExportMapSymbol> {
        let record = self.resolve_record(module_name)?;
        self.public_candidates(address).into_iter()
            .find(|candidate| record.table.matches_module_name(&candidate.symbol.module_name))
    }

    pub fn resolve_module_name(&self, module_name: &str, name: &str) -> Option<ExportSymbol> {
        self.resolve_module_name_with_source(module_name, name)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_module_name_with_source(
        &self,
        module_name: &str,
        name: &str,
    ) -> Option<ExportMapSymbol> {
        self.resolve_record(module_name)
            .and_then(|record| {
                record.table.resolve_name(name).map(|symbol| ExportMapSymbol {
                    symbol,
                    source: record.source,
                })
            })
    }

    pub fn resolve_module_ordinal(&self, module_name: &str, ordinal: u32) -> Option<ExportSymbol> {
        self.resolve_module_ordinal_with_source(module_name, ordinal)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_module_ordinal_with_source(
        &self,
        module_name: &str,
        ordinal: u32,
    ) -> Option<ExportMapSymbol> {
        self.resolve_record(module_name)
            .and_then(|record| {
                record.table.resolve_ordinal(ordinal).map(|symbol| ExportMapSymbol {
                    symbol,
                    source: record.source,
                })
            })
    }

    pub fn resolve_forwarder(&self, forwarder: &str) -> Option<ExportSymbol> {
        self.resolve_forwarder_with_source(forwarder)
            .map(|resolved| resolved.symbol)
    }

    pub fn resolve_forwarder_with_source(&self, forwarder: &str) -> Option<ExportMapSymbol> {
        let target = parse_forwarder(forwarder)?;
        self.resolve_forwarder_target(&target, 0)
    }

    fn resolve_record(&self, module_name: &str) -> Option<&ExportTableRecord> {
        self.records
            .iter()
            .find(|record| record.table.matches_module_name(module_name))
            .or_else(|| {
                self.api_set_map
                    .resolve_contract(module_name)
                    .and_then(|host_name| {
                        self.records
                            .iter()
                            .find(|record| record.table.matches_module_name(host_name))
                    })
            })
    }

    fn build_forwarded_exports(&self) -> BTreeMap<u64, Vec<ExportMapSymbol>> {
        let mut forwarded_exports = BTreeMap::<u64, Vec<ExportMapSymbol>>::new();

        for record in self.records.iter() {
            for symbol in &record.table.symbols {
                let Some(forwarder) = symbol.forwarder.as_deref() else {
                    continue;
                };
                let Some(target_symbol) = self.resolve_forwarder_with_source(forwarder) else {
                    continue;
                };

                let mut public_symbol = symbol.clone();
                public_symbol.address = target_symbol.symbol.address;
                public_symbol.rva = target_symbol.symbol.rva;
                forwarded_exports
                    .entry(public_symbol.address)
                    .or_default().push(ExportMapSymbol {
                        symbol: public_symbol,
                        source: record.source,
                    });
            }
        }

        forwarded_exports
    }

    fn resolve_forwarder_target(
        &self,
        target: &ForwarderTarget,
        depth: usize,
    ) -> Option<ExportMapSymbol> {
        if depth >= MAX_FORWARDER_DEPTH {
            return None;
        }

        let record = self.resolve_record(&target.module_name)?;
        let symbol = match &target.target {
            ForwarderTargetName::Name(name) => record.table.resolve_name(name),
            ForwarderTargetName::Ordinal(ordinal) => record.table.resolve_ordinal(*ordinal),
        }?;

        match symbol.forwarder.as_deref() {
            Some(forwarder) => {
                let target = parse_forwarder(forwarder)?;
                self.resolve_forwarder_target(&target, depth + 1)
            }
            None => Some(ExportMapSymbol {
                symbol,
                source: record.source,
            }),
        }
    }
}

fn parse_forwarder(forwarder: &str) -> Option<ForwarderTarget> {
    let (module_name, target) = forwarder.rsplit_once('.')?;
    if module_name.is_empty() || target.is_empty() {
        return None;
    }

    let target = match target.strip_prefix('#') {
        Some(ordinal) => ForwarderTargetName::Ordinal(ordinal.parse().ok()?),
        None => ForwarderTargetName::Name(target.to_string()),
    };

    Some(ForwarderTarget {
        module_name: module_name.to_string(),
        target,
    })
}

#[derive(Clone, Debug)]
struct ForwarderTarget {
    module_name: String,
    target: ForwarderTargetName,
}

#[derive(Clone, Debug)]
enum ForwarderTargetName {
    Name(String),
    Ordinal(u32),
}

const MAX_FORWARDER_DEPTH: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_map_resolves_api_set_forwarder_to_host_module() {
        let api_set_map = ApiSetMap::parse(&test_api_set_namespace()).unwrap();
        let map = ExportMap::with_api_set_map(
            vec![
                ExportTable {
                    module_name: "kernel32.dll".to_string(),
                    image_base: 0x1000,
                    image_size: 0x1000,
                    time_date_stamp: None,
                    symbols: vec![ExportSymbol {
                        module_name: "kernel32.dll".to_string(),
                        name: Some("PublicHeapAlloc".to_string()),
                        names: vec!["PublicHeapAlloc".to_string()],
                        ordinal: 1,
                        rva: 0x100,
                        address: 0x1100,
                        forwarder: Some("api-ms-win-core-heap-l1-1-0.HostHeapAlloc".to_string()),
                    }],
                },
                ExportTable {
                    module_name: "kernelbase.dll".to_string(),
                    image_base: 0x5000,
                    image_size: 0x1000,
                    time_date_stamp: None,
                    symbols: vec![ExportSymbol {
                        module_name: "kernelbase.dll".to_string(),
                        name: Some("HostHeapAlloc".to_string()),
                        names: vec!["HostHeapAlloc".to_string()],
                        ordinal: 7,
                        rva: 0x300,
                        address: 0x5300,
                        forwarder: None,
                    }],
                },
            ],
            api_set_map,
        );

        let host_symbol = map
            .resolve_module_name("api-ms-win-core-heap-l1-1-0.dll", "HostHeapAlloc")
            .unwrap();
        let public_symbol = map.resolve_public_va(0x5300).unwrap();

        assert_eq!(host_symbol.module_name, "kernelbase.dll");
        assert_eq!(public_symbol.module_name, "kernel32.dll");
        assert_eq!(public_symbol.name.as_deref(), Some("PublicHeapAlloc"));
    }

    #[test]
    fn export_map_resolves_recursive_forwarders() {
        let map = ExportMap::new(vec![
            ExportTable {
                module_name: "a.dll".to_string(),
                image_base: 0x1000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "a.dll".to_string(),
                    name: Some("A".to_string()),
                    names: vec!["A".to_string()],
                    ordinal: 1,
                    rva: 0x100,
                    address: 0x1100,
                    forwarder: Some("b.B".to_string()),
                }],
            },
            ExportTable {
                module_name: "b.dll".to_string(),
                image_base: 0x2000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "b.dll".to_string(),
                    name: Some("B".to_string()),
                    names: vec!["B".to_string()],
                    ordinal: 1,
                    rva: 0x200,
                    address: 0x2200,
                    forwarder: Some("c.C".to_string()),
                }],
            },
            ExportTable {
                module_name: "c.dll".to_string(),
                image_base: 0x3000,
                image_size: 0x1000,
                time_date_stamp: None,
                symbols: vec![ExportSymbol {
                    module_name: "c.dll".to_string(),
                    name: Some("C".to_string()),
                    names: vec!["C".to_string()],
                    ordinal: 1,
                    rva: 0x300,
                    address: 0x3300,
                    forwarder: None,
                }],
            },
        ]);

        let public_symbol = map.resolve_public_va(0x3300).unwrap();

        assert_eq!(public_symbol.module_name, "a.dll");
        assert_eq!(public_symbol.name.as_deref(), Some("A"));
    }

    #[test]
    fn export_map_keeps_table_source_metadata() {
        let map = ExportMap::with_records(
            vec![ExportTableRecord {
                source: ExportTableSource::Disk,
                table: ExportTable {
                    module_name: "kernel32.dll".to_string(),
                    image_base: 0x1000,
                    image_size: 0x1000,
                    time_date_stamp: None,
                    symbols: vec![ExportSymbol {
                        module_name: "kernel32.dll".to_string(),
                        name: Some("CreateFileW".to_string()),
                        names: vec!["CreateFileW".to_string()],
                        ordinal: 1,
                        rva: 0x200,
                        address: 0x1200,
                        forwarder: None,
                    }],
                },
            }],
            ApiSetMap::default(),
        );

        let resolved = map.resolve_va_with_source(0x1200).unwrap();

        assert_eq!(resolved.symbol.name.as_deref(), Some("CreateFileW"));
        assert_eq!(resolved.source, ExportTableSource::Disk);
    }

    fn test_api_set_namespace() -> Vec<u8> {
        let mut data = vec![0u8; 0x120];
        let contract = wide("api-ms-win-core-heap-l1-1-0");
        let host = wide("kernelbase.dll");

        write_u32(&mut data, 0, 6);
        write_u32(&mut data, 4, 0x120);
        write_u32(&mut data, 12, 1);
        write_u32(&mut data, 16, 0x20);

        write_u32(&mut data, 0x20 + 4, 0x60);
        write_u32(&mut data, 0x20 + 8, contract.len() as u32);
        write_u32(&mut data, 0x20 + 16, 0x40);
        write_u32(&mut data, 0x20 + 20, 1);

        write_u32(&mut data, 0x40 + 12, 0xa0);
        write_u32(&mut data, 0x40 + 16, host.len() as u32);

        data[0x60..0x60 + contract.len()].copy_from_slice(&contract);
        data[0xa0..0xa0 + host.len()].copy_from_slice(&host);
        data
    }

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .flat_map(|ch| ch.to_le_bytes())
            .collect()
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
