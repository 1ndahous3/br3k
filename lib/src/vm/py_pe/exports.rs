use crate::vm::prelude::*;

use crate::pe::export_map::{ExportMap, ExportMapSymbol, ExportTableRecord, ExportTableSource};
use crate::pe::exports::{ExportSymbol, ExportTable};
use crate::vm::py_pe::api_set::PeApiSetMap;

/// One export identity, its alias names, target address, and optional forwarding/source metadata.
#[pyclass(module = "br3k.pe.exports", name = "Symbol")]
#[derive(Debug, PyPayload)]
pub struct PeExportSymbol {
    symbol: ExportSymbol,
    source: Option<ExportTableSource>,
}

#[pyclass]
impl PeExportSymbol {
    /// Name of the module supplying this export or table.
    #[pygetset]
    fn module_name(&self) -> String {
        self.symbol.module_name.clone()
    }

    /// Preferred export name, or None for ordinal-only exports.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.symbol.name.clone()
    }

    /// All name aliases associated with this export.
    #[pygetset]
    fn names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        let names = self
            .symbol
            .names
            .iter()
            .map(|name| vm.ctx.new_str(name.as_str()))
            .collect::<Vec<_>>();

        PyListOf::new(names, vm)
    }

    /// Public export ordinal.
    #[pygetset]
    fn ordinal(&self) -> u32 {
        self.symbol.ordinal
    }

    /// Export target RVA; forwarders refer to the forwarding-string RVA.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.symbol.rva
    }

    /// Export address under the table's image base; inspect forwarder before treating it as code.
    #[pygetset]
    fn address(&self) -> u64 {
        self.symbol.address
    }

    /// Forwarding target string, or None for a non-forwarded export.
    #[pygetset]
    fn forwarder(&self) -> Option<String> {
        self.symbol.forwarder.clone()
    }

    /// Provenance of the export table; optional when a standalone table has no assigned source.
    #[pygetset]
    fn source(&self, vm: &VirtualMachine) -> PyResult<Option<PyEnumValue<crate::pe::export_map::ExportTableSource>>> {
        export_table_source_to_py(self.source, vm)
    }
}

/// Parsed exports for one image. Prefer Image.exports to preserve an explicit image layout.
#[pyclass(module = "br3k.pe.exports", name = "Table")]
#[derive(Debug, PyPayload)]
pub struct PeExportResolver {
    table: ExportTable,
}

impl PeExportResolver {
    pub(crate) fn from_table(table: ExportTable) -> Self {
        Self { table }
    }

    pub(crate) fn table_clone(&self) -> ExportTable {
        self.table.clone()
    }
}

#[derive(FromArgs)]
pub struct PeExportResolverNewArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(named, optional)]
    image_base: OptionalArg<u64>,
    #[pyarg(named, optional)]
    module_name: OptionalArg<PyStrRef>,
}

#[derive(FromArgs)]
pub struct ResolveVaArgs {
    #[pyarg(any)]
    address: u64,
}

#[derive(FromArgs)]
pub struct ResolvePublicVaArgs {
    #[pyarg(any)]
    address: u64,
    #[pyarg(named, optional)]
    module_name: OptionalArg<String>,
}

#[derive(FromArgs)]
pub struct ResolveModuleNameArgs {
    #[pyarg(any)]
    module_name: PyStrRef,
    #[pyarg(any)]
    name: PyStrRef,
}

#[derive(FromArgs)]
pub struct ResolveModuleOrdinalArgs {
    #[pyarg(any)]
    module_name: PyStrRef,
    #[pyarg(any)]
    ordinal: u32,
}

#[derive(FromArgs)]
pub struct PeExportMapNewArgs {
    #[pyarg(any)]
    export_resolvers: Vec<PyRef<PeExportResolver>>,
    #[pyarg(named, optional)]
    api_set_map: OptionalArg<PyRef<PeApiSetMap>>,
}

/// One export table registered in a multi-module symbol map, including its source.
#[pyclass(module = "br3k.pe.exports", name = "Record")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeExportMapRecord {
    record: ExportTableRecord,
}

#[pyclass]
impl PeExportMapRecord {
    /// Name of the module supplying this export or table.
    #[pygetset]
    fn module_name(&self) -> String {
        self.record.table.module_name.clone()
    }

    /// Base used to convert this table's RVAs into virtual addresses.
    #[pygetset]
    fn image_base(&self) -> u64 {
        self.record.table.image_base
    }

    /// Mapped image extent used for address containment, in bytes.
    #[pygetset]
    fn image_size(&self) -> u32 {
        self.record.table.image_size
    }

    /// Number of export records in the table.
    #[pygetset]
    fn export_count(&self) -> usize {
        self.record.table.symbols.len()
    }

    /// Provenance of the export table; optional when a standalone table has no assigned source.
    #[pygetset]
    fn source(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::export_map::ExportTableSource>> {
        PyEnumValue::new(self.record.source, vm)
    }

    /// Format the module name, export count, and table source.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{} exports={} source={}",
            self.record.table.module_name,
            self.record.table.symbols.len(),
            self.record.source.as_str()
        )
    }
}

impl Constructor for PeExportResolver {
    type Args = PeExportResolverNewArgs;

    /// Parse exports from PE bytes, optionally overriding image_base and module_name.
    ///
    /// Parsing failures raise SystemError. Use an explicit-layout Image.exports view
    /// when consuming captured mapped bytes.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let module_name = args.module_name.present().map(|name| name.to_string());
        let table = ExportTable::parse(args.data.as_bytes(), args.image_base.present(), module_name)
            .map_err(map_to_py_system_error(vm, "Unable to parse PE export table"))?;

        Ok(Self { table })
    }
}

#[pyclass(with(Constructor))]
impl PeExportResolver {
    /// Return the image timestamp associated with the export table, when available.
    #[pymethod]
    fn time_date_stamp(&self) -> Option<u32> { self.table.time_date_stamp }

    /// Name of the module supplying this export or table.
    #[pygetset]
    fn module_name(&self) -> String {
        self.table.module_name.clone()
    }

    /// Return all export records in the table or symbol map.
    #[pymethod]
    fn exports(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportSymbol>>> {
        let exports = self
            .table
            .symbols
            .iter()
            .cloned()
            .map(|symbol| PeExportSymbol { symbol, source: None }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(exports, vm))
    }

    /// Resolve an exact export virtual address; return None when no match exists.
    #[pymethod]
    fn resolve_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_symbol_to_py(self.table.resolve_va(args.address), vm)
    }

    /// Return every export record matching an exact virtual address.
    #[pymethod]
    fn resolve_all_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportSymbol>>> {
        let symbols = self
            .table
            .resolve_all_va(args.address)
            .into_iter()
            .map(|symbol| PeExportSymbol { symbol, source: None }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(symbols, vm))
    }

    /// Resolve the nearest preceding non-forwarded export within a containing image.
    ///
    /// This is not function-boundary analysis; an interior address need not belong
    /// to the returned export's implementation.
    #[pymethod]
    fn resolve_nearest_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_symbol_to_py(self.table.resolve_nearest_va(args.address), vm)
    }
}

/// Cross-module export resolution with forwarding and optional API-set contracts.
///
/// This is a snapshot of supplied tables, not a debugger symbol engine or a live
/// module loader. Missing resolutions return None or an empty candidate list.
#[pyclass(module = "br3k.pe.exports", name = "Symbols")]
#[derive(Debug, PyPayload)]
pub struct PeExportMap {
    export_map: ExportMap,
}

impl PeExportMap {
    pub(crate) fn from_export_map(export_map: ExportMap) -> Self {
        Self { export_map }
    }

    pub(crate) fn map(&self) -> &ExportMap {
        &self.export_map
    }
}

impl Constructor for PeExportMap {
    type Args = PeExportMapNewArgs;

    /// Build a symbol map from export tables and an optional API-set map; does not load modules.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        let tables = args
            .export_resolvers
            .iter()
            .map(|resolver| resolver.table_clone())
            .collect::<Vec<_>>();
        let api_set_map = args
            .api_set_map
            .into_option()
            .map(|api_set_map| api_set_map.map_clone())
            .unwrap_or_default();

        Ok(Self {
            export_map: ExportMap::with_api_set_map(tables, api_set_map),
        })
    }
}

#[pyclass(with(Constructor))]
impl PeExportMap {
    /// Number of registered export tables.
    #[pygetset]
    fn resolver_count(&self) -> usize {
        self.export_map.tables().len()
    }

    /// Number of API-set contracts available for resolution.
    #[pygetset]
    fn api_set_count(&self) -> usize {
        self.export_map.api_set_map().entries().len()
    }

    /// Return per-table metadata and source provenance.
    #[pymethod]
    fn records(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportMapRecord>>> {
        let records = self
            .export_map
            .records()
            .iter()
            .cloned()
            .map(|record| PeExportMapRecord { record }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(records, vm))
    }

    /// Return all export records in the table or symbol map.
    #[pymethod]
    fn exports(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportSymbol>>> {
        let exports = self
            .export_map
            .records()
            .iter()
            .flat_map(|record| {
                record
                    .table
                    .symbols
                    .iter()
                    .cloned()
                    .map(|symbol| PeExportSymbol {
                        symbol,
                        source: Some(record.source),
                    }.into_ref(&vm.ctx))
            })
            .collect::<Vec<_>>();

        Ok(PyListOf::new(exports, vm))
    }

    /// Resolve an exact export virtual address; return None when no match exists.
    #[pymethod]
    fn resolve_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_map_symbol_to_py(self.export_map.resolve_va_with_source(args.address), vm)
    }

    /// Choose a public import identity for a target, optionally preferring a module name.
    #[pymethod]
    fn resolve_public_va(&self, args: ResolvePublicVaArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        let symbol = match args.module_name.present() {
            Some(module_name) => self.export_map.resolve_public_va_for_module(args.address, &module_name),
            None => self.export_map.resolve_public_va_with_source(args.address),
        };
        export_map_symbol_to_py(symbol, vm)
    }

    /// List possible public export identities for a target, including forwarding paths.
    #[pymethod]
    fn public_candidates(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyListOf<PyRef<PeExportSymbol>> {
        let symbols = self.export_map.public_candidates(args.address).into_iter()
            .map(|resolved| PeExportSymbol { symbol: resolved.symbol, source: Some(resolved.source) }.into_ref(&vm.ctx))
            .collect();
        PyListOf::new(symbols, vm)
    }

    /// Return every export record matching an exact virtual address.
    #[pymethod]
    fn resolve_all_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportSymbol>>> {
        let symbols = self
            .export_map
            .resolve_all_va_with_source(args.address)
            .into_iter()
            .map(|resolved| PeExportSymbol {
                symbol: resolved.symbol,
                source: Some(resolved.source),
            }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(symbols, vm))
    }

    /// Resolve the nearest preceding non-forwarded export within a containing image.
    ///
    /// This is not function-boundary analysis; an interior address need not belong
    /// to the returned export's implementation.
    #[pymethod]
    fn resolve_nearest_va(&self, args: ResolveVaArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_map_symbol_to_py(self.export_map.resolve_nearest_va_with_source(args.address), vm)
    }

    /// Resolve a module and export name through known forwarding/API-set relationships.
    #[pymethod]
    fn resolve_module_name(&self, args: ResolveModuleNameArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_map_symbol_to_py(
            self.export_map
                .resolve_module_name_with_source(&args.module_name.to_string(), &args.name.to_string()),
            vm,
        )
    }

    /// Resolve a module and public ordinal through the known export tables.
    #[pymethod]
    fn resolve_module_ordinal(&self, args: ResolveModuleOrdinalArgs, vm: &VirtualMachine) -> PyResult<Option<PyRef<PeExportSymbol>>> {
        export_map_symbol_to_py(
            self.export_map
                .resolve_module_ordinal_with_source(&args.module_name.to_string(), args.ordinal),
            vm,
        )
    }
}

fn export_symbol_to_py(
    symbol: Option<ExportSymbol>,
    vm: &VirtualMachine,
) -> PyResult<Option<PyRef<PeExportSymbol>>> {
    match symbol {
        Some(symbol) => Ok(Some(PeExportSymbol { symbol, source: None }.into_ref(&vm.ctx))),
        None => Ok(None),
    }
}

fn export_map_symbol_to_py(
    resolved: Option<ExportMapSymbol>,
    vm: &VirtualMachine,
) -> PyResult<Option<PyRef<PeExportSymbol>>> {
    match resolved {
        Some(resolved) => Ok(Some(PeExportSymbol {
            symbol: resolved.symbol,
            source: Some(resolved.source),
        }.into_ref(&vm.ctx))),
        None => Ok(None),
    }
}

pub(crate) fn export_table_source_to_py(
    source: Option<ExportTableSource>,
    vm: &VirtualMachine,
) -> PyResult<Option<PyEnumValue<crate::pe::export_map::ExportTableSource>>> {
    match source {
        Some(source) => PyEnumValue::new(source, vm).map(Some),
        None => Ok(None),
    }
}
