use crate::vm::prelude::*;

use crate::pe::api_set::{ApiSetEntry, ApiSetMap};

/// An API-set contract and its recorded host DLL names.
#[pyclass(module = "br3k.pe.exports", name = "ApiSetEntry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeApiSetEntry {
    entry: ApiSetEntry,
}

#[pyclass]
impl PeApiSetEntry {
    /// API-set contract name.
    #[pygetset]
    fn contract(zelf: &Py<Self>) -> String {
        zelf.entry.contract.clone()
    }

    /// Host DLL names recorded for this contract.
    #[pygetset]
    fn hosts(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        string_list_to_py(&zelf.entry.hosts, vm)
    }
}

/// Parsed API-set namespace used to resolve contract names to host DLLs. Obtain it from a process or the PE API-set parser.
#[pyclass(module = "br3k.pe.exports", name = "ApiSetMap")]
#[derive(Clone, Debug, Default, PyPayload)]
pub struct PeApiSetMap {
    map: ApiSetMap,
}

impl PeApiSetMap {
    pub(crate) fn from_map(map: ApiSetMap) -> Self {
        Self { map }
    }

    pub(crate) fn map_clone(&self) -> ApiSetMap {
        self.map.clone()
    }
}

#[derive(FromArgs)]
pub struct ResolveContractArgs {
    #[pyarg(any)]
    contract_name: PyStrRef,
}

#[pyclass]
impl PeApiSetMap {
    /// Number of contracts in the map.
    #[pygetset]
    fn count(zelf: &Py<Self>) -> usize {
        zelf.map.entries().len()
    }

    /// Contract records in the parsed namespace.
    #[pygetset]
    fn entries(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeApiSetEntry>> {
        let entries = zelf
            .map
            .entries()
            .iter()
            .cloned()
            .map(|entry| PeApiSetEntry { entry }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        PyListOf::new(entries, vm)
    }

    /// Return the selected host for a known contract, or None when no host is available.
    #[pymethod]
    fn resolve_contract(zelf: &Py<Self>, args: ResolveContractArgs) -> Option<String> {
        zelf.map
            .resolve_contract(&args.contract_name.to_string())
            .map(|host| host.to_string())
    }

    /// Resolve a contract to its host, leaving an unresolved ordinary module name unchanged.
    #[pymethod]
    fn resolve_module_name(zelf: &Py<Self>, args: ResolveContractArgs) -> String {
        zelf.map
            .resolve_module_name(&args.contract_name.to_string())
            .to_string()
    }
}

fn string_list_to_py(items: &[String], vm: &VirtualMachine) -> PyListOf<PyStrRef> {
    let items = items
        .iter()
        .map(|item| vm.ctx.new_str(item.as_str()))
        .collect::<Vec<_>>();

    PyListOf::new(items, vm)
}
