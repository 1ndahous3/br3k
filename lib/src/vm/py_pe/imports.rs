use crate::vm::prelude::*;

use crate::pe::imports::{
    ImportAddressResolveMode, ImportAddressResolveOptions, ImportAddressSlot, ImportModel,
    ImportTarget, RecoverIatOptions,
};
use crate::vm::py_pe::exports::PeExportMap;
use crate::vm::py_pe::image::PeImportCodeReference;
pub use crate::vm::py_pe::import_records::{
    PeImportAddressTableRange, PeImportAddressTableRangeScore, PeImportEvidence, PeImportFunction,
    PeImportIssue, PeImportModule, PeImportRebuild,
};
pub(crate) use crate::vm::py_pe::import_records::{
    import_entry_to_py, import_issue_to_py, import_module_entry_to_py,
};

use std::cell::{Cell, RefCell};

/// Editable import model with an explicit target pointer width.
///
/// Entries describe imports and IAT slot RVAs, not live process memory. Successful edits increment revision; failed edits leave the model unchanged. Use an image editor or recovery plan to rebuild image bytes.
#[pyclass(module = "br3k.pe.imports", name = "Model")]
#[derive(Debug, PyPayload)]
pub struct PeImportBuilder {
    model: RefCell<ImportModel>,
    pointer_size: usize,
    revision: Cell<u64>,
}

impl PeImportBuilder {
    pub(crate) fn from_model(model: ImportModel, pointer_size: usize) -> Self {
        Self {
            model: model.into(), pointer_size, revision: Cell::new(0),
        }
    }

    pub(crate) fn model_clone(&self) -> ImportModel {
        self.model.borrow().clone()
    }
}

#[derive(FromArgs)]
pub struct AddModuleArgs {
    #[pyarg(any)]
    module_name: PyStrRef,
    #[pyarg(any)]
    first_thunk: u32,
    #[pyarg(any, optional)]
    nb_thunks: OptionalArg<u32>,
}

#[derive(FromArgs)]
pub struct AddFunctionArgs {
    #[pyarg(any)]
    module_name: PyStrRef,
    #[pyarg(any)]
    rva: u32,
    #[pyarg(named, optional)]
    name: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    ordinal: OptionalArg<u16>,
    #[pyarg(named, optional)]
    address: OptionalArg<u64>,
    #[pyarg(named, optional)]
    export_ordinal: OptionalArg<u16>,
    #[pyarg(named, optional)]
    hint: OptionalArg<u16>,
    #[pyarg(named, optional)]
    valid: OptionalArg<bool>,
    #[pyarg(named, optional)]
    force: OptionalArg<bool>,
}

#[derive(FromArgs)]
pub struct SetFunctionValidityArgs {
    #[pyarg(any)]
    rva: u32,
    #[pyarg(any)]
    valid: bool,
}

#[derive(FromArgs)]
pub struct ImportFunctionRvaArgs {
    #[pyarg(any)]
    rva: u32,
}

#[derive(FromArgs)]
pub struct CutThunkArgs {
    #[pyarg(any)]
    rva: u32,
}

#[derive(FromArgs)]
pub struct ImportIssuesArgs {
    #[pyarg(named, optional)]
    symbols: OptionalArg<PyRef<PeExportMap>>,
}

#[derive(FromArgs)]
pub struct RenameModuleContainingThunkArgs {
    #[pyarg(any)]
    rva: u32,
    #[pyarg(any)]
    module_name: PyStrRef,
}

#[derive(FromArgs)]
pub struct ResolveSlotsArgs {
    #[pyarg(any)]
    slots: Vec<PyRef<AddressSlot>>,
    #[pyarg(any)]
    symbols: PyRef<PeExportMap>,
    #[pyarg(named, optional)]
    nearest: OptionalArg<bool>,
    #[pyarg(named, optional)]
    forwarders: OptionalArg<bool>,
    #[pyarg(named, optional)]
    keep_unresolved: OptionalArg<bool>,
}

#[derive(FromArgs)]
pub struct AddReferencesArgs {
    #[pyarg(any)]
    references: Vec<PyRef<PeImportCodeReference>>,
}

impl Constructor for PeImportBuilder {
    type Args = (usize,);
    /// Create an empty model for a target pointer size of 4 or 8 bytes.
    fn py_new(_cls: &Py<PyType>, (pointer_size,): Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        if !matches!(pointer_size, 4 | 8) { return Err(vm.new_value_error("Pointer size must be 4 or 8")); }
        Ok(Self::from_model(ImportModel::default(), pointer_size))
    }
}

#[pyclass(with(Constructor))]
impl PeImportBuilder {
    /// Revision incremented after each successful model edit.
    #[pygetset]
    fn revision(&self) -> u64 { self.revision.get() }
    /// Target pointer width, in bytes.
    #[pygetset]
    pub(crate) fn pointer_size(&self) -> usize { self.pointer_size }
    /// Add an empty module with its first IAT slot RVA and optional declared slot count (default zero).
    ///
    /// Names are matched case-insensitively. Adding an existing module name replaces that module and its functions.
    #[pymethod]
    fn add_module(&self, args: AddModuleArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to add import module", |model| model.add_module(&args.module_name.to_string(), args.first_thunk, args.nb_thunks.unwrap_or(0)))?;

        Ok(())
    }

    /// Add a function at an IAT slot RVA in an existing module.
    ///
    /// Specify exactly one of name, ordinal, or unresolved address. Named imports may also carry hint (default zero) and export_ordinal. Unresolved addresses must remain invalid. force=True replaces an existing slot; the default rejects duplicates.
    #[pymethod]
    fn add_function(&self, args: AddFunctionArgs, vm: &VirtualMachine) -> PyResult<()> {
        let export_ordinal = args.export_ordinal.present();
        let target = match (args.name.present(), args.ordinal.present(), args.address.present()) {
            (Some(name), None, None) => ImportTarget::Name {
                hint: args.hint.unwrap_or(0),
                ordinal: export_ordinal,
                name: name.to_string(),
            },
            (None, Some(ordinal), None) => {
                if export_ordinal.is_some() {
                    return Err(vm.new_value_error("'export_ordinal' can only be used with named imports"));
                }

                ImportTarget::Ordinal(ordinal)
            }
            (None, None, Some(address)) => {
                if export_ordinal.is_some() {
                    return Err(vm.new_value_error("'export_ordinal' can only be used with named imports"));
                }

                ImportTarget::Unknown(address)
            }
            (None, None, None) => return Err(vm.new_value_error("Specify import function by name, ordinal, or address")),
            _ => return Err(vm.new_value_error("Specify import function by name, ordinal, or address, not more than one")),
        };
        let valid = args.valid.unwrap_or(!matches!(target, ImportTarget::Unknown(_)));
        if valid && matches!(target, ImportTarget::Unknown(_)) {
            return Err(vm.new_value_error("Unresolved import functions must be invalid"));
        }

        self.edit(vm, "Unable to add import function", |model| model.add_function(
                &args.module_name.to_string(),
                args.rva,
                target,
                valid,
                args.force.unwrap_or(false),
            ))?;

        Ok(())
    }

    /// Set the validation flag for an existing IAT slot. This is a model annotation, not independent verification of its target.
    #[pymethod]
    fn set_function_validity(&self, args: SetFunctionValidityArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to update import function validity", |model| model.set_function_validity(args.rva, args.valid))?;

        Ok(())
    }

    /// Remove the function at the supplied IAT slot RVA.
    #[pymethod]
    fn remove_function(&self, args: ImportFunctionRvaArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to remove import function", |model| model.remove_function(args.rva))?;

        Ok(())
    }

    /// Remove the module containing the specified IAT slot and all of its functions.
    #[pymethod]
    fn remove_module_containing_thunk(&self, args: ImportFunctionRvaArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to remove import module", |model| model.remove_module_containing_thunk(args.rva))?;

        Ok(())
    }

    /// Remove one IAT slot and split its module's declared span around the resulting gap.
    #[pymethod]
    fn cut_thunk(&self, args: CutThunkArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to cut import thunk", |model| model.cut_thunk(args.rva, self.pointer_size))?;

        Ok(())
    }

    /// Rename the module containing the supplied IAT slot.
    #[pymethod]
    fn rename_module_containing_thunk(&self, args: RenameModuleContainingThunkArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.edit(vm, "Unable to rename import module", |model| model.rename_module_containing_thunk(args.rva, &args.module_name.to_string()))?;

        Ok(())
    }

    /// Resolve explicit IAT slot values against symbols and merge the results into this model.
    ///
    /// Defaults: exact addresses, forwarder resolution enabled, unresolved slots omitted. Returns the number recovered by this operation.
    #[pymethod]
    fn resolve_slots(&self, args: ResolveSlotsArgs, vm: &VirtualMachine) -> PyResult<usize> {
        let exports = args.symbols.map().tables().collect::<Vec<_>>();
        let pointer_size = self.pointer_size;
        let slots = args.slots.iter().map(|slot| slot.slot.clone()).collect::<Vec<_>>();
        let recovery_options = RecoverIatOptions {
            address_resolve_options: ImportAddressResolveOptions {
                mode: if args.nearest.unwrap_or(false) { ImportAddressResolveMode::Nearest } else { ImportAddressResolveMode::Exact },
                resolve_forwarders: args.forwarders.unwrap_or(true), api_set_map: Some(args.symbols.map().api_set_map().clone()),
            },
            keep_unresolved: args.keep_unresolved.unwrap_or(false),
        };

        let recovered = self.edit(vm, "Unable to recover PE imports from IAT slots", |model| model.recover_iat_slots_with_recovery_options(&slots, pointer_size, recovery_options, &exports))?;

        Ok(recovered)
    }

    /// Merge supported IAT-bearing code-reference evidence into the model and return the recovered count.
    #[pymethod]
    fn add_references(&self, args: AddReferencesArgs, vm: &VirtualMachine) -> PyResult<usize> {
        let references = args
            .references
            .into_iter()
            .map(|reference| reference.to_import_code_reference())
            .collect::<Vec<_>>();
        let recovered = self.edit(vm, "Unable to recover PE imports from code references", |model| model.recover_iat_from_code_references(&references, self.pointer_size))?;

        Ok(recovered)
    }

    /// Return the number of modules currently in the model.
    #[pymethod]
    fn module_count(&self) -> usize {
        self.model.borrow().module_count()
    }

    /// Return the total number of functions, including invalid or unresolved entries.
    #[pymethod]
    fn function_count(&self) -> usize {
        self.model.borrow().function_count()
    }

    /// Return snapshots of the model's module records.
    #[pymethod]
    fn modules(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportModule>>> {
        let modules = self
            .model
            .borrow()
            .modules()
            .into_iter()
            .map(|entry| import_module_entry_to_py(entry, vm))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(modules, vm))
    }

    /// Return snapshots of the model's function records and recovery evidence.
    #[pymethod]
    fn imports(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportFunction>>> {
        let imports = self
            .model
            .borrow()
            .imports()
            .into_iter()
            .map(|entry| import_entry_to_py(entry, vm))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(imports, vm))
    }

    /// Return current structural issues, optionally checking targets against symbols. This does not mutate the model.
    #[pymethod]
    fn validate(&self, args: ImportIssuesArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportIssue>>> {
        let pointer_size = self.pointer_size;
        let issues = match args.symbols.present() {
            Some(symbols) => self.model.borrow().issues_with_export_map(pointer_size, symbols.map()),
            None => self.model.borrow().issues(pointer_size),
        }
        .map_err(map_to_py_value_error(vm, "Unable to inspect PE import model"))?
            .into_iter()
            .map(|issue| import_issue_to_py(issue, vm))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(issues, vm))
    }
}

impl PeImportBuilder {
    fn edit<T>(&self, vm: &VirtualMachine, context: &'static str, operation: impl FnOnce(&mut ImportModel) -> Result<T, crate::pe::imports::ImportError>) -> PyResult<T> {
        let revision = self.revision.get().checked_add(1).ok_or_else(|| vm.new_value_error("Import model revision overflow"))?;
        let mut model = self.model_clone();
        let result = operation(&mut model).map_err(map_to_py_value_error(vm, context))?;
        *self.model.borrow_mut() = model;
        self.revision.set(revision);
        Ok(result)
    }
}

/// Explicit noncontiguous IAT slot input.
#[pyclass(module = "br3k.pe.imports", name = "AddressSlot")]
#[derive(Clone, Debug, PyPayload)]
pub struct AddressSlot { slot: ImportAddressSlot }
impl Constructor for AddressSlot {
    type Args = (u32, u64);
    /// Create an explicit slot from its image-relative RVA and observed target virtual address.
    fn py_new(_cls: &Py<PyType>, (rva, address): Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self { slot: ImportAddressSlot { rva, address } })
    }
}
#[pyclass(with(Constructor))]
impl AddressSlot {
    /// Image-relative virtual address of the IAT slot.
    #[pygetset]
    fn rva(&self) -> u32 { self.slot.rva }
    /// Observed target virtual address stored in the slot.
    #[pygetset]
    fn address(&self) -> u64 { self.slot.address }
}
