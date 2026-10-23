use crate::vm::prelude::*;

use std::cell::RefCell;

/// An opened PDB for symbol RVAs and structure-field offsets.
///
/// Use a PDB matching the target image's build. Returned RVAs are relative to
/// that image's base; field offsets are bytes from the start of a structure.
/// Parse failures and missing symbols or fields raise `ValueError`.
#[pyclass(module = false, name = "Pdb")]
#[derive(Debug, PyPayload)]
pub struct Pdb {
    pub pdb: RefCell<crate::pdb::Pdb<'static>>,
}

#[derive(FromArgs)]
pub struct PdbNewArgs {
    #[pyarg(any)]
    filepath: PyStrRef,
}

impl Constructor for Pdb {
    type Args = PdbNewArgs;

    /// Open and parse the PDB at `filepath`.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let pdb = crate::pdb::Pdb::init(&args.filepath.to_string())
            .map_err(map_to_py_value_error(vm, "Failed to initialize PDB"))?;

        Ok(Self { pdb: pdb.into() })
    }
}

#[derive(FromArgs)]
pub struct GetSymbolRvaArgs {
    #[pyarg(any)]
    name: PyStrRef,
}

#[derive(FromArgs)]
pub struct GetFieldOffsetArgs {
    #[pyarg(any)]
    struct_name: PyStrRef,
    #[pyarg(any)]
    field_name: PyStrRef,
}

#[pyclass(with(Constructor))]
impl Pdb {
    /// Resolve an exact symbol name to an image-relative virtual address.
    #[pymethod]
    fn get_symbol_rva(&self, args: GetSymbolRvaArgs, vm: &VirtualMachine) -> PyResult<usize> {
        let mut pdb = self.pdb.borrow_mut();

        let rva = pdb.get_symbol_rva(&args.name.to_string())
            .map_err(map_to_py_value_error(vm, "Failed to get symbol RVA"))?;

        Ok(rva)
    }

    /// Return the byte offset of `field_name` within the named structure or class.
    #[pymethod]
    fn get_field_offset(&self, args: GetFieldOffsetArgs, vm: &VirtualMachine) -> PyResult<usize> {
        let mut pdb = self.pdb.borrow_mut();

        let rva = pdb
            .get_field_offset(&args.struct_name.to_string(), &args.field_name.to_string())
            .map_err(map_to_py_value_error(vm, "Failed to get struct field offset"))?;

        Ok(rva)
    }
}
