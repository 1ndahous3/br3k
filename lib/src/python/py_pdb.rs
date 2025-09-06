use crate::prelude::*;

use rustpython_vm::{
    VirtualMachine,
    pyclass,
    FromArgs,
    PyPayload, PyObjectRef, PyResult,
    types::Constructor,
    builtins::{PyTypeRef, PyStrRef},
};

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

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {

        let pdb = crate::pdb::Pdb::init(args.filepath.as_str())
            .map_err(|e| vm.new_value_error(format!("Failed to initialize PDB: {}", e)))?;

        Self {
            pdb: pdb.into()
        }
            .into_ref_with_type(vm, cls)
            .map(Into::into)
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

    #[pymethod]
    fn get_symbol_rva(&self, args: GetSymbolRvaArgs, vm: &VirtualMachine) -> PyResult<usize> {

        let mut pdb = self.pdb.borrow_mut();

        let rva = pdb.get_symbol_rva(args.name.as_str())
            .map_err(|e| vm.new_value_error(format!("Failed to get symbol RVA: {}", e)))?;

        Ok(rva)
    }

    #[pymethod]
    fn get_field_offset(&self, args: GetFieldOffsetArgs, vm: &VirtualMachine) -> PyResult<usize> {

        let mut pdb = self.pdb.borrow_mut();

        let rva = pdb.get_field_offset(args.struct_name.as_str(), args.field_name.as_str())
            .map_err(|e| vm.new_value_error(format!("Failed to get struct field offset: {}", e)))?;

        Ok(rva)
    }

}
