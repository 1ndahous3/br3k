use crate::prelude::*;
use crate::vm::prelude::*;

use crate::sysapi;

use std::cell::RefCell;

/// A named native transaction with explicit creation and thread attachment.
///
/// Call `create()` before `set()` or `rollback()`. `set()` affects the calling
/// thread, not every process thread; use `unset()` in a `finally` block. This
/// wrapper exposes rollback but no commit operation.
#[pyclass(module = false, name = "Transaction")]
#[derive(Debug, PyPayload)]
pub struct Transaction {
    pub name: RefCell<String>,
    pub handle: RefCell<sysapi::UniqueHandle>,
}

#[derive(FromArgs)]
pub struct TransactionNewArgs {
    #[pyarg(any)]
    name: PyStrRef,
}

impl Constructor for Transaction {
    type Args = TransactionNewArgs;
    /// Store the transaction name without creating a native transaction.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self {
            name: args.name.to_string().into(),
            handle: sysapi::null_handle().into()
        })
    }
}

#[pyclass(with(Constructor))]
impl Transaction {
    /// Create the named native transaction and retain its handle.
    #[pymethod]
    fn create(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let name = zelf.name.borrow();

        let handle = sysapi::create_transaction(&name)
            .map_err(map_to_py_system_error(vm, "Unable to create transaction"))?;

        zelf.handle.replace(handle);

        Ok(())
    }

    /// Roll back the created transaction. Does not clear the thread's current transaction.
    #[pymethod]
    fn rollback(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let handle = zelf.handle.borrow();

        sysapi::rollback_transaction(**handle)
            .map_err(map_to_py_system_error(vm, "Unable to rollback transaction"))?;

        Ok(())
    }

    /// Make this transaction current on the calling thread.
    #[pymethod]
    fn set(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let handle = zelf.handle.borrow();

        sysapi::set_transaction(**handle)
            .map_err(map_to_py_system_error(vm, "Unable to set transaction"))?;

        Ok(())
    }

    /// Clear the calling thread's current transaction; does not roll it back.
    #[pymethod]
    fn unset(_zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        sysapi::set_transaction(ptr::null_mut())
            .map_err(map_to_py_system_error(vm, "Unable to unset transaction"))?;

        Ok(())
    }
}
