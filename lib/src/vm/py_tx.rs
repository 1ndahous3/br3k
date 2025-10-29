use crate::vm::prelude::*;
use crate::prelude::*;
use crate::sysapi;

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
    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        Self {
            name: args.name.to_string().into(),
            handle: sysapi::null_handle().into(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[pyclass(with(Constructor))]
impl Transaction {
    #[pymethod]
    fn create(&self, vm: &VirtualMachine) -> PyResult<()> {
        let name = self.name.borrow();

        let handle = sysapi::create_transaction(name.as_str()).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create transaction: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        self.handle.replace(handle);

        Ok(())
    }

    #[pymethod]
    fn rollback(&self, vm: &VirtualMachine) -> PyResult<()> {
        let handle = self.handle.borrow();

        sysapi::rollback_transaction(**handle).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to rollback transaction: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(())
    }

    #[pymethod]
    fn set(&self, vm: &VirtualMachine) -> PyResult<()> {
        let handle = self.handle.borrow();

        sysapi::set_transaction(**handle).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to set transaction: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(())
    }

    #[pymethod]
    fn unset(&self, vm: &VirtualMachine) -> PyResult<()> {
        sysapi::set_transaction(ptr::null_mut()).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to unset transaction: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(())
    }
}
