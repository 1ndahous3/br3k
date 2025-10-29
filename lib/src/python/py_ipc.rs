use std::time::Duration;

use windef::ntstatus;
use rustpython_vm::{
    VirtualMachine,
    pyclass,
    FromArgs,
    PyPayload,
    PyRef, PyObjectRef, PyResult,
    builtins::PyTypeRef,
    types::Constructor,
};

use crate::prelude::*;
use crate::python;
use crate::sysapi;
use crate::ipc;
use crate::{slog_info, slog_warn};

use python::py_proc::Process;

#[derive(FromArgs)]
pub struct IpcNewArgs {
    #[pyarg(any)]
    process: PyRef<Process>,
}

#[derive(FromArgs)]
pub struct SendDataArgs {
    #[pyarg(any)]
    data: Vec<u8>,
}

#[pyclass(module = false, name = "Ipc")]
#[derive(Debug, PyPayload)]
pub struct Ipc {
    process: PyRef<Process>,
    pipe_handle: RefCell<sysapi::UniqueHandle>,
}

impl Constructor for Ipc {
    type Args = IpcNewArgs;

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {

        Self {
            process: args.process,
            pipe_handle: sysapi::null_handle().into(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[pyclass(with(Constructor))]
impl Ipc {
    #[pymethod]
    pub fn create(&self, vm: &VirtualMachine) -> PyResult<()> {

        let pid = *self.process.pid.borrow();
        slog_info!("Creating pipe for process, PID = {pid}");

        let pipe_handle = ipc::create_pipe(pid)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to create pipe: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        self.pipe_handle.replace(pipe_handle.into());
        Ok(())
    }

    #[pymethod]
    pub fn send_data(&self, args: SendDataArgs, vm: &VirtualMachine) -> PyResult<()> {

        let pipe_handle = self.pipe_handle.borrow();

        for _ in 0..10 {
            return match ipc::send_data(*pipe_handle.get(), args.data.as_slice()) {
                Ok(_) => Ok(()),
                Err(e) => {

                    if e.0 == ntstatus::STATUS_PIPE_LISTENING {
                        slog_warn!("Client is not connected to the pipe, waiting...");
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }

                    Err(vm.new_system_error(format!(
                        "Unable to write data to the pipe: {}",
                        sysapi::ntstatus_decode(e)
                    )))
                }
            }
        }

        Err(vm.new_system_error("Unable to write data to the pipe: the client is not connected."))
    }

    #[pymethod]
    pub fn open(&self, vm: &VirtualMachine) -> PyResult<()> {

        let pipe_handle = ipc::open_pipe(*self.process.pid.borrow())
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to open pipe: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        self.pipe_handle.replace(pipe_handle.into());
        Ok(())
    }
}
