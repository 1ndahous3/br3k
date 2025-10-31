use crate::prelude::*;
use crate::vm::prelude::*;
use crate::sysapi;

use windows_sys::Win32::System::Threading::THREAD_ALL_ACCESS;

use crate::vm;
use vm::py_proc::Process;
use vm::py_module::Handle;
use vm::api_strategy;
use api_strategy::{ThreadOpenStrategy, ThreadOpenArgs};

#[derive(FromArgs)]
pub struct ThreadNewArgs {
    #[pyarg(any)]
    process: PyRef<Process>,
    #[pyarg(any, optional)]
    tid: OptionalArg<u32>,
    #[pyarg(any, optional)]
    thread_handle: OptionalArg<PyRef<Handle>>,
}

#[derive(FromArgs)]
pub struct SetThreadEpArgs {
    #[pyarg(any)]
    new_thread: bool,
    #[pyarg(any)]
    ep: u64
}

#[derive(FromArgs)]
pub struct CreateThreadArgs {
    #[pyarg(any)]
    ep: u64,
    #[pyarg(any, optional)]
    arg: OptionalArg<u64>,
}

#[pyclass(module = false, name = "Thread")]
#[derive(Debug, PyPayload)]
pub struct Thread {
    pub process: PyRef<Process>,
    pub tid: RefCell<Option<u32>>,
    pub handle: RefCell<Option<PyRef<Handle>>>,
}

impl Constructor for Thread {
    type Args = ThreadNewArgs;

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        Self {
            process: args.process,
            tid: args.tid.present().into(),
            handle: args.thread_handle.present().into(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[pyclass(with(Constructor))]
impl Thread {

    #[pymethod]
    fn set_ep(&self, args: SetThreadEpArgs, vm: &VirtualMachine) -> PyResult<()> {

        let mut handle = self.handle.borrow_mut();
        let handle = handle
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match (args.new_thread, self.process.is_x64(vm)?) {
            (true, true) => {
                api_strategy::new_thread_set_ep_x64(*handle.handle.get(), args.ep as _)
            }
            (true, false) => {
                api_strategy::new_thread_set_ep_x86(*handle.handle.get(), args.ep as _)
            }
            (false, true) => {
                api_strategy::thread_set_ep_x64(*handle.handle.get(), args.ep as _)
            }
            (false, false) => {
                api_strategy::thread_set_ep_x86(*handle.handle.get(), args.ep as _)
            }
        }
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to set thread entry point: {}", sysapi::ntstatus_decode(e)
                ))
            })?;

        Ok(())
    }

    #[pymethod]
    fn create(&self, args: CreateThreadArgs, vm: &VirtualMachine) -> PyResult<()> {

        let process_handle = self.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let arg = match args.arg.present() {
            Some(arg) => Some(arg as PVOID),
            None => None,
        };

        let handle = sysapi::create_thread(
            *process_handle.get(),
            args.ep as _,
            arg
        )
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to create thread: {}", sysapi::ntstatus_decode(e)
                ))
            })?;

        self.handle.replace(
            Handle {
                handle
            }.into_ref(&vm.ctx).into()
        );

        Ok(())
    }

    #[pymethod]
    fn open(&self, vm: &VirtualMachine) -> PyResult<()> {

        let mut thread_open_strategy = self.process.thread_open_strategy.borrow_mut();
        let thread_open_strategy = thread_open_strategy
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Thread open method is not set".to_string()))?;

        let args = match thread_open_strategy {
            ThreadOpenStrategy::ThreadOpenByTid => {
                let tid = *self.tid.borrow();
                if tid.is_none() {
                    return Err(vm.new_system_error("Process TID is unknown"));
                }

                ThreadOpenArgs {
                    tid,
                    ..Default::default()
                }
            },
            ThreadOpenStrategy::ThreadOpenAnyNext => {
                let process_handle = self.process.process_handle.borrow();
                if process_handle.is_null() {
                    return Err(vm.new_system_error("Process is not opened"));
                }

                ThreadOpenArgs {
                    process_handle: Some(*process_handle.get()),
                    ..Default::default()
                }
            },
            ThreadOpenStrategy::ThreadOpenAnyByHwnd => {
                let pid = *self.process.pid.borrow();
                if pid == 0 {
                    return Err(vm.new_system_error("Process PID is unknown"));
                }

                ThreadOpenArgs {
                    pid: Some(pid),
                    ..Default::default()
                }
            },
        };

        let handle = thread_open_strategy.open(args, THREAD_ALL_ACCESS)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to open thread: {}", sysapi::ntstatus_decode(e)
                ))
            })?;

        self.handle.replace(
            Handle {
                handle
            }.into_ref(&vm.ctx).into()
        );

        Ok(())
    }

    // TODO: rework with thread open strategy
    #[pymethod]
    fn open_alertable(&self, vm: &VirtualMachine) -> PyResult<()> {

        let process_handle = self.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let handle = api_strategy::process_open_alertable_thread(*process_handle.get())
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to open alertable thread: {}", sysapi::ntstatus_decode(e)
                ))
            })?;

        self.handle.replace(
            Handle {
                handle
            }.into_ref(&vm.ctx).into()
        );

        Ok(())
    }

    #[pymethod]
    fn suspend(&self, vm: &VirtualMachine) -> PyResult<()> {

        let mut handle = self.handle.borrow_mut();
        let handle = handle
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match sysapi::suspend_thread(*handle.handle.get()) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Failed to suspend thread: {}", sysapi::ntstatus_decode(status)
            ))),
        }
    }

    #[pymethod]
    fn resume(&self, vm: &VirtualMachine) -> PyResult<()> {

        let mut handle = self.handle.borrow_mut();
        let handle = handle
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match sysapi::resume_thread(*handle.handle.get()) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Failed to resume thread: {}", sysapi::ntstatus_decode(status)
            ))),
        }
    }

    #[pymethod]
    fn queue_user_apc(&self, args: CreateThreadArgs, vm: &VirtualMachine) -> PyResult<()> {

        let mut handle = self.handle.borrow_mut();
        let handle = handle
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match sysapi::queue_apc_thread(
            *handle.handle.get(),
            args.ep as _,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Unable to queue user APC: {}", sysapi::ntstatus_decode(status)
            ))),
        }
    }
}
