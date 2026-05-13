use crate::prelude::*;
use crate::vm::prelude::*;

use crate::sysapi;

use std::cell::RefCell;

use windows_sys::Win32::System::Threading::THREAD_ALL_ACCESS;

use crate::vm;
use vm::api_strategy;
use vm::py_proc::Process;
use vm::py_resource::Handle;

use api_strategy::{ThreadOpenArgs, ThreadOpenStrategy};

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
pub struct SetEpArgs {
    #[pyarg(any)]
    new_thread: bool,
    #[pyarg(any)]
    ep: u64,
}

#[derive(FromArgs)]
pub struct CreateArgs {
    #[pyarg(any)]
    ep: u64,
    #[pyarg(any, optional)]
    arg: OptionalArg<u64>,
}

#[derive(FromArgs)]
pub struct CreateUserApcArgs {
    #[pyarg(any)]
    ep: u64,
    #[pyarg(any, optional)]
    arg1: OptionalArg<u64>,
    #[pyarg(any, optional)]
    arg2: OptionalArg<u64>,
    #[pyarg(any, optional)]
    arg3: OptionalArg<u64>,
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

    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self {
            process: args.process,
            tid: args.tid.present().into(),
            handle: args.thread_handle.present().into()
        })
    }
}

#[pyclass(with(Constructor))]
impl Thread {
    #[pymethod]
    fn set_ep(&self, args: SetEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = self.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match (args.new_thread, self.process.is_x64(vm)?) {
            (true, true) => api_strategy::new_thread_set_ep_x64(*handle.handle, args.ep as _),
            (true, false) => api_strategy::new_thread_set_ep_x86(*handle.handle, args.ep as _),
            (false, true) => api_strategy::thread_set_ep_x64(*handle.handle, args.ep as _),
            (false, false) => api_strategy::thread_set_ep_x86(*handle.handle, args.ep as _),
        }
        .map_err(map_to_py_system_error(vm, "Unable to set thread entry point"))?;

        Ok(())
    }

    #[pymethod]
    fn create(&self, args: CreateArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = self.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let arg = match args.arg.present() {
            Some(arg) => Some(arg as PVOID),
            None => None,
        };

        let handle = sysapi::create_thread(**process_handle, args.ep as _, arg)
            .map_err(map_to_py_system_error(vm, "Unable to create thread"))?;

        self.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    #[pymethod]
    fn open(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut thread_open_strategy = self.process.thread_open_strategy.borrow_mut();
        let missing_strategy = || vm.new_value_error("Thread open method is not set".to_string());
        let thread_open_strategy = thread_open_strategy.as_mut()
            .ok_or_else(missing_strategy)?;

        let args = match thread_open_strategy {
            ThreadOpenStrategy::ThreadOpenByTid => {
                let tid = *self.tid.borrow();
                if tid.is_none() {
                    return Err(vm.new_system_error("Process TID is unknown"));
                }

                ThreadOpenArgs { tid, ..Default::default() }
            }
            ThreadOpenStrategy::ThreadOpenAnyNext => {
                let process_handle = self.process.process_handle.borrow();
                if process_handle.is_null() {
                    return Err(vm.new_system_error("Process is not opened"));
                }

                ThreadOpenArgs { process_handle: Some(**process_handle), ..Default::default() }
            }
            ThreadOpenStrategy::ThreadOpenAnyByHwnd => {
                let pid = *self.process.pid.borrow();
                if pid == 0 {
                    return Err(vm.new_system_error("Process PID is unknown"));
                }

                ThreadOpenArgs { pid: Some(pid), ..Default::default() }
            }
        };

        let handle = thread_open_strategy.open(args, THREAD_ALL_ACCESS)
            .map_err(map_to_py_system_error(vm, "Unable to open thread"))?;

        self.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    // TODO: rework with thread open strategy
    #[pymethod]
    fn open_alertable(&self, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = self.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let handle = sysapi::process_open_alertable_thread(**process_handle)
            .map_err(map_to_py_system_error(vm, "Unable to open alertable thread"))?;

        self.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    #[pymethod]
    fn suspend(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = self.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match sysapi::suspend_thread(*handle.handle) {
            Ok(()) => Ok(()),
            Err(error) => Err(to_py_system_error(vm, "Failed to suspend thread", error)),
        }
    }

    #[pymethod]
    fn resume(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = self.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match sysapi::resume_thread(*handle.handle) {
            Ok(()) => Ok(()),
            Err(error) => Err(to_py_system_error(vm, "Failed to resume thread", error)),
        }
    }

    #[pymethod]
    fn queue_user_apc(&self, args: CreateUserApcArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = self.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        let mut apc_arg1: PVOID = ptr::null_mut();
        let mut apc_arg2: PVOID = ptr::null_mut();
        let mut apc_arg3: PVOID = ptr::null_mut();

        if let Some(&arg1) = args.arg1.as_option() {
            apc_arg1 = arg1 as _;
        }
        if let Some(&arg2) = args.arg2.as_option() {
            apc_arg2 = arg2 as _;
        }
        if let Some(&arg3) = args.arg3.as_option() {
            apc_arg3 = arg3 as _;
        }

        match sysapi::queue_apc_thread(*handle.handle, args.ep as _, apc_arg1, apc_arg2, apc_arg3) {
            Ok(()) => Ok(()),
            Err(error) => Err(to_py_system_error(vm, "Unable to queue user APC", error)),
        }
    }
}
