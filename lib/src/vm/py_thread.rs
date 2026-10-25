use crate::prelude::*;
use crate::vm::prelude::*;

use crate::sysapi;

use std::cell::RefCell;

use windows_sys::Win32::System::Threading::THREAD_ALL_ACCESS;

use crate::vm;
use vm::api_strategy;
use vm::py_proc::Process;
use vm::py_resource::Handle;

use api_strategy::{ThreadOpenArgs, ThreadOpenStrategy, ThreadResumeStrategy, ThreadSuspendStrategy};

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

#[py_api]
#[derive(FromArgs)]
pub struct ThreadSuspendArgs {
    /// Defaults to NtSuspendThread.
    #[pyi(ty = "br3k.proc.ThreadSuspendStrategy | int")]
    #[pyarg(named, optional)]
    thread_suspend_strategy: OptionalArg<u32>,
}

#[py_api]
#[derive(FromArgs)]
pub struct ThreadResumeArgs {
    /// Defaults to NtResumeThread.
    #[pyi(ty = "br3k.proc.ThreadResumeStrategy | int")]
    #[pyarg(named, optional)]
    thread_resume_strategy: OptionalArg<u32>,
}

/// A thread associated with a `br3k.proc.Process`.
///
/// Construction only stores the process and optional TID or handle. Call `open()`
/// or `create()` to acquire a handle, unless one was supplied. Native addresses
/// refer to the target process. Context and callback operations require matching
/// architecture and calling conventions; they do not validate executable code.
#[pyclass(module = false, name = "Thread")]
#[derive(Debug, PyPayload)]
pub struct Thread {
    pub process: PyRef<Process>,
    pub tid: RefCell<Option<u32>>,
    pub handle: RefCell<Option<PyRef<Handle>>>,
}

impl Constructor for Thread {
    type Args = ThreadNewArgs;

    /// Store a process and optional integer TID or owning handle without opening a thread.
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
    /// Change a suspended thread's entry point to `ep`.
    ///
    /// Set `new_thread=True` for initial startup-context handling, or `False` to
    /// replace the current instruction pointer. Does not suspend or resume the thread.
    #[pymethod]
    fn set_ep(zelf: &Py<Self>, args: SetEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = zelf.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        match (args.new_thread, Process::is_x64(&zelf.process, vm)?) {
            (true, true) => api_strategy::new_thread_set_ep_x64(*handle.handle, args.ep as _),
            (true, false) => api_strategy::new_thread_set_ep_x86(*handle.handle, args.ep as _),
            (false, true) => api_strategy::thread_set_ep_x64(*handle.handle, args.ep as _),
            (false, false) => api_strategy::thread_set_ep_x86(*handle.handle, args.ep as _),
        }
        .map_err(map_to_py_system_error(vm, "Unable to set thread entry point"))?;

        Ok(())
    }

    /// Create a thread at target address `ep`, using the configured system API dispatch.
    ///
    /// `arg` defaults to a null pointer. Requires an opened process; retains the
    /// returned thread handle. Creation does not imply that the callback completed.
    #[pymethod]
    fn create(zelf: &Py<Self>, args: CreateArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = zelf.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let arg = match args.arg.present() {
            Some(arg) => Some(arg as PVOID),
            None => None,
        };

        let handle = sysapi::create_thread(**process_handle, args.ep as _, arg)
            .map_err(map_to_py_system_error(vm, "Unable to create thread"))?;

        zelf.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    /// Open a thread using the parent process's `ThreadOpenStrategy`.
    ///
    /// The TID strategy requires `tid`; other strategies use the opened process or
    /// its PID/window. An omitted strategy raises `ValueError`.
    #[pymethod]
    fn open(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let mut thread_open_strategy = zelf.process.thread_open_strategy.borrow_mut();
        let missing_strategy = || vm.new_value_error("Thread open method is not set".to_string());
        let thread_open_strategy = thread_open_strategy.as_mut()
            .ok_or_else(missing_strategy)?;

        let args = match thread_open_strategy {
            ThreadOpenStrategy::ThreadOpenByTid => {
                let tid = *zelf.tid.borrow();
                if tid.is_none() {
                    return Err(vm.new_system_error("Process TID is unknown"));
                }

                ThreadOpenArgs { tid, ..Default::default() }
            }
            ThreadOpenStrategy::ThreadOpenAnyNext => {
                let process_handle = zelf.process.process_handle.borrow();
                if process_handle.is_null() {
                    return Err(vm.new_system_error("Process is not opened"));
                }

                ThreadOpenArgs { process_handle: Some(**process_handle), ..Default::default() }
            }
            ThreadOpenStrategy::ThreadOpenAnyByHwnd => {
                let pid = *zelf.process.pid.borrow();
                if pid == 0 {
                    return Err(vm.new_system_error("Process PID is unknown"));
                }

                ThreadOpenArgs { pid: Some(pid), ..Default::default() }
            }
        };

        let handle = thread_open_strategy.open(args, THREAD_ALL_ACCESS)
            .map_err(map_to_py_system_error(vm, "Unable to open thread"))?;

        zelf.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    // TODO: rework with thread open strategy
    /// Search the opened process for an alertable thread and retain its handle.
    ///
    /// This is a snapshot-based selection; a thread may leave its alertable state.
    #[pymethod]
    fn open_alertable(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = zelf.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let handle = sysapi::process_open_alertable_thread(**process_handle)
            .map_err(map_to_py_system_error(vm, "Unable to open alertable thread"))?;

        zelf.handle.replace(Handle { handle }.into_ref(&vm.ctx).into());

        Ok(())
    }

    /// Suspend the opened thread. Defaults to `ThreadSuspendStrategy.NtSuspendThread`.
    #[pymethod]
    fn suspend(zelf: &Py<Self>, args: ThreadSuspendArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = zelf.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        let strategy = args.thread_suspend_strategy
            .into_option()
            .map(|v| ThreadSuspendStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid ThreadSuspendStrategy".to_string())))
            .transpose()?
            .unwrap_or(ThreadSuspendStrategy::NtSuspendThread);

        strategy.suspend(*handle.handle)
            .map_err(map_to_py_system_error(vm, "Failed to suspend thread"))?;

        Ok(())
    }

    /// Resume the opened thread. Defaults to `ThreadResumeStrategy.NtResumeThread`.
    #[pymethod]
    fn resume(zelf: &Py<Self>, args: ThreadResumeArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = zelf.handle.borrow_mut();
        let handle = handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Thread handle is not initialized".to_string()))?;

        let strategy = args.thread_resume_strategy
            .into_option()
            .map(|v| ThreadResumeStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid ThreadResumeStrategy".to_string())))
            .transpose()?
            .unwrap_or(ThreadResumeStrategy::NtResumeThread);

        strategy.resume(*handle.handle)
            .map_err(map_to_py_system_error(vm, "Failed to resume thread"))?;

        Ok(())
    }

    /// Queue a user APC at target address `ep` on the opened thread.
    ///
    /// The three optional pointer-sized arguments default to zero. Uses the system
    /// API `QueueApcThread` dispatch; successful queueing does not guarantee delivery.
    #[pymethod]
    fn queue_user_apc(zelf: &Py<Self>, args: CreateUserApcArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut handle = zelf.handle.borrow_mut();
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
