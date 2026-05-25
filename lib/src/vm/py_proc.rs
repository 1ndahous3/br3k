use crate::prelude::*;
use crate::vm::prelude::*;

use crate::slog_info;
use crate::str;
use crate::sysapi;
use crate::vm;

use std::cell::RefCell;
use std::fmt;
use std::slice;

use vm::api_strategy;
use vm::py_resource::Handle;
use vm::py_thread::Thread;

use windef::{ntpebteb, ntpsapi, ntrtl};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

use exe::{Buffer, PE, RelocationDirectory, VecPE, headers, types};
use windef::ntpebteb::PEB;

#[pyclass(module = false, name = "PROCESS_BASIC_INFORMATION")]
#[derive(PyPayload)]
pub struct CProcessBasicInformation {
    pub data: ntpsapi::PROCESS_BASIC_INFORMATION,
}

impl fmt::Debug for CProcessBasicInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CProcessBasicInformation {{ PebBaseAddress: {:?}, UniqueProcessId: {:?} }}",
            self.data.PebBaseAddress, self.data.UniqueProcessId
        )
    }
}

#[pyclass]
impl CProcessBasicInformation {
    #[pygetset(name = "PebBaseAddress")]
    fn peb_base_address(&self) -> usize {
        self.data.PebBaseAddress as _
    }
}

#[pyclass(module = false, name = "PEB")]
#[derive(PyPayload)]
pub struct CPeb {
    pub data: ntpebteb::PEB,
}

impl fmt::Debug for CPeb {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CPeb {{ ImageBaseAddress: {:?} }}", self.data.ImageBaseAddress)
    }
}

#[pyclass]
impl CPeb {
    #[pygetset(name = "ImageBaseAddress")]
    fn image_base_address(&self) -> usize {
        self.data.ImageBaseAddress as _
    }
}

#[pyclass(module = false, name = "PRTL_USER_PROCESS_PARAMETERS")]
#[derive(Debug, PyPayload)]
pub struct CPUserProcessParameters {
    pub params: RefCell<sysapi::UniqueProcessParameters>,
}

#[derive(FromArgs)]
pub struct CPUserProcessParametersNewArgs {
    #[pyarg(any)]
    filepath: PyStrRef,
}

#[pyclass(with(Constructor))]
impl CPUserProcessParameters {}

impl Constructor for CPUserProcessParameters {
    type Args = CPUserProcessParametersNewArgs;

    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let params = sysapi::create_process_parameters(&args.filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to create process parameters"))?;

        Ok(Self { params: params.into() })
    }
}

#[pyclass(module = false, name = "Process")]
#[derive(Debug, PyPayload)]
pub struct Process {
    pub pid: RefCell<u32>,
    pub image_path: RefCell<Option<String>>,
    pub section_handle: RefCell<Option<HANDLE>>,

    pub process_open_strategy: RefCell<Option<api_strategy::ProcessOpenStrategy>>,
    pub thread_open_strategy: RefCell<Option<api_strategy::ThreadOpenStrategy>>,
    pub process_vm_read_strategy: RefCell<Option<api_strategy::ProcessVmReadStrategy>>,
    pub process_vm_write_strategy: RefCell<Option<api_strategy::ProcessVmWriteStrategy>>,

    pub process_handle: RefCell<sysapi::UniqueHandle>,
    pub thread: RefCell<Option<PyRef<Thread>>>,
    pub memory: RefCell<Option<api_strategy::ProcessMemory>>,
}

#[derive(FromArgs)]
pub struct ProcessNewArgs {
    #[pyarg(named, optional)]
    current: OptionalArg<bool>,
    #[pyarg(named, optional)]
    name: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    pid: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    image_path: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    section_handle: OptionalArg<PyRef<Handle>>,
    #[pyarg(named, optional)]
    process_vm_read_strategy: OptionalArg<u32>,
    #[pyarg(named, optional)]
    process_vm_write_strategy: OptionalArg<u32>,
    #[pyarg(named, optional)]
    process_open_strategy: OptionalArg<u32>,
    #[pyarg(named, optional)]
    thread_open_strategy: OptionalArg<u32>,
}

impl Constructor for Process {
    type Args = ProcessNewArgs;

    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let mut pid = 0;
        let mut image_path: Option<String> = None;
        let mut section_handle: Option<HANDLE> = None;

        if let Some(v) = args.current.present() && v {
            unsafe {
                let teb = sysapi::teb();

                pid = (*teb).ClientId.UniqueProcess as _;
                image_path = str::to_u16cstring(&(*(*(*teb).ProcessEnvironmentBlock).ProcessParameters).ImagePathName).to_string().ok();
            }
        } else if let Some(v) = args.pid.present() {
            let pid_str = v.to_string();
            pid = pid_str.parse::<u32>()
                .map_err(|_| vm.new_value_error(format!("Invalid PID format: '{pid_str}'")))?
        } else if let Some(v) = args.name.present() {
            let name_str = v.to_string();
            pid = sysapi::find_process(&name_str)
                .map_err(|e| to_py_value_error(vm, &format!("Unable to find process '{name_str}'"), e))?
        } else if let Some(v) = args.image_path.present() {
            image_path = v.to_string().into()
        } else if let Some(v) = args.section_handle.present() {
            let s = *v.handle;
            section_handle = Some(s)
        } else {
            return Err(vm.new_value_error("'name', 'pid', 'image_path' or 'section_handle' must be specified".to_string()));
        };

        let invalid_strategy = |name: &str| vm.new_value_error(format!("Invalid {name}"));

        let process_vm_read_strategy = args
            .process_vm_read_strategy
            .into_option()
            .map(|v| api_strategy::ProcessVmReadStrategy::from_repr(v)
                .ok_or_else(|| invalid_strategy("ProcessVmReadStrategy")))
            .transpose()?;

        let process_vm_write_strategy = args
            .process_vm_write_strategy
            .into_option()
            .map(|v| api_strategy::ProcessVmWriteStrategy::from_repr(v)
                .ok_or_else(|| invalid_strategy("ProcessVmWriteStrategy")))
            .transpose()?;

        let process_open_strategy = args
            .process_open_strategy
            .into_option()
            .map(|v| api_strategy::ProcessOpenStrategy::from_repr(v)
                .ok_or_else(|| invalid_strategy("ProcessOpenStrategy")))
            .transpose()?;

        let thread_open_strategy = args
            .thread_open_strategy
            .into_option()
            .map(|v| api_strategy::ThreadOpenStrategy::from_repr(v)
                .ok_or_else(|| invalid_strategy("ThreadOpenStrategy")))
            .transpose()?;

        Ok(Self {
            pid: pid.into(),
            image_path: image_path.into(),
            section_handle: section_handle.into(),
            process_vm_read_strategy: process_vm_read_strategy.into(),
            process_vm_write_strategy: process_vm_write_strategy.into(),
            process_open_strategy: process_open_strategy.into(),
            thread_open_strategy: thread_open_strategy.into(),
            process_handle: sysapi::null_handle().into(),
            thread: None.into(),
            memory: None.into(),
        })
    }
}

// func params

#[derive(FromArgs)]
pub struct CreateUserArgs {
    #[pyarg(any)]
    suspended: bool,
}

#[derive(FromArgs)]
pub struct ProcessSuspendArgs {
    #[pyarg(named, optional)]
    process_suspend_strategy: OptionalArg<u32>,
}

#[derive(FromArgs)]
pub struct ProcessResumeArgs {
    #[pyarg(named, optional)]
    process_resume_strategy: OptionalArg<u32>,
}

#[derive(FromArgs)]
pub struct WriteMemoryArgs {
    #[pyarg(any)]
    data: Vec<u8>,
    #[pyarg(any, optional)]
    offset: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct CreateMemoryArgs {
    #[pyarg(any)]
    size: usize,
}

#[derive(FromArgs)]
pub struct WritePebProcParmsArgs {
    #[pyarg(any)]
    peb_address: usize,
    #[pyarg(any)]
    proc_params: PyRef<CPUserProcessParameters>,
}

#[derive(FromArgs)]
pub struct WriteMemImageArgs {
    #[pyarg(any)]
    mem_image: PyRef<PyBytes>,
}

//

#[pyclass(with(Constructor))]
impl Process {
    #[pygetset]
    fn main_thread(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let mut thread = self.thread.borrow_mut();
        let not_opened = || vm.new_value_error("Process main thread is not opened".to_string());
        let thread = thread.as_mut()
            .ok_or_else(not_opened)?.clone();

        Ok(thread.into())
    }

    #[pymethod]
    fn open(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut process_open_strategy = self.process_open_strategy.borrow_mut();
        let missing_strategy = || vm.new_value_error("Process open method is not set".to_string());
        let process_open_strategy = process_open_strategy.as_mut()
            .ok_or_else(missing_strategy)?;

        let handle = process_open_strategy
            .open(*self.pid.borrow(), PROCESS_ALL_ACCESS)
            .map_err(map_to_py_system_error(vm, "Unable to open process"))?;

        let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
        let basic_info = sysapi::get_process_basic_info(*handle)
            .map_err(read_basic_info_error)?;

        self.process_handle.replace(handle);
        self.pid.replace(basic_info.UniqueProcessId as _);

        Ok(())
    }

    #[pymethod]
    fn create_user(zelf: PyRef<Self>, args: CreateUserArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut image_path = zelf.image_path.borrow_mut();
        let image_path = image_path.as_mut()
            .ok_or_else(|| vm.new_value_error("Process image path is not set".to_string()))?;

        let create_process_error = map_to_py_system_error(vm, "Unable to create process");
        let (process_handle, thread_handle) = sysapi::create_user_process(&image_path, args.suspended)
            .map_err(create_process_error)?;

        let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
        let basic_info = sysapi::get_process_basic_info(*process_handle)
            .map_err(read_basic_info_error)?;

        zelf.process_handle.replace(process_handle);
        zelf.pid.replace(basic_info.UniqueProcessId as _);

        let py_handle = Handle { handle: thread_handle }.into_ref(&vm.ctx);

        let py_thread = Thread { process: zelf.clone(), tid: None.into(), handle: Some(py_handle.clone()).into() }.into_ref(&vm.ctx);

        zelf.thread.replace(py_thread.into());
        Ok(())
    }

    #[pymethod]
    fn create(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut section_handle = self.section_handle.borrow_mut();
        let section_handle = section_handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Process section handle is not set".to_string()))?;

        let process_handle = sysapi::create_process(*section_handle)
            .map_err(map_to_py_system_error(vm, "Unable to create process"))?;

        let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
        let basic_info = sysapi::get_process_basic_info(*process_handle)
            .map_err(read_basic_info_error)?;

        self.process_handle.replace(process_handle);
        self.pid.replace(basic_info.UniqueProcessId as _);

        Ok(())
    }

    #[pymethod]
    fn suspend(&self, args: ProcessSuspendArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = **self.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let strategy = args.process_suspend_strategy
            .into_option()
            .map(|v| api_strategy::ProcessSuspendStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid ProcessSuspendStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::ProcessSuspendStrategy::NtSuspendProcess);

        strategy.suspend(process_handle)
            .map_err(map_to_py_system_error(vm, "Failed to suspend process"))?;

        Ok(())
    }

    #[pymethod]
    fn resume(&self, args: ProcessResumeArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = **self.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let strategy = args.process_resume_strategy
            .into_option()
            .map(|v| api_strategy::ProcessResumeStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid ProcessResumeStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::ProcessResumeStrategy::NtResumeProcess);

        strategy.resume(process_handle)
            .map_err(map_to_py_system_error(vm, "Failed to resume process"))?;

        Ok(())
    }

    #[pymethod]
    fn init_memory(&self, vm: &VirtualMachine) -> PyResult<()> {
        let process_vm_read_strategy = self.process_vm_read_strategy.borrow().clone();
        let process_vm_write_strategy = self.process_vm_write_strategy.borrow().clone();

        if process_vm_read_strategy.is_none() && process_vm_write_strategy.is_none() {
            return Err(vm.new_value_error("Process VM read or write strategy is not set".to_string()));
        }

        let process_handle = **self.process_handle.borrow();

        if process_vm_read_strategy == Some(api_strategy::ProcessVmReadStrategy::LiveDumpParse) {
            sysapi::adjust_privilege(windef::ntseapi::SE_DEBUG_PRIVILEGE)
                .map_err(map_to_py_system_error(vm, "Unable to get debug privilege"))?;
        }

        let memory = api_strategy::ProcessMemory::init(
            process_vm_read_strategy.as_ref(),
            process_vm_write_strategy.as_ref(),
            process_handle,
            *self.pid.borrow()
        )
        .map_err(|e| {
            to_py_system_error(
                vm,
                &format!("Failed to initialize process VM strategies read={process_vm_read_strategy:?}, write={process_vm_write_strategy:?}"),
                e,
            )
        })?;

        self.memory.replace(Some(memory));
        Ok(())
    }

    #[pymethod]
    fn create_memory(&self, args: CreateMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        memory.create_memory(args.size)
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to create memory"))?;

        Ok(())
    }

    #[pymethod]
    fn write_memory(&self, args: WriteMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let offset = args.offset.unwrap_or(0);

        memory
            .write_memory(
                offset,
                args.data.as_ptr() as _,
                args.data.len()
            )
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to write memory"))?;

        Ok(())
    }

    #[pymethod]
    fn get_memory_remote_address(&self, vm: &VirtualMachine) -> PyResult<u64> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let remote_base_addr = memory.get_remote_base_addr() as u64;
        Ok(remote_base_addr)
    }

    //

    #[pymethod]
    pub fn is_x64(&self, vm: &VirtualMachine) -> PyResult<bool> {
        match sysapi::get_process_wow64_info(**self.process_handle.borrow()) {
            Ok(is_x64) => Ok(is_x64),
            Err(error) => Err(to_py_system_error(vm, "Unable to get Wow64 info", error)),
        }
    }

    //

    #[pymethod]
    fn get_basic_info(&self, vm: &VirtualMachine) -> PyResult<CProcessBasicInformation> {
        let basic_info = sysapi::get_process_basic_info(**self.process_handle.borrow())
            .map_err(map_to_py_system_error(vm, "Unable to get process basic info"))?;

        Ok(CProcessBasicInformation { data: basic_info })
    }

    #[pymethod]
    fn read_peb(&self, vm: &VirtualMachine) -> PyResult<CPeb> {
        unsafe {
            let process_handle = **self.process_handle.borrow();

            let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
            let basic_info = sysapi::get_process_basic_info(process_handle)
                .map_err(read_basic_info_error)?;

            let mut peb = Box::new(PEB::default());

            let peb_data = slice::from_raw_parts_mut(peb.as_mut() as *mut PEB as *mut u8, size_of::<PEB>());

            sysapi::read_virtual_memory(peb_data, basic_info.PebBaseAddress as _, process_handle)
                .map_err(map_to_py_system_error(vm, "Unable to read process PEB"))?;

            Ok(CPeb { data: mem::transmute_copy(&*peb) })
        }
    }

    #[pymethod]
    fn write_peb_proc_params(&self, args: WritePebProcParmsArgs, vm: &VirtualMachine) -> PyResult<()> {
        unsafe {
            let mut memory = self.memory.borrow_mut();
            let memory = memory.as_mut()
                .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

            let proc_params = args.proc_params.params.borrow_mut();
            let proc_params = **proc_params;

            let mut peb_memory = memory.clone();
            peb_memory.set_remote_base_addr(args.peb_address as PVOID);

            let mut proc_params_memory = memory.clone();
            proc_params_memory
                .create_write_memory_fixup_addr(
                    proc_params as _,
                    (*proc_params).Length as _,
                    peb_memory,
                    offset_of!(ntpebteb::PEB, ProcessParameters),
                )
                .map_err(map_process_memory_error_to_py_exception(vm, "Unable to write process parameters"))?;

            if !(*proc_params).Environment.is_null() && (*proc_params).EnvironmentSize > 0 {
                let mut env_memory = memory.clone();
                env_memory
                    .create_write_memory_fixup_addr(
                        (*proc_params).Environment,
                        (*proc_params).EnvironmentSize,
                        proc_params_memory,
                        offset_of!(ntrtl::RTL_USER_PROCESS_PARAMETERS, Environment),
                    )
                    .map_err(map_process_memory_error_to_py_exception(vm, "Unable to write process parameters"))?;
            }

            Ok(())
        }
    }

    #[pymethod]
    fn write_mem_image(&self, args: WriteMemImageArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let base_address = memory.get_remote_base_addr() as usize;

        let mem_image = VecPE::from_memory_data(args.mem_image.as_bytes());
        let mut new_mem_image = mem_image.clone();

        let e_lfanew = mem_image.e_lfanew()
            .map_err(map_to_py_system_error(vm, "Unable to read PE header offset"))?;

        let nt_header = mem_image.get_valid_nt_headers()
            .map_err(map_to_py_system_error(vm, "Unable to read PE NT headers"))?;

        match nt_header {
            types::NTHeaders::NTHeaders32(_) => {
                let image_base_offset = e_lfanew.0 as usize
                    + offset_of!(headers::ImageNTHeaders32, optional_header)
                    + offset_of!(headers::ImageOptionalHeader32, image_base);

                let base_address = base_address as u64;
                new_mem_image
                    .write(image_base_offset, base_address.to_le_bytes())
                    .map_err(map_to_py_system_error(vm, "Unable to write image base address"))?;
            }
            types::NTHeaders::NTHeaders64(_) => {
                let image_base_offset = e_lfanew.0 as usize
                    + offset_of!(headers::ImageNTHeaders64, optional_header)
                    + offset_of!(headers::ImageOptionalHeader64, image_base);

                let base_address = base_address as u64;
                new_mem_image
                    .write(image_base_offset, base_address.to_le_bytes())
                    .map_err(map_to_py_system_error(vm, "Unable to write image base address"))?;
            }
        };

        let parse_relocation_error = map_to_py_system_error(vm, "Unable to parse relocation directory");
        let reloc_dir = RelocationDirectory::parse(&mem_image)
            .map_err(parse_relocation_error)?;
        reloc_dir.relocate(&mut new_mem_image, base_address as _)
            .map_err(map_to_py_system_error(vm, "Unable to relocate memory image"))?;

        memory
            .write_memory(
                0,
                new_mem_image.as_ptr() as _,
                new_mem_image.len()
            ).map_err(map_process_memory_error_to_py_exception(vm, "Unable to write memory"))?;

        Ok(())
    }

    #[pymethod]
    fn log_handles(&self, vm: &VirtualMachine) -> PyResult<()> {
        let pid = *self.pid.borrow();

        let processes = sysapi::get_processes_pid_name()
            .map_err(map_to_py_system_error(vm, "Unable to get processes info"))?;

        let handles = sysapi::get_process_handles(pid)
            .map_err(map_to_py_system_error(vm, "Unable to get process handles"))?;

        for handle in handles {
            slog_info!("HANDLE: 0x{:X}", handle as usize);

            if let Ok((handle_name, handle_type)) = sysapi::get_handle_info(handle) {
                slog_info!("Name: {handle_name}");
                slog_info!("Type: {handle_type}");

                if let Ok(info) = sysapi::get_process_basic_info(handle) {
                    let handle_pid = info.UniqueProcessId as u32;

                    slog_info!("PID: {}", handle_pid);
                    if let Some(path) = processes.get(&handle_pid) {
                        slog_info!("Path: {path}");
                    }
                }
            }
            slog_info!("");
        }

        Ok(())
    }
}
