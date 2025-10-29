use crate::prelude::*;
use crate::vm::prelude::*;
use crate::vm;
use crate::sysapi;

use vm::api_strategy;
use vm::py_module::Handle;

use windef::{ntrtl, ntpsapi, ntpebteb};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};

use exe::{PE, Buffer, VecPE, RelocationDirectory, types, headers};
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
        write!(
            f,
            "CPeb {{ ImageBaseAddress: {:?} }}",
            self.data.ImageBaseAddress
        )
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

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let params = sysapi::create_process_parameters(args.filepath.as_str()).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create process parameters: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Self {
            params: params.into(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[pyclass(module = false, name = "Process")]
#[derive(Debug, PyPayload)]
pub struct Process {
    pub pid: RefCell<u32>,
    pub image_path: RefCell<Option<String>>,
    pub section_handle: RefCell<Option<HANDLE>>,

    pub open_method: RefCell<Option<api_strategy::ProcessOpenMethod>>,
    pub memory_strategy: RefCell<Option<api_strategy::ProcessMemoryStrategy>>,

    pub process_handle: RefCell<sysapi::UniqueHandle>,
    pub thread_handle: RefCell<sysapi::UniqueHandle>,
    pub memory: RefCell<Option<api_strategy::ProcessMemory>>,
}

#[derive(FromArgs)]
pub struct ProcessNewArgs {
    #[pyarg(named, optional)]
    name: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    pid: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    image_path: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    section_handle: OptionalArg<PyRef<Handle>>,
    #[pyarg(named, optional)]
    memory_strategy: OptionalArg<u32>,
    #[pyarg(named, optional)]
    open_method: OptionalArg<u32>,
}

impl Constructor for Process {
    type Args = ProcessNewArgs;

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let mut pid = 0;
        let mut image_path: Option<String> = None;
        let mut section_handle: Option<HANDLE> = None;

        if let OptionalArg::Present(v) = args.pid {
            let pid_str = v.as_str();
            pid = pid_str
                .parse::<u32>()
                .map_err(|_| vm.new_value_error(format!("Invalid PID format: '{pid_str}'")))?
        } else if let OptionalArg::Present(v) = args.name {
            let name_str = v.as_str();
            pid = sysapi::find_process(name_str).map_err(|e| {
                vm.new_value_error(format!(
                    "Unable to find process '{}': {}",
                    name_str,
                    sysapi::ntstatus_decode(e)
                ))
            })?
        } else if let OptionalArg::Present(v) = args.image_path {
            image_path = v.as_str().to_string().into()
        } else if let OptionalArg::Present(v) = args.section_handle {
            let s = *v.handle.get();
            section_handle = Some(s)
        } else {
            return Err(vm.new_value_error(
                "'name', 'pid', 'image_path' or 'section_handle' must be specified".to_string(),
            ));
        };

        let memory_strategy = args
            .memory_strategy
            .into_option()
            .map(|v| {
                api_strategy::ProcessMemoryStrategy::from_repr(v)
                    .ok_or_else(|| vm.new_value_error("Invalid ProcessMemoryStrategy".to_string()))
            })
            .transpose()?;

        let open_method = args
            .open_method
            .into_option()
            .map(|v| {
                api_strategy::ProcessOpenMethod::from_repr(v)
                    .ok_or_else(|| vm.new_value_error("Invalid ProcessOpenMethod".to_string()))
            })
            .transpose()?;

        Self {
            pid: pid.into(),
            image_path: image_path.into(),
            section_handle: section_handle.into(),
            memory_strategy: memory_strategy.into(),
            open_method: open_method.into(),
            process_handle: sysapi::null_handle().into(),
            thread_handle: sysapi::null_handle().into(),
            memory: None.into(),
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

// func params

#[derive(FromArgs)]
pub struct CreateUserArgs {
    #[pyarg(any)]
    suspended: bool
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
pub struct SetThreadEpArgs {
    #[pyarg(any)]
    new_thread: bool,
    #[pyarg(any)]
    ep: u64
}

#[derive(FromArgs)]
pub struct CreateThreadArgs {
    #[pyarg(any)]
    ep: u64
}

#[derive(FromArgs)]
pub struct OpenThreadArgs {
    #[pyarg(any)]
    tid: u32
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
    #[pymethod]
    fn open(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut open_method = self.open_method.borrow_mut();
        let open_method = open_method
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Process open method is not set".to_string()))?;

        let handle = open_method
            .open(*self.pid.borrow(), PROCESS_ALL_ACCESS)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to open process: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        self.process_handle.replace(handle);

        Ok(())
    }

    #[pymethod]
    fn create_user(&self, args: CreateUserArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut image_path = self.image_path.borrow_mut();
        let image_path = image_path
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Process image path is not set".to_string()))?;

        let (process_handle, thread_handle) = sysapi::create_user_process(&image_path, args.suspended)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to create process: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        let basic_info = sysapi::get_process_basic_info(*process_handle)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to read process basic info: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        self.process_handle.replace(process_handle);
        self.thread_handle.replace(thread_handle);

        self.pid.replace(basic_info.UniqueProcessId as _);

        Ok(())
    }

    #[pymethod]
    fn create(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut section_handle = self.section_handle.borrow_mut();
        let section_handle = section_handle
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Process section handle is not set".to_string()))?;

        let process_handle = sysapi::create_process(*section_handle).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create process: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        self.process_handle.replace(process_handle);

        Ok(())
    }

    #[pymethod]
    fn init_memory(&self, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory_strategy = self.memory_strategy.borrow_mut();
        let memory_strategy = memory_strategy
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Memory strategy is not set".to_string()))?;

        let process_handle = *self.process_handle.borrow().get();

        let memory = match memory_strategy {
            api_strategy::ProcessMemoryStrategy::AllocateInAddr => {
                api_strategy::ProcessMemory::init_allocate_in_addr(process_handle)
            }
            api_strategy::ProcessMemoryStrategy::CreateSectionMap => {
                api_strategy::ProcessMemory::init_create_section_map(process_handle)
            }
            api_strategy::ProcessMemoryStrategy::CreateSectionMapLocalMap => {
                api_strategy::ProcessMemory::init_create_section_map_local_map(process_handle)
            }
            api_strategy::ProcessMemoryStrategy::LiveDumpParse => {
                api_strategy::ProcessMemory::init_live_dump_parse(*self.pid.borrow())
            }
        };

        if memory.is_err() {
            return Err(vm.new_value_error(format!(
                "Failed to initialize memory strategy: {memory_strategy:?}"
            )));
        }

        self.memory.replace(Some(memory.unwrap()));
        Ok(())
    }

    #[pymethod]
    fn create_memory(&self, args: CreateMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        memory.create_memory(args.size).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create memory: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(())
    }

    #[pymethod]
    fn write_memory(&self, args: WriteMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let offset = args.offset.unwrap_or(0);

        memory
            .write_memory(offset, args.data.as_ptr() as _, args.data.len())
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to write memory: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        Ok(())
    }

    #[pymethod]
    fn get_memory_remote_address(&self, vm: &VirtualMachine) -> PyResult<u64> {
        let mut memory = self.memory.borrow_mut();
        let memory = memory
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let remote_base_addr = memory.get_remote_base_addr() as u64;
        Ok(remote_base_addr)
    }

    //

    #[pymethod]
    fn set_thread_ep(&self, args: SetThreadEpArgs, vm: &VirtualMachine) -> PyResult<()> {

        match (args.new_thread, self.is_x64(vm)?) {
            (true, true) => {
                api_strategy::new_thread_set_ep_x64(*self.thread_handle.borrow().get(), args.ep as _)
            }
            (true, false) => {
                api_strategy::new_thread_set_ep_x86(*self.thread_handle.borrow().get(), args.ep as _)
            }
            (false, true) => {
                api_strategy::thread_set_ep_x64(*self.thread_handle.borrow().get(), args.ep as _)
            }
            (false, false) => {
                api_strategy::thread_set_ep_x86(*self.thread_handle.borrow().get(), args.ep as _)
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
    fn create_thread(&self, args: CreateThreadArgs, vm: &VirtualMachine) -> PyResult<()> {

        let thread_handle = sysapi::create_thread(*self.process_handle.borrow().get(), args.ep as _)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to create thread: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        self.thread_handle.replace(thread_handle);

        //Ok(thread_handle as u32)
        Ok(())
    }

    #[pymethod]
    fn open_any_thread(&self, vm: &VirtualMachine) -> PyResult<()> {
        let thread_handle = sysapi::open_next_thread(
            *self.process_handle.borrow().get(),
            ptr::null_mut(),
            THREAD_ALL_ACCESS,
        )
        .map_err(|e| {
            vm.new_system_error(format!(
                "Unable to open thread: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        self.thread_handle.replace(thread_handle);

        //Ok(thread_handle as u32)
        Ok(())
    }

    #[pymethod]
    fn open_thread(&self, args: OpenThreadArgs, vm: &VirtualMachine) -> PyResult<()> {

        let thread_handle = sysapi::open_thread(*self.pid.borrow(), args.tid, THREAD_ALL_ACCESS).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to open thread: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        self.thread_handle.replace(thread_handle);

        //Ok(thread_handle as u32)
        Ok(())
    }

    #[pymethod]
    fn open_alertable_thread(&self, vm: &VirtualMachine) -> PyResult<()> {
        let thread_handle = api_strategy::process_open_alertable_thread(
            *self.process_handle.borrow().get(),
        )
        .map_err(|e| {
            vm.new_system_error(format!(
                "Unable to open alertable thread: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        self.thread_handle.replace(thread_handle);

        //Ok(thread_handle as u32)
        Ok(())
    }

    #[pymethod]
    fn suspend_thread(&self, vm: &VirtualMachine) -> PyResult<()> {
        match sysapi::suspend_thread(*self.thread_handle.borrow().get()) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Failed to suspend thread: {}",
                sysapi::ntstatus_decode(status)
            ))),
        }
    }

    #[pymethod]
    fn resume_thread(&self, vm: &VirtualMachine) -> PyResult<()> {
        match sysapi::resume_thread(*self.thread_handle.borrow().get()) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Failed to resume thread: {}",
                sysapi::ntstatus_decode(status)
            ))),
        }
    }

    #[pymethod]
    fn thread_queue_user_apc(&self, args: CreateThreadArgs, vm: &VirtualMachine) -> PyResult<()> {

        match sysapi::queue_apc_thread(
            *self.thread_handle.borrow().get(),
            args.ep as _,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) {
            Ok(()) => Ok(()),
            Err(status) => Err(vm.new_system_error(format!(
                "Unable to queue user APC: {}",
                sysapi::ntstatus_decode(status)
            ))),
        }
    }

    #[pymethod]
    fn is_x64(&self, vm: &VirtualMachine) -> PyResult<bool> {
        match sysapi::get_process_wow64_info(*self.process_handle.borrow().get()) {
            Ok(is_x64) => Ok(is_x64),
            Err(status) => Err(vm.new_system_error(format!(
                "Unable to get Wow64 info: {}",
                sysapi::ntstatus_decode(status)
            ))),
        }
    }

    //

    #[pymethod]
    fn get_basic_info(&self, vm: &VirtualMachine) -> PyResult<CProcessBasicInformation> {
        let basic_info =
            sysapi::get_process_basic_info(*self.process_handle.borrow().get()).map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to get process basic info: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        Ok(CProcessBasicInformation { data: basic_info })
    }

    #[pymethod]
    fn read_peb(&self, vm: &VirtualMachine) -> PyResult<CPeb> {
        unsafe {
            let process_handle = *self.process_handle.borrow().get();

            let basic_info = sysapi::get_process_basic_info(process_handle)
                .map_err(|e| {
                    vm.new_system_error(format!(
                        "Unable to read process basic info: {}",
                        sysapi::ntstatus_decode(e)
                    ))
                })?;

            let mut peb = Box::new(PEB::default());

            let peb_data =
                slice::from_raw_parts_mut(peb.as_mut() as *mut PEB as *mut u8, size_of::<PEB>());

            sysapi::read_virtual_memory(peb_data, basic_info.PebBaseAddress as _, process_handle)
                .map_err(|e| {
                    vm.new_system_error(format!(
                        "Unable to read process PEB: {}",
                        sysapi::ntstatus_decode(e)
                    ))
                })?;

            Ok(CPeb {
                data: mem::transmute_copy(&*peb),
            })
        }
    }

    #[pymethod]
    fn write_peb_proc_params(
        &self,
        args: WritePebProcParmsArgs,
        vm: &VirtualMachine,
    ) -> PyResult<()> {
        unsafe {
            let mut memory = self.memory.borrow_mut();
            let memory = memory.as_mut().ok_or_else(|| {
                vm.new_value_error("Memory context is not initialized".to_string())
            })?;

            let proc_params = args.proc_params.params.borrow_mut();
            let proc_params = proc_params.get();

            let mut peb_memory = memory.clone();
            peb_memory.set_remote_base_addr(args.peb_address as PVOID);

            let mut proc_params_memory = memory.clone();
            proc_params_memory
                .create_write_memory_fixup_addr(
                    *proc_params as _,
                    (*(*proc_params)).Length as _,
                    peb_memory,
                    offset_of!(ntpebteb::PEB, ProcessParameters),
                )
                .map_err(|e| {
                    vm.new_system_error(format!(
                        "Unable to write process parameters: {}",
                        sysapi::ntstatus_decode(e)
                    ))
                })?;

            if (*(*proc_params)).Environment.is_null() {
                let mut env_memory = memory.clone();
                env_memory
                    .create_write_memory_fixup_addr(
                        (*(*proc_params)).Environment,
                        (*(*proc_params)).EnvironmentSize,
                        proc_params_memory,
                        offset_of!(ntrtl::RTL_USER_PROCESS_PARAMETERS, Environment),
                    )
                    .map_err(|e| {
                        vm.new_system_error(format!(
                            "Unable to write process parameters: {}",
                            sysapi::ntstatus_decode(e)
                        ))
                    })?;
            }

            Ok(())
        }
    }

    #[pymethod]
    fn write_mem_image(&self, args: WriteMemImageArgs, vm: &VirtualMachine) -> PyResult<()> {

        let mut memory = self.memory.borrow_mut();
        let memory = memory.as_mut().ok_or_else(|| {
            vm.new_value_error("Memory context is not initialized".to_string())
        })?;

        let base_address = memory.get_remote_base_addr() as usize;

        let mem_image = VecPE::from_memory_data(args.mem_image.as_bytes());
        let mut new_mem_image = mem_image.clone();

        let e_lfanew = mem_image.e_lfanew().unwrap();
        let nt_header = mem_image.get_valid_nt_headers().unwrap();
        match nt_header {
            types::NTHeaders::NTHeaders32(_) => {
                let image_base_offset = e_lfanew.0 as usize +
                    offset_of!(headers::ImageNTHeaders32, optional_header) +
                    offset_of!(headers::ImageOptionalHeader32, image_base);

                let base_address = base_address as u64;
                new_mem_image.write(image_base_offset, base_address.to_le_bytes())
                    .map_err(|e| {
                        vm.new_system_error(format!(
                            "Unable to write image base address: {e}"
                        ))
                    })?;
            },
            types::NTHeaders::NTHeaders64(_) => {
                let image_base_offset = e_lfanew.0 as usize +
                    offset_of!(headers::ImageNTHeaders64, optional_header) +
                    offset_of!(headers::ImageOptionalHeader64, image_base);

                let base_address = base_address as u64;
                new_mem_image.write(image_base_offset, base_address.to_le_bytes())
                    .map_err(|e| {
                        vm.new_system_error(format!(
                            "Unable to write image base address: {e}"
                        ))
                    })?;
            }
        };

        let reloc_dir = RelocationDirectory::parse(&mem_image).unwrap();
        reloc_dir.relocate(&mut new_mem_image, base_address as _)
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to relocate memory image: {e}"
                ))
            })?;

        memory.write_memory(0, new_mem_image.as_ptr() as _, new_mem_image.len())
            .map_err(|e| {
                vm.new_system_error(format!(
                    "Unable to write memory: {}",
                    sysapi::ntstatus_decode(e)
                ))
            })?;

        Ok(())
    }
}
