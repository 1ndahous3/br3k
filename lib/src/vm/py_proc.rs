use crate::prelude::*;
use crate::vm::prelude::*;

use crate::slog_info;
use crate::str;
use crate::sysapi;
use crate::vm;
use crate::vm::py_pe::PeApiSetMap;

use std::cell::RefCell;
use std::fmt;
use std::slice;

use vm::api_strategy;
use vm::py_resource::Handle;
use vm::py_thread::Thread;

use windef::{ntldr, ntpebteb, ntpsapi, ntrtl};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;

use exe::{Buffer, PE, RelocationDirectory, VecPE, headers, types};
use windef::ntpebteb::PEB;

/// A native process-basic-information snapshot exposing the PEB address.
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
    /// Target virtual address of the process environment block.
    #[pygetset(name = "PebBaseAddress")]
    fn peb_base_address(zelf: &Py<Self>) -> usize {
        zelf.data.PebBaseAddress as _
    }
}

/// A copied process environment block exposing the main image base.
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
    /// Target virtual address of the main executable image.
    #[pygetset(name = "ImageBaseAddress")]
    fn image_base_address(zelf: &Py<Self>) -> usize {
        zelf.data.ImageBaseAddress as _
    }
}

/// A loader-listed module snapshot. Addresses are target virtual addresses.
///
/// This record comes from the process loader lists; manually mapped or unlinked
/// images may not appear. Names and ranges describe the moment of enumeration.
#[pyclass(module = false, name = "PROCESS_MODULE")]
#[derive(Debug, Clone, PyPayload)]
pub struct CProcessModule {
    /// Base virtual address of the loaded module.
    #[pymember(name = "DllBase")]
    pub dll_base: u64,
    /// Loader-reported entry-point virtual address; may be zero.
    #[pymember(name = "EntryPoint")]
    pub entry_point: u64,
    /// Loader-reported mapped image size in bytes.
    #[pymember(name = "SizeOfImage")]
    pub size_of_image: u32,
    pub full_dll_name: String,
    pub base_dll_name: String,
}

#[pyclass]
impl CProcessModule {
    /// Full module path reported by the loader.
    #[pygetset(name = "FullDllName")]
    fn full_dll_name(zelf: &Py<Self>) -> String {
        zelf.full_dll_name.clone()
    }

    /// Module basename reported by the loader.
    #[pygetset(name = "BaseDllName")]
    fn base_dll_name(zelf: &Py<Self>) -> String {
        zelf.base_dll_name.clone()
    }
}

/// A virtual-memory region snapshot from the target process.
///
/// Addresses are target virtual addresses and sizes are bytes. State, Type,
/// and protection values use `br3k.mem` constants. These are observations, not
/// promises that a later read will succeed.
#[pyclass(module = false, name = "PROCESS_MEMORY_REGION")]
#[derive(Debug, Clone, PyPayload)]
pub struct CProcessMemoryRegion {
    pub data: sysapi::MemoryRegion,
}

#[pyclass]
impl CProcessMemoryRegion {
    /// First virtual address in the region.
    #[pygetset(name = "BaseAddress")]
    fn base_address(zelf: &Py<Self>) -> u64 {
        zelf.data.base_address
    }

    /// Exclusive end virtual address of the region.
    #[pygetset(name = "EndAddress")]
    fn end_address(zelf: &Py<Self>) -> u64 {
        zelf.data.end_address()
    }

    /// Base address of the allocation containing this region.
    #[pygetset(name = "AllocationBase")]
    fn allocation_base(zelf: &Py<Self>) -> u64 {
        zelf.data.allocation_base
    }

    /// Original allocation protection flags.
    #[pygetset(name = "AllocationProtect")]
    fn allocation_protect(zelf: &Py<Self>) -> u32 {
        zelf.data.allocation_protect
    }

    /// Region length in bytes.
    #[pygetset(name = "RegionSize")]
    fn region_size(zelf: &Py<Self>) -> usize {
        zelf.data.region_size
    }

    /// Memory state, such as `br3k.mem.MEM_COMMIT` or `MEM_RESERVE`.
    #[pygetset(name = "State")]
    fn state(zelf: &Py<Self>) -> u32 {
        zelf.data.state
    }

    /// Current page protection and modifier flags.
    #[pygetset(name = "Protect")]
    fn protect(zelf: &Py<Self>) -> u32 {
        zelf.data.protect
    }

    /// Memory type: image, mapped, private, or zero for unallocated memory.
    #[pygetset(name = "Type")]
    fn memory_type(zelf: &Py<Self>) -> u32 {
        zelf.data.memory_type
    }

    /// Mapped-file path when available; otherwise `None`.
    #[pygetset(name = "MappedPath")]
    fn mapped_path(zelf: &Py<Self>) -> Option<String> {
        zelf.data.mapped_path.clone()
    }

    /// Whether the region state is MEM_COMMIT.
    #[pygetset(name = "IsCommitted")]
    fn is_committed(zelf: &Py<Self>) -> bool {
        zelf.data.is_committed()
    }

    /// Whether the base protection is executable; does not test commitment or GUARD.
    #[pygetset(name = "IsExecutable")]
    fn is_executable(zelf: &Py<Self>) -> bool {
        zelf.data.is_executable()
    }

    /// Whether the base protection is writable-executable or executable copy-on-write.
    #[pygetset(name = "IsWritableExecutable")]
    fn is_writable_executable(zelf: &Py<Self>) -> bool {
        zelf.data.is_writable_executable()
    }

    /// Whether PAGE_GUARD is present in the current protection.
    #[pygetset(name = "IsGuarded")]
    fn is_guarded(zelf: &Py<Self>) -> bool {
        zelf.data.is_guarded()
    }

    /// Whether the region is MEM_IMAGE.
    #[pygetset(name = "IsImage")]
    fn is_image(zelf: &Py<Self>) -> bool {
        zelf.data.is_image()
    }

    /// Whether the region is MEM_MAPPED.
    #[pygetset(name = "IsMapped")]
    fn is_mapped(zelf: &Py<Self>) -> bool {
        zelf.data.is_mapped()
    }

    /// Whether the region is MEM_PRIVATE.
    #[pygetset(name = "IsPrivate")]
    fn is_private(zelf: &Py<Self>) -> bool {
        zelf.data.is_private()
    }
}

/// Page-residency and sharing counts for a memory-region snapshot.
///
/// Private pages can include copy-on-write modifications; they are evidence for
/// analysis, not proof of malicious changes. Invalid pages are not necessarily
/// unmapped and may simply be nonresident.
#[pyclass(module = false, name = "PROCESS_WORKING_SET_REGION")]
#[derive(Debug, Clone, PyPayload)]
pub struct CProcessWorkingSetRegion {
    pub data: sysapi::WorkingSetRegionSummary,
}

#[pyclass]
impl CProcessWorkingSetRegion {
    /// Memory-region snapshot used for this page query.
    #[pygetset(name = "Region")]
    fn region(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<CProcessMemoryRegion> {
        CProcessMemoryRegion { data: zelf.data.region.clone() }.into_ref(&vm.ctx)
    }

    /// First virtual address of the queried region.
    #[pygetset(name = "BaseAddress")]
    fn base_address(zelf: &Py<Self>) -> u64 {
        zelf.data.region.base_address
    }

    /// Exclusive end virtual address of the queried region.
    #[pygetset(name = "EndAddress")]
    fn end_address(zelf: &Py<Self>) -> u64 {
        zelf.data.region.end_address()
    }

    /// Queried region length in bytes.
    #[pygetset(name = "RegionSize")]
    fn region_size(zelf: &Py<Self>) -> usize {
        zelf.data.region.region_size
    }

    /// Page size in bytes used for the query.
    #[pygetset(name = "PageSize")]
    fn page_size(zelf: &Py<Self>) -> usize {
        zelf.data.page_size
    }

    /// Total number of queried pages.
    #[pygetset(name = "PageCount")]
    fn page_count(zelf: &Py<Self>) -> usize {
        zelf.data.page_count
    }

    /// Pages with valid working-set entries.
    #[pygetset(name = "ValidPageCount")]
    fn valid_page_count(zelf: &Py<Self>) -> usize {
        zelf.data.valid_page_count
    }

    /// Valid pages marked shared.
    #[pygetset(name = "SharedPageCount")]
    fn shared_page_count(zelf: &Py<Self>) -> usize {
        zelf.data.shared_page_count
    }

    /// Valid pages not marked shared.
    #[pygetset(name = "PrivatePageCount")]
    fn private_page_count(zelf: &Py<Self>) -> usize {
        zelf.data.private_page_count
    }

    /// Pages without a valid working-set entry.
    #[pygetset(name = "InvalidPageCount")]
    fn invalid_page_count(zelf: &Py<Self>) -> usize {
        zelf.data.invalid_page_count
    }

    /// Pages flagged bad by the working-set query.
    #[pygetset(name = "BadPageCount")]
    fn bad_page_count(zelf: &Py<Self>) -> usize {
        zelf.data.bad_page_count
    }

    /// Whether at least one valid page is private.
    #[pygetset(name = "HasPrivatePages")]
    fn has_private_pages(zelf: &Py<Self>) -> bool {
        zelf.data.has_private_pages()
    }

    /// Format region bounds and page counters for display.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "base={} size={} pages={} valid={} shared={} private={} invalid={} bad={}",
            format_args!("0x{:x}", zelf.data.region.base_address),
            format_args!("0x{:x}", zelf.data.region.region_size),
            zelf.data.page_count,
            zelf.data.valid_page_count,
            zelf.data.shared_page_count,
            zelf.data.private_page_count,
            zelf.data.invalid_page_count,
            zelf.data.bad_page_count,
        )
    }
}

/// A thread snapshot with best-effort start-address, TEB, and stack information.
///
/// Optional fields are `None` when unavailable. `StartAddress` prefers the Win32
/// start address and otherwise uses the system-reported address.
#[pyclass(module = false, name = "PROCESS_THREAD_INFO")]
#[derive(Debug, Clone, PyPayload)]
pub struct CProcessThreadInfo {
    pub data: sysapi::ProcessThreadInfo,
}

#[pyclass]
impl CProcessThreadInfo {
    /// Owning process ID.
    #[pygetset(name = "ProcessId")]
    fn process_id(zelf: &Py<Self>) -> u32 {
        zelf.data.process_id
    }

    /// Thread ID.
    #[pygetset(name = "ThreadId")]
    fn thread_id(zelf: &Py<Self>) -> u32 {
        zelf.data.thread_id
    }

    /// Win32 start address when available, otherwise the system-reported start address.
    #[pygetset(name = "StartAddress")]
    fn start_address(zelf: &Py<Self>) -> u64 {
        zelf.data.start_address()
    }

    /// Start address from the system thread snapshot.
    #[pygetset(name = "SystemStartAddress")]
    fn system_start_address(zelf: &Py<Self>) -> u64 {
        zelf.data.system_start_address
    }

    /// Win32 thread start address, or `None` if the query failed.
    #[pygetset(name = "Win32StartAddress")]
    fn win32_start_address(zelf: &Py<Self>) -> Option<u64> {
        zelf.data.win32_start_address
    }

    /// Thread environment block address, or `None` when unavailable.
    #[pygetset(name = "TebAddress")]
    fn teb_address(zelf: &Py<Self>) -> Option<u64> {
        zelf.data.teb_address
    }

    /// Upper stack boundary, or `None` when unavailable.
    #[pygetset(name = "StackBase")]
    fn stack_base(zelf: &Py<Self>) -> Option<u64> {
        zelf.data.stack_base
    }

    /// Lower committed stack boundary, or `None` when unavailable.
    #[pygetset(name = "StackLimit")]
    fn stack_limit(zelf: &Py<Self>) -> Option<u64> {
        zelf.data.stack_limit
    }

    /// Whether both stack boundaries are available.
    #[pygetset(name = "HasStackBounds")]
    fn has_stack_bounds(zelf: &Py<Self>) -> bool {
        zelf.data.has_stack_bounds()
    }

    /// Format the TID, start addresses, TEB, and available stack bounds.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "pid={} tid={} start=0x{:x} system_start=0x{:x} win32_start={} teb={} stack={}",
            zelf.data.process_id,
            zelf.data.thread_id,
            zelf.data.start_address(),
            zelf.data.system_start_address,
            zelf.data
                .win32_start_address
                .map(|address| format!("0x{address:x}"))
                .unwrap_or_else(|| "none".to_string()),
            zelf.data
                .teb_address
                .map(|address| format!("0x{address:x}"))
                .unwrap_or_else(|| "none".to_string()),
            zelf.data
                .stack_limit
                .zip(zelf.data.stack_base)
                .map(|(limit, base)| format!("0x{limit:x}-0x{base:x}"))
                .unwrap_or_else(|| "none".to_string()),
        )
    }
}

#[derive(FromArgs)]
pub struct MemoryMapAllocationArgs {
    #[pyarg(any)]
    allocation_base: u64,
}

/// A captured virtual-memory map with reusable filters.
///
/// Properties return lists derived from the same snapshot; they do not re-query
/// the target. Call `Process.memory_map()` again to refresh the snapshot.
#[pyclass(module = false, name = "ProcessMemoryMap")]
#[derive(Debug, Clone, PyPayload)]
pub struct CProcessMemoryMap {
    regions: Vec<sysapi::MemoryRegion>,
}

#[pyclass]
impl CProcessMemoryMap {
    /// All regions in this snapshot, including uncommitted ranges.
    #[pygetset]
    fn regions(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
        memory_regions_to_py(&zelf.regions, vm)
    }

    /// Regions whose state is MEM_COMMIT.
    #[pygetset]
    fn committed(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
        memory_regions_to_py(&filtered_regions(&zelf.regions, |region| region.is_committed()), vm)
    }

    /// Committed regions with executable protection, excluding guard pages.
    #[pygetset]
    fn executable(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
        memory_regions_to_py(
            &filtered_regions(&zelf.regions, |region| {
                region.is_committed() && region.is_executable() && !region.is_guarded()
            }),
            vm,
        )
    }

    /// Deduplicated allocation bases in snapshot order, using region base when allocation base is zero.
    #[pygetset]
    fn allocation_bases(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<u64> {
        let mut bases = Vec::<u64>::new();

        for region in &zelf.regions {
            let base = memory_region_allocation_key(region);
            if !bases.contains(&base) {
                bases.push(base);
            }
        }

        PyListOf::new(bases, vm)
    }

    /// Return snapshot regions grouped under `allocation_base`.
    #[pymethod]
    fn regions_for_allocation(zelf: &Py<Self>, args: MemoryMapAllocationArgs, vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
        memory_regions_to_py(
            &filtered_regions(&zelf.regions, |region| {
                memory_region_allocation_key(region) == args.allocation_base
            }),
            vm,
        )
    }
}

/// Owned native process parameters initialized from an executable path.
///
/// Used by `Process.write_peb_proc_params()` when setting up an image-section
/// process. Creating this object does not start a process.
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

    /// Create native process parameters for `filepath`. Native errors raise `SystemError`.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let params = sysapi::create_process_parameters(&args.filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to create process parameters"))?;

        Ok(Self { params: params.into() })
    }
}

/// A process selection, native handle, and independent memory read/write strategies.
///
/// Select an existing process with `name`, decimal-string `pid`, or `current=True`;
/// select a new one with `image_path` or an image `section_handle`. Selection
/// precedence is current, PID, name, path, section. Construction does not open
/// or create the process. Call `open()`, `create_user()`, or `create()` as appropriate,
/// then `init_memory()` before strategy-based memory operations.
///
/// Strategies omitted from the constructor remain unset. Read and write choices
/// are independent; read-only analysis need not configure writing. A supplied
/// section handle is borrowed: keep its owning `Handle` alive through `create()`.
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

#[py_api]
#[derive(FromArgs)]
pub struct ProcessNewArgs {
    /// Select the current process when True; takes precedence over other selectors.
    #[pyarg(named, optional)]
    current: OptionalArg<bool>,
    /// Existing executable basename to find, such as notepad.exe.
    #[pyarg(named, optional)]
    name: OptionalArg<PyStrRef>,
    /// Existing process ID as a decimal string.
    #[pyarg(named, optional)]
    pid: OptionalArg<PyStrRef>,
    /// Executable path for create_user(); does not start it during construction.
    #[pyarg(named, optional)]
    image_path: OptionalArg<PyStrRef>,
    /// Image section for create(); keep this owning Handle alive until creation completes.
    #[pyarg(named, optional)]
    section_handle: OptionalArg<PyRef<Handle>>,
    /// Read strategy; omitted means no reader until configured by a higher-level facade.
    #[pyi(ty = "br3k.proc.ProcessVmReadStrategy | int")]
    #[pyarg(named, optional)]
    process_vm_read_strategy: OptionalArg<u32>,
    /// Write strategy; omitted means no writer.
    #[pyi(ty = "br3k.proc.ProcessVmWriteStrategy | int")]
    #[pyarg(named, optional)]
    process_vm_write_strategy: OptionalArg<u32>,
    /// Required by open(); omitted means no open strategy.
    #[pyi(ty = "br3k.proc.ProcessOpenStrategy | int")]
    #[pyarg(named, optional)]
    process_open_strategy: OptionalArg<u32>,
    /// Used by Thread.open(); omitted means no thread-open strategy.
    #[pyi(ty = "br3k.proc.ThreadOpenStrategy | int")]
    #[pyarg(named, optional)]
    thread_open_strategy: OptionalArg<u32>,
}

impl Constructor for Process {
    type Args = ProcessNewArgs;

    /// Select a target and store strategies without opening a handle.
    ///
    /// `pid` must be a decimal string, not an integer. Missing selection, an invalid
    /// PID, a failed name lookup, or an unknown strategy value raises `ValueError`.
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

#[py_api]
#[derive(FromArgs)]
pub struct CreateUserArgs {
    #[pyarg(any)]
    suspended: bool,
    /// Full Windows command line, including the executable name. Quote paths containing spaces.
    #[pyarg(named, optional)]
    command_line: OptionalArg<String>,
}

#[py_api]
#[derive(FromArgs)]
pub struct ProcessSuspendArgs {
    /// Defaults to NtSuspendProcess.
    #[pyi(ty = "br3k.proc.ProcessSuspendStrategy | int")]
    #[pyarg(named, optional)]
    process_suspend_strategy: OptionalArg<u32>,
}

#[py_api]
#[derive(FromArgs)]
pub struct ProcessResumeArgs {
    /// Defaults to NtResumeProcess.
    #[pyi(ty = "br3k.proc.ProcessResumeStrategy | int")]
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
pub struct ReadMemoryArgs {
    #[pyarg(any)]
    size: usize,
    #[pyarg(any, optional)]
    offset: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct DumpMemoryArgs {
    #[pyarg(any)]
    base_address: u64,
    #[pyarg(any)]
    size: usize,
}

#[derive(FromArgs)]
pub struct DumpModuleArgs {
    #[pyarg(any)]
    module: PyRef<CProcessModule>,
}

#[derive(FromArgs)]
pub struct WorkingSetRegionArgs {
    #[pyarg(any)]
    region: PyRef<CProcessMemoryRegion>,
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

#[derive(Debug, thiserror::Error)]
enum ProcessModuleError {
    #[error("process is not opened")]
    ProcessNotOpened,
    #[error("process loader data is not initialized")]
    LoaderNotInitialized,
    #[error("remote module list entry address underflow")]
    ModuleListAddressUnderflow,
    #[error("remote module list is too large or circular")]
    TooManyModules,
    #[error("remote UNICODE_STRING length is not even: {0}")]
    InvalidUnicodeLength(u16),
    #[error("remote UNICODE_STRING is too large: {0} bytes")]
    UnicodeStringTooLarge(usize),
    #[error("process API set map is null")]
    ApiSetMapMissing,
    #[error("process API set namespace size is invalid: {0}")]
    InvalidApiSetNamespaceSize(u32),
    #[error(transparent)]
    ApiSet(#[from] crate::pe::api_set::ApiSetError),
    #[error(transparent)]
    NtStatus(#[from] sysapi::NtStatusError),
}

//

#[pyclass(with(Constructor))]
impl Process {
    /// Thread created by `create_user()`. Raises `ValueError` before it exists.
    #[pygetset]
    fn main_thread(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyRef<Thread>> {
        let mut thread = zelf.thread.borrow_mut();
        let not_opened = || vm.new_value_error("Process main thread is not opened".to_string());
        let thread = thread.as_mut()
            .ok_or_else(not_opened)?.clone();

        Ok(thread)
    }

    /// Open the selected PID with PROCESS_ALL_ACCESS using `process_open_strategy`.
    ///
    /// Requires an explicit open strategy. Does not initialize memory or a main thread.
    #[pymethod]
    fn open(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let mut process_open_strategy = zelf.process_open_strategy.borrow_mut();
        let missing_strategy = || vm.new_value_error("Process open method is not set".to_string());
        let process_open_strategy = process_open_strategy.as_mut()
            .ok_or_else(missing_strategy)?;

        let handle = process_open_strategy
            .open(*zelf.pid.borrow(), PROCESS_ALL_ACCESS)
            .map_err(map_to_py_system_error(vm, "Unable to open process"))?;

        let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
        let basic_info = sysapi::get_process_basic_info(*handle)
            .map_err(read_basic_info_error)?;

        zelf.process_handle.replace(handle);
        zelf.pid.replace(basic_info.UniqueProcessId as _);

        Ok(())
    }

    /// Create a user process from `image_path` and retain its main thread.
    ///
    /// `suspended` controls initial thread suspension. Native failures raise `SystemError`.
    /// Optional `command_line` is passed verbatim; no shell is invoked. Omission preserves the native default.
    #[pymethod]
    fn create_user(zelf: PyRef<Self>, args: CreateUserArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut image_path = zelf.image_path.borrow_mut();
        let image_path = image_path.as_mut()
            .ok_or_else(|| vm.new_value_error("Process image path is not set".to_string()))?;

        let create_process_error = map_to_py_system_error(vm, "Unable to create process");
        let command_line = args.command_line.into_option();
        let (process_handle, thread_handle) = sysapi::create_user_process(&image_path, args.suspended, command_line.as_deref())
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

    /// Create a process from the supplied image section using the CreateProcess dispatch.
    ///
    /// Does not create a thread or install process parameters.
    #[pymethod]
    fn create(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let mut section_handle = zelf.section_handle.borrow_mut();
        let section_handle = section_handle.as_mut()
            .ok_or_else(|| vm.new_value_error("Process section handle is not set".to_string()))?;

        let process_handle = sysapi::create_process(*section_handle)
            .map_err(map_to_py_system_error(vm, "Unable to create process"))?;

        let read_basic_info_error = map_to_py_system_error(vm, "Unable to read process basic info");
        let basic_info = sysapi::get_process_basic_info(*process_handle)
            .map_err(read_basic_info_error)?;

        zelf.process_handle.replace(process_handle);
        zelf.pid.replace(basic_info.UniqueProcessId as _);

        Ok(())
    }

    /// Suspend the opened process. Defaults to `ProcessSuspendStrategy.NtSuspendProcess`.
    #[pymethod]
    fn suspend(zelf: &Py<Self>, args: ProcessSuspendArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = **zelf.process_handle.borrow();
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

    /// Resume the opened process. Defaults to `ProcessResumeStrategy.NtResumeProcess`.
    #[pymethod]
    fn resume(zelf: &Py<Self>, args: ProcessResumeArgs, vm: &VirtualMachine) -> PyResult<()> {
        let process_handle = **zelf.process_handle.borrow();
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

    /// Initialize the configured read and/or write strategies.
    ///
    /// At least one strategy must be set. LiveDumpParse captures a kernel dump and
    /// may require privileges and symbol downloads; it reads a snapshot, not live data.
    #[pymethod]
    fn init_memory(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let process_vm_read_strategy = zelf.process_vm_read_strategy.borrow().clone();
        let process_vm_write_strategy = zelf.process_vm_write_strategy.borrow().clone();

        if process_vm_read_strategy.is_none() && process_vm_write_strategy.is_none() {
            return Err(vm.new_value_error("Process VM read or write strategy is not set".to_string()));
        }

        let process_handle = **zelf.process_handle.borrow();

        if process_vm_read_strategy == Some(api_strategy::ProcessVmReadStrategy::LiveDumpParse) {
            sysapi::adjust_privilege(windef::ntseapi::SE_DEBUG_PRIVILEGE)
                .map_err(map_to_py_system_error(vm, "Unable to get debug privilege"))?;
        }

        let memory = api_strategy::ProcessMemory::init(
            process_vm_read_strategy.as_ref(),
            process_vm_write_strategy.as_ref(),
            process_handle,
            *zelf.pid.borrow()
        )
        .map_err(|e| {
            to_py_system_error(
                vm,
                &format!("Failed to initialize process VM strategies read={process_vm_read_strategy:?}, write={process_vm_write_strategy:?}"),
                e,
            )
        })?;

        zelf.memory.replace(Some(memory));
        Ok(())
    }

    /// Allocate or map `size` bytes through the initialized write strategy.
    ///
    /// Stores the resulting remote base for subsequent memory operations.
    #[pymethod]
    fn create_memory(zelf: &Py<Self>, args: CreateMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = zelf.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        memory.create_memory(args.size)
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to create memory"))?;

        Ok(())
    }

    /// Write byte values at an offset from the memory context's remote base.
    ///
    /// `offset` defaults to zero. Requires initialized writing and suitable target
    /// storage; this is not a file write or an automatic allocation.
    #[pymethod]
    fn write_memory(zelf: &Py<Self>, args: WriteMemoryArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = zelf.memory.borrow_mut();
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

    /// Read `size` bytes at `offset` from the memory context's remote base.
    ///
    /// `offset` defaults to zero. Requires an initialized read strategy.
    #[pymethod]
    fn read_memory(zelf: &Py<Self>, args: ReadMemoryArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let memory = zelf.memory.borrow();
        let memory = memory.as_ref()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let offset = args.offset.unwrap_or(0);
        let mut data = vec![0u8; args.size];

        memory
            .read_memory(offset, data.as_mut_ptr() as _, data.len())
            .map_err(map_process_memory_error_to_py_exception(vm, "Unable to read memory"))?;

        Ok(vm.ctx.new_bytes(data))
    }

    /// Read `size` bytes from an absolute target `base_address`.
    ///
    /// Requires an initialized read strategy. Returns mapped bytes, not a rebuilt PE file.
    #[pymethod]
    fn dump_memory(zelf: &Py<Self>, args: DumpMemoryArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let data = read_process_memory(zelf, args.base_address, args.size, vm)?;
        Ok(vm.ctx.new_bytes(data))
    }

    /// Read the loader module's complete mapped address range.
    ///
    /// Returns mapped bytes without repairing imports, file offsets, or unreadable
    /// ranges. Use `br3k.pe.ProcessView` and `Capture` for sparse capture and recovery.
    #[pymethod]
    fn dump_module(zelf: &Py<Self>, args: DumpModuleArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let data = read_process_memory(zelf, args.module.dll_base, args.module.size_of_image as usize, vm)?;
        Ok(vm.ctx.new_bytes(data))
    }

    /// Return the current memory context's remote base address.
    #[pymethod]
    fn get_memory_remote_address(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<u64> {
        let mut memory = zelf.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let remote_base_addr = memory.get_remote_base_addr() as u64;
        Ok(remote_base_addr)
    }

    //

    /// Return whether the opened process is native 64-bit rather than WOW64.
    ///
    /// The historical name does not distinguish AMD64 from ARM64.
    #[pymethod]
    pub fn is_x64(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<bool> {
        match sysapi::get_process_wow64_info(**zelf.process_handle.borrow()) {
            Ok(is_x64) => Ok(is_x64),
            Err(error) => Err(to_py_system_error(vm, "Unable to get Wow64 info", error)),
        }
    }

    //

    /// Query native process-basic information from the opened handle.
    #[pymethod]
    fn get_basic_info(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<CProcessBasicInformation> {
        let basic_info = sysapi::get_process_basic_info(**zelf.process_handle.borrow())
            .map_err(map_to_py_system_error(vm, "Unable to get process basic info"))?;

        Ok(CProcessBasicInformation { data: basic_info })
    }

    /// Snapshot modules listed by the target's loader; hidden mappings may be absent.
    #[pymethod]
    fn modules(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<CProcessModule>>> {
        let modules = list_process_modules(**zelf.process_handle.borrow())
            .map_err(map_to_py_system_error(vm, "Unable to list process modules"))?;
        let modules = modules
            .into_iter()
            .map(|module| module.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(modules, vm))
    }

    /// Enumerate a fresh list of virtual-memory regions from the opened process.
    #[pymethod]
    fn memory_regions(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<CProcessMemoryRegion>>> {
        let process_handle = **zelf.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let regions = sysapi::enumerate_memory_regions(process_handle)
            .map_err(map_to_py_system_error(vm, "Unable to enumerate process memory regions"))?;
        let regions = regions
            .into_iter()
            .map(|region| CProcessMemoryRegion { data: region }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(regions, vm))
    }

    /// Capture a fresh virtual-memory map with grouped/filterable region views.
    #[pymethod]
    fn memory_map(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<CProcessMemoryMap> {
        let process_handle = **zelf.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        let regions = sysapi::enumerate_memory_regions(process_handle)
            .map_err(map_to_py_system_error(vm, "Unable to enumerate process memory regions"))?;

        Ok(CProcessMemoryMap {
            regions,
        })
    }

    /// Query page-residency and sharing counters for the supplied region.
    #[pymethod]
    fn working_set_region(zelf: &Py<Self>, args: WorkingSetRegionArgs, vm: &VirtualMachine) -> PyResult<CProcessWorkingSetRegion> {
        let process_handle = **zelf.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        sysapi::query_working_set_region(process_handle, &args.region.data)
            .map(|data| CProcessWorkingSetRegion { data })
            .map_err(map_to_py_system_error(vm, "Unable to query region working set"))
    }

    /// Snapshot process threads with best-effort start addresses and stack bounds.
    #[pymethod]
    fn threads(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<CProcessThreadInfo>>> {
        let threads = process_threads(zelf)
            .map_err(map_to_py_system_error(vm, "Unable to query process threads"))?;

        Ok(process_threads_to_py(&threads, vm))
    }

    /// Read the process PEB's API-set namespace for contract-to-host resolution.
    #[pymethod]
    fn api_set_map(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PeApiSetMap> {
        let process_handle = **zelf.process_handle.borrow();
        if process_handle.is_null() {
            return Err(vm.new_system_error("Process is not opened"));
        }

        read_process_api_set_map(process_handle)
            .map(PeApiSetMap::from_map)
            .map_err(map_to_py_system_error(vm, "Unable to read process API set map"))
    }

    /// Copy the native-layout PEB from the opened process.
    #[pymethod]
    fn read_peb(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<CPeb> {
        unsafe {
            let process_handle = **zelf.process_handle.borrow();

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

    /// Copy process parameters and environment to target memory and update the PEB pointer.
    ///
    /// `peb_address` is an absolute target address. Requires an initialized write strategy.
    #[pymethod]
    fn write_peb_proc_params(zelf: &Py<Self>, args: WritePebProcParmsArgs, vm: &VirtualMachine) -> PyResult<()> {
        unsafe {
            let mut memory = zelf.memory.borrow_mut();
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

    /// Relocate mapped PE bytes to the memory context's base and write them there.
    ///
    /// Requires allocated target storage and an initialized write strategy. This is
    /// not a complete loader: it does not resolve imports or run TLS callbacks.
    #[pymethod]
    fn write_mem_image(zelf: &Py<Self>, args: WriteMemImageArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = zelf.memory.borrow_mut();
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

    /// Log accessible handle names, types, and associated process details.
    ///
    /// Returns no structured result; inaccessible per-handle details may be omitted.
    #[pymethod]
    fn log_handles(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<()> {
        let pid = *zelf.pid.borrow();

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

fn list_process_modules(process_handle: HANDLE) -> Result<Vec<CProcessModule>, ProcessModuleError> {
    if process_handle.is_null() {
        return Err(ProcessModuleError::ProcessNotOpened);
    }

    let basic_info = sysapi::get_process_basic_info(process_handle)?;
    let peb = read_remote_struct::<ntpebteb::PEB>(process_handle, basic_info.PebBaseAddress as usize)?;

    if peb.Ldr.is_null() {
        return Err(ProcessModuleError::LoaderNotInitialized);
    }

    let ldr = read_remote_struct::<ntpebteb::PEB_LDR_DATA>(process_handle, peb.Ldr as usize)?;
    let list_head = peb.Ldr as usize + offset_of!(ntpebteb::PEB_LDR_DATA, InLoadOrderModuleList);
    let mut current = ldr.InLoadOrderModuleList.Flink as usize;
    let mut modules = Vec::new();

    for _ in 0..MAX_MODULES {
        if current == 0 || current == list_head {
            return Ok(modules);
        }

        let entry_address = current
            .checked_sub(offset_of!(ntldr::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks))
            .ok_or(ProcessModuleError::ModuleListAddressUnderflow)?;
        let entry = read_remote_struct::<ntldr::LDR_DATA_TABLE_ENTRY>(process_handle, entry_address)?;

        modules.push(CProcessModule {
            dll_base: entry.DllBase as u64,
            entry_point: entry.EntryPoint as u64,
            size_of_image: entry.SizeOfImage,
            full_dll_name: read_remote_unicode_string(process_handle, entry.FullDllName.Length, entry.FullDllName.Buffer)?,
            base_dll_name: read_remote_unicode_string(process_handle, entry.BaseDllName.Length, entry.BaseDllName.Buffer)?,
        });

        current = entry.InLoadOrderLinks.Flink as usize;
    }

    Err(ProcessModuleError::TooManyModules)
}

pub(crate) fn process_modules(process: &Process) -> Result<Vec<CProcessModule>, String> {
    list_process_modules(**process.process_handle.borrow())
        .map_err(|error| error.to_string())
}

pub(crate) fn process_working_set_regions(
    process: &Process,
    regions: &[sysapi::MemoryRegion],
) -> Result<Vec<sysapi::WorkingSetRegionSummary>, String> {
    let process_handle = **process.process_handle.borrow();
    if process_handle.is_null() {
        return Err("process is not opened".to_string());
    }

    sysapi::query_working_set_regions(process_handle, regions)
        .map_err(|error| error.to_string())
}

pub(crate) fn process_threads(process: &Process) -> Result<Vec<sysapi::ProcessThreadInfo>, String> {
    let pid = *process.pid.borrow();
    if pid == 0 {
        return Err("process id is not set".to_string());
    }

    sysapi::query_process_threads(pid)
        .map_err(|error| error.to_string())
}

pub(crate) fn process_threads_to_py(
    threads: &[sysapi::ProcessThreadInfo],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<CProcessThreadInfo>> {
    let threads = threads
        .iter()
        .cloned()
        .map(|data| CProcessThreadInfo { data }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(threads, vm)
}

fn read_process_api_set_map(process_handle: HANDLE) -> Result<crate::pe::api_set::ApiSetMap, ProcessModuleError> {
    if process_handle.is_null() {
        return Err(ProcessModuleError::ProcessNotOpened);
    }

    let basic_info = sysapi::get_process_basic_info(process_handle)?;
    let peb = read_remote_struct::<ntpebteb::PEB>(process_handle, basic_info.PebBaseAddress as usize)?;
    let api_set_map = peb.ApiSetMap;
    if api_set_map.is_null() {
        return Err(ProcessModuleError::ApiSetMapMissing);
    }

    let mut header_data = vec![0u8; crate::pe::api_set::API_SET_NAMESPACE_HEADER_SIZE];
    sysapi::read_virtual_memory(header_data.as_mut_slice(), api_set_map as _, process_handle)?;

    let namespace_size = crate::pe::api_set::namespace_size(&header_data)?;
    let namespace_size_usize = namespace_size as usize;
    if namespace_size_usize > crate::pe::api_set::MAX_API_SET_NAMESPACE_SIZE
        || namespace_size_usize < crate::pe::api_set::API_SET_NAMESPACE_HEADER_SIZE {
        return Err(ProcessModuleError::InvalidApiSetNamespaceSize(namespace_size));
    }

    let mut namespace_data = vec![0u8; namespace_size_usize];
    sysapi::read_virtual_memory(namespace_data.as_mut_slice(), api_set_map as _, process_handle)?;

    Ok(crate::pe::api_set::ApiSetMap::parse(&namespace_data)?)
}

pub(crate) fn process_api_set_map(process: &Process) -> Result<crate::pe::api_set::ApiSetMap, String> {
    read_process_api_set_map(**process.process_handle.borrow())
        .map_err(|error| error.to_string())
}

pub(crate) fn read_process_memory(
    process: &Process,
    base_address: u64,
    size: usize,
    vm: &VirtualMachine,
) -> PyResult<Vec<u8>> {
    let memory = process.memory.borrow();
    let memory = memory.as_ref()
        .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

    let mut memory = memory.clone();
    memory.set_remote_base_addr(base_address as _);

    let mut data = vec![0u8; size];
    memory
        .read_memory(0, data.as_mut_ptr() as _, data.len())
        .map_err(map_process_memory_error_to_py_exception(vm, "Unable to dump memory"))?;

    Ok(data)
}

fn memory_regions_to_py(regions: &[sysapi::MemoryRegion], vm: &VirtualMachine) -> PyListOf<PyRef<CProcessMemoryRegion>> {
    let regions = regions
        .iter()
        .cloned()
        .map(|region| CProcessMemoryRegion { data: region }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(regions, vm)
}

pub(crate) fn working_set_regions_to_py(
    regions: &[sysapi::WorkingSetRegionSummary],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<CProcessWorkingSetRegion>> {
    let regions = regions
        .iter()
        .cloned()
        .map(|data| CProcessWorkingSetRegion { data }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(regions, vm)
}

fn filtered_regions<F>(
    regions: &[sysapi::MemoryRegion],
    predicate: F,
) -> Vec<sysapi::MemoryRegion>
where
    F: Fn(&sysapi::MemoryRegion) -> bool,
{
    regions
        .iter()
        .filter(|region| predicate(region))
        .cloned()
        .collect()
}

fn memory_region_allocation_key(region: &sysapi::MemoryRegion) -> u64 {
    if region.allocation_base == 0 {
        region.base_address
    } else {
        region.allocation_base
    }
}

fn read_remote_struct<T: Default>(
    process_handle: HANDLE,
    address: usize,
) -> Result<T, sysapi::NtStatusError> {
    let mut value = T::default();
    let buffer = unsafe {
        slice::from_raw_parts_mut(addr_of_mut!(value) as *mut u8, size_of::<T>())
    };

    sysapi::read_virtual_memory(buffer, address as _, process_handle)?;
    Ok(value)
}

fn read_remote_unicode_string(
    process_handle: HANDLE,
    length: u16,
    buffer: *mut u16,
) -> Result<String, ProcessModuleError> {
    let size = length as usize;
    if size == 0 || buffer.is_null() {
        return Ok(String::new());
    }
    if size % 2 != 0 {
        return Err(ProcessModuleError::InvalidUnicodeLength(length));
    }
    if size > MAX_UNICODE_STRING_BYTES {
        return Err(ProcessModuleError::UnicodeStringTooLarge(size));
    }

    let mut data = vec![0u8; size];
    sysapi::read_virtual_memory(data.as_mut_slice(), buffer as _, process_handle)?;

    let data = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();

    Ok(String::from_utf16_lossy(&data))
}

const MAX_MODULES: usize = 4096;
const MAX_UNICODE_STRING_BYTES: usize = 0x8000;
