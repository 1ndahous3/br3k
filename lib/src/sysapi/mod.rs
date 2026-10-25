use crate::prelude::*;
use crate::str::*;
use crate::fs;

pub mod backend;
pub mod ctx;

pub use backend::SysApiBackend;
pub use ctx::{InitOptions, SysApiCtx, SysApiDispatchConfig};

use self::backend::DirectSyscallError;
use self::ctx::{
    SysApiCtx as api_ctx,
    AllocateVirtualMemory,
    CreateProcess,
    CreateSection,
    CreateThread,
    MapViewOfSection,
    QueueApcThread,
    ReadVirtualMemory,
    SetInformation_Delete,
    SetInformation_Rename,
    UnmapViewOfSection,
    SysApiCtxError,
};

use std::fmt;
use std::arch;
use std::slice;
use std::path::PathBuf;
use std::collections::HashMap;

use scopeguard::ScopeGuard;
use windef::winbase::{AlignedContext, AlignedWow64Context};

use windows::Win32::Foundation::{HMODULE, NTSTATUS};
use windows::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::Foundation::{HANDLE, HWND, FALSE, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, WOW64_CONTEXT};
use windows_sys::Win32::System::Threading::{
    EVENT_ALL_ACCESS, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};
use windows_sys::Win32::System::JobObjects::JOBOBJECT_ASSOCIATE_COMPLETION_PORT;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, MEMORY_BASIC_INFORMATION,
    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
    PAGE_NOCACHE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_WRITECOMBINE, SEC_COMMIT,
    SEC_IMAGE, SECTION_FLAGS, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE,
    SECTION_ALL_ACCESS,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE,
    SYNCHRONIZE,
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_DATA, FILE_WRITE_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE
};

use windef::*;
use winbase::{ULONG, NT_CURRENT_PROCESS};

pub type NtResult<T> = Result<T, NtStatusError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub region_size: usize,
    pub state: u32,
    pub protect: u32,
    pub memory_type: u32,
    pub mapped_path: Option<String>,
}

impl MemoryRegion {
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.region_size as u64)
    }

    pub fn is_committed(&self) -> bool {
        self.state == MEM_COMMIT
    }

    pub fn is_executable(&self) -> bool {
        is_executable_protection(self.protect)
    }

    pub fn is_writable_executable(&self) -> bool {
        is_writable_executable_protection(self.protect)
    }

    pub fn is_guarded(&self) -> bool {
        self.protect & PAGE_GUARD != 0
    }

    pub fn is_image(&self) -> bool {
        self.memory_type == MEM_IMAGE
    }

    pub fn is_mapped(&self) -> bool {
        self.memory_type == MEM_MAPPED
    }

    pub fn is_private(&self) -> bool {
        self.memory_type == MEM_PRIVATE
    }
}

impl From<MEMORY_BASIC_INFORMATION> for MemoryRegion {
    fn from(info: MEMORY_BASIC_INFORMATION) -> Self {
        Self {
            base_address: info.BaseAddress as u64,
            allocation_base: info.AllocationBase as u64,
            allocation_protect: info.AllocationProtect,
            region_size: info.RegionSize,
            state: info.State,
            protect: info.Protect,
            memory_type: info.Type,
            mapped_path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingSetPage {
    pub address: u64,
    pub flags: usize,
}

impl WorkingSetPage {
    pub fn is_valid(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn is_shared(&self) -> bool {
        self.flags & (1 << 15) != 0
    }

    pub fn is_private(&self) -> bool {
        self.is_valid() && !self.is_shared()
    }

    pub fn is_locked(&self) -> bool {
        self.flags & (1 << 22) != 0
    }

    pub fn is_large_page(&self) -> bool {
        self.flags & (1 << 23) != 0
    }

    pub fn is_bad(&self) -> bool {
        self.flags & (1 << 31) != 0
    }

    pub fn share_count(&self) -> u8 {
        ((self.flags >> 1) & 0x7) as u8
    }

    pub fn protection(&self) -> u16 {
        ((self.flags >> 4) & 0x7ff) as u16
    }

    pub fn node(&self) -> u16 {
        ((self.flags >> 16) & 0x3f) as u16
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkingSetRegionSummary {
    pub region: MemoryRegion,
    pub page_size: usize,
    pub page_count: usize,
    pub valid_page_count: usize,
    pub shared_page_count: usize,
    pub private_page_count: usize,
    pub invalid_page_count: usize,
    pub bad_page_count: usize,
}

impl WorkingSetRegionSummary {
    fn new(region: MemoryRegion, page_size: usize, page_count: usize) -> Self {
        Self {
            region,
            page_size,
            page_count,
            valid_page_count: 0,
            shared_page_count: 0,
            private_page_count: 0,
            invalid_page_count: 0,
            bad_page_count: 0,
        }
    }

    fn push_page(&mut self, page: WorkingSetPage) {
        if page.is_valid() {
            self.valid_page_count += 1;

            if page.is_shared() {
                self.shared_page_count += 1;
            } else {
                self.private_page_count += 1;
            }
        } else {
            self.invalid_page_count += 1;
        }

        if page.is_bad() {
            self.bad_page_count += 1;
        }
    }

    pub fn has_private_pages(&self) -> bool {
        self.private_page_count != 0
    }
}

const MAX_MEMORY_REGIONS: usize = 1_000_000;
const SYSTEM_PROCESS_INFORMATION_INITIAL_SIZE: usize = 0x10000;
const SYSTEM_PROCESS_INFORMATION_MAX_SIZE: usize = 0x10000000;
const WORKING_SET_QUERY_CHUNK_PAGES: usize = 4096;

pub type UniqueHandle = ScopeGuard<HANDLE, fn(HANDLE)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProcessThreadInfo {
    pub thread_id: u32,
    pub system_start_address: u64,
    pub win32_start_address: Option<u64>,
    pub teb_address: Option<u64>,
    pub stack_base: Option<u64>,
    pub stack_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProcessInfo {
    pub process_id: u32,
    pub image_name: Option<String>,
    pub threads: Vec<SystemProcessThreadInfo>,
}

#[derive(Debug, Clone)]
pub struct ProcessThreadInfo {
    pub process_id: u32,
    pub thread_id: u32,
    pub system_start_address: u64,
    pub win32_start_address: Option<u64>,
    pub teb_address: Option<u64>,
    pub stack_base: Option<u64>,
    pub stack_limit: Option<u64>,
}

impl ProcessThreadInfo {
    pub fn start_address(&self) -> u64 {
        self.win32_start_address
            .filter(|address| *address != 0)
            .unwrap_or(self.system_start_address)
    }

    pub fn has_stack_bounds(&self) -> bool {
        self.stack_limit
            .zip(self.stack_base)
            .is_some_and(|(limit, base)| limit != 0 && limit < base)
    }

    pub fn stack_contains(&self, address: u64) -> bool {
        self.stack_limit
            .zip(self.stack_base)
            .is_some_and(|(limit, base)| address >= limit && address < base)
    }
}

pub fn ntstatus_decode(status: NTSTATUS) -> String {
    format!(
        "0x{:x} ({})",
        status.0 as u32,
        api_ctx::ntstatus_decoder()
            .get(&status.0).copied()
            .unwrap_or("UNKNOWN_STATUS")
    )
}

#[derive(Debug, Clone, Copy)]
pub struct NtStatusError {
    pub operation: Option<&'static str>,
    pub status: NTSTATUS,
}

impl NtStatusError {
    pub fn new(operation: &'static str, status: NTSTATUS) -> Self {
        Self { operation: Some(operation), status }
    }

    pub fn from_status(status: NTSTATUS) -> Self {
        Self { operation: None, status }
    }

    pub fn with_operation(self, operation: &'static str) -> Self {
        Self { operation: Some(operation), ..self }
    }
}

impl fmt::Display for NtStatusError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(operation) = self.operation {
            write!(f, "{}: {}", operation, ntstatus_decode(self.status))
        } else {
            write!(f, "{}", ntstatus_decode(self.status))
        }
    }
}

impl std::error::Error for NtStatusError {}

impl From<NTSTATUS> for NtStatusError {
    fn from(status: NTSTATUS) -> Self {
        Self::from_status(status)
    }
}

fn require_api<T>(api: Option<T>, operation: &'static str) -> NtResult<T> {
    api.ok_or_else(|| NtStatusError::new(operation, NTSTATUS(ntstatus::STATUS_PROCEDURE_NOT_FOUND)))
}

fn require_sys_api<T: Copy>(api: Option<T>, operation: &'static str) -> NtResult<T> {
    let api = require_api(api, operation)?;

    if api_ctx::sys_api_backend() != SysApiBackend::DirectSyscall {
        return Ok(api);
    }

    api_ctx::direct_syscall(operation, api).map_err(|error| {
        log::error!("{error}");

        let status = match error {
            SysApiCtxError::DirectSyscall(DirectSyscallError::SyscallIdNotFound { .. }) => {
                ntstatus::STATUS_PROCEDURE_NOT_FOUND
            }
            SysApiCtxError::DirectSyscall(
                DirectSyscallError::StubNotPrepared { .. } |
                DirectSyscallError::StubAllocationFailed { .. } |
                DirectSyscallError::StubInstructionCacheFlushFailed { .. }
            ) => {
                ntstatus::STATUS_NOT_SUPPORTED
            }
            _ => ntstatus::STATUS_UNSUCCESSFUL,
        };

        NtStatusError::new(operation, NTSTATUS(status))
    })
}

fn is_memory_query_end(error: NtStatusError) -> bool {
    matches!(
        error.status.0,
        ntstatus::STATUS_INVALID_PARAMETER | ntstatus::STATUS_ACCESS_VIOLATION
    )
}

fn is_executable_protection(protect: u32) -> bool {
    let protect = protect & !(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

    matches!(
        protect,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

fn is_writable_executable_protection(protect: u32) -> bool {
    let protect = protect & !(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

    matches!(protect, PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
}

fn page_count(size: usize, page_size: usize) -> usize {
    if page_size == 0 {
        return 0;
    }

    size.saturating_add(page_size - 1) / page_size
}

pub fn close_handle(handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_close = require_sys_api(api_ctx::ntdll().NtClose, "NtClose")?;
        let status = NTSTATUS(nt_close(handle));
        status
            .is_ok()
            .then_some(())
            .ok_or_else(|| status.into())
    }
}

pub fn duplicate_handle(
    target_process_handle: HANDLE,
    source_handle: HANDLE,
    source_process_handle: HANDLE
) -> NtResult<UniqueHandle> {
    duplicate_handle_ex(
        target_process_handle,
        source_handle,
        source_process_handle,
        0,
        ntobapi::DUPLICATE_SAME_ACCESS,
    )
}

pub fn duplicate_handle_with_access(
    target_process_handle: HANDLE,
    source_handle: HANDLE,
    source_process_handle: HANDLE,
    desired_access: winbase::ACCESS_MASK,
) -> NtResult<UniqueHandle> {
    duplicate_handle_ex(
        target_process_handle,
        source_handle,
        source_process_handle,
        desired_access,
        0,
    )
}

fn duplicate_handle_ex(
    target_process_handle: HANDLE,
    source_handle: HANDLE,
    source_process_handle: HANDLE,
    desired_access: winbase::ACCESS_MASK,
    options: ULONG,
) -> NtResult<UniqueHandle> {
    unsafe {
        let target_handle: HANDLE = ptr::null_mut();

        let nt_duplicate_object = require_sys_api(api_ctx::ntdll().NtDuplicateObject, "NtDuplicateObject")?;
        let status = NTSTATUS(nt_duplicate_object(
            source_process_handle,
            source_handle,
            target_process_handle,
            addr_of!(target_handle) as _,
            desired_access,
            0,
            options,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(target_handle)) }
    }
}

fn wrap_handle(handle: HANDLE) -> UniqueHandle {
    fn handle_close_deleter(handle: HANDLE) {
        let _ = close_handle(handle);
    }
    scopeguard::guard(handle, handle_close_deleter)
}

pub fn null_handle() -> UniqueHandle {
    fn handle_close_deleter(handle: HANDLE) {
        let _ = close_handle(handle);
    }
    scopeguard::guard(ptr::null_mut(), handle_close_deleter)
}

pub fn peb() -> ntpebteb::PPEB {
    unsafe { (*teb()).ProcessEnvironmentBlock }
}

pub fn teb() -> ntexapi::PTEB {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let teb: u64;
            arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
            teb as _
        }
    }
    #[cfg(target_arch = "x86")]
    {
        unsafe {
            let teb: u32;
            arch::asm!("mov {}, fs:[0x18]", out(reg) teb);
            teb as _
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            let teb: usize;
            arch::asm!("mov {}, x18", out(reg) teb);
            teb as _
        }
    }
}

pub type UniqueProcessParameters = ScopeGuard<
    ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
    fn(ntpebteb::PRTL_USER_PROCESS_PARAMETERS)
>;

pub fn create_process_parameters(name: &str) -> NtResult<UniqueProcessParameters> {
    unsafe {
        let nt_name = format!("\\??\\{name}");
        let nt_name = U16CString::from_str(nt_name).unwrap();
        let nt_name = to_unicode_string(&nt_name);

        let mut current_directory = [0u16; MAX_PATH as usize];
        GetCurrentDirectoryW(Some(&mut current_directory));
        let current_directory = to_unicode_string(&current_directory);

        let peb = peb();

        let process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
        let status = NTSTATUS(api_ctx::ntdll().RtlCreateProcessParametersEx.unwrap()(
            addr_of!(process_parameters) as _,
            addr_of!(nt_name) as _,
            addr_of!((*(*peb).ProcessParameters).DllPath) as _,
            addr_of!(current_directory) as _,
            addr_of!(nt_name) as _,
            (*(*peb).ProcessParameters).Environment,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_process_parameters(process_parameters)) }
    }
}

pub fn destroy_process_parameters(process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS) {
    unsafe {
        api_ctx::ntdll().RtlDestroyProcessParameters.unwrap()(process_parameters);
    }
}
fn wrap_process_parameters(process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS) -> UniqueProcessParameters {
    fn process_parameters_destroy_deleter(process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS) {
        destroy_process_parameters(process_parameters);
    }
    scopeguard::guard(process_parameters, process_parameters_destroy_deleter)
}

// ProcessHandle, ThreadHandle
pub fn create_user_process(name: &str, suspended: bool, command_line: Option<&str>) -> NtResult<(UniqueHandle, UniqueHandle)> {
    unsafe {
        let nt_name = format!("\\??\\{name}");
        let invalid_parameter = || NtStatusError::from(NTSTATUS(ntstatus::STATUS_INVALID_PARAMETER));
        let nt_name = U16CString::from_str(nt_name).map_err(|_| invalid_parameter())?;
        let command_line = command_line.map(U16CString::from_str).transpose().map_err(|_| invalid_parameter())?;
        if nt_name.len() >= u16::MAX as usize / 2 || command_line.as_ref().is_some_and(|value| value.len() >= u16::MAX as usize / 2) {
            return Err(invalid_parameter());
        }
        let nt_name = to_unicode_string(&nt_name);
        let command_line = command_line.as_ref().map(to_unicode_string);

        let process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
        let status = NTSTATUS(api_ctx::ntdll().RtlCreateProcessParametersEx.unwrap()(
            addr_of!(process_parameters) as _,
            addr_of!(nt_name) as _,
            ptr::null_mut(),
            ptr::null_mut(),
            command_line.as_ref().map_or(ptr::null_mut(), |value| addr_of!(*value) as _),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED,
        ));

        if !status.is_ok() {
            return Err(status.into());
        }
        let process_parameters = wrap_process_parameters(process_parameters);

        let create_info = ntpsapi::PS_CREATE_INFO {
            Size: size_of::<ntpsapi::PS_CREATE_INFO>(),
            State: ntpsapi::PS_CREATE_STATE::PsCreateInitialState,
            ..Default::default()
        };

        let mut attribute_list = ntpsapi::PS_ATTRIBUTE_LIST {
            TotalLength: size_of::<ntpsapi::PS_ATTRIBUTE_LIST>(),
            Attributes: [ntpsapi::PS_ATTRIBUTE { ..Default::default() }],
        };

        attribute_list.Attributes[0].Attribute = winbase::PS_ATTRIBUTE_IMAGE_NAME as _;
        attribute_list.Attributes[0].Size = nt_name.Length as _;
        *attribute_list.Attributes[0].a1.ValuePtr.as_mut() = nt_name.Buffer as _;

        let process_handle: HANDLE = ptr::null_mut();
        let thread_handle: HANDLE = ptr::null_mut();

        let nt_create_user_process = require_sys_api(api_ctx::ntdll().NtCreateUserProcess, "NtCreateUserProcess")?;
        let status = NTSTATUS(nt_create_user_process(
            addr_of!(process_handle) as _,
            addr_of!(thread_handle) as _,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            if suspended { ntpsapi::THREAD_CREATE_FLAGS_CREATE_SUSPENDED } else { ntpsapi::THREAD_CREATE_FLAGS_NONE },
            *process_parameters as _,
            addr_of!(create_info) as _,
            addr_of!(attribute_list) as _,
        ));

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_OBJECT_PATH_INVALID {
                log::warn!("the process \"{name}\" probably has an IFEO key without a 'Debugger' value");
            }

            Err(status.into())
        } else {
            Ok((wrap_handle(process_handle), wrap_handle(thread_handle)))
        }
    }
}

pub fn create_process(section_handle: HANDLE) -> NtResult<UniqueHandle> {
    unsafe {
        let process_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status: NTSTATUS = match api_ctx::sys_api_dispatch().create_process {
            CreateProcess::NtCreateProcess => {
                let nt_create_process = require_sys_api(api_ctx::ntdll().NtCreateProcess, "NtCreateProcess")?;
                NTSTATUS(nt_create_process(
                    addr_of!(process_handle) as _,
                    PROCESS_ALL_ACCESS,
                    addr_of!(object_attributes) as _,
                    NT_CURRENT_PROCESS,
                    true.into(),
                    section_handle,
                    ptr::null_mut(),
                    ptr::null_mut(),
                ))
            }
            CreateProcess::NtCreateProcessEx => {
                let nt_create_process_ex = require_sys_api(api_ctx::ntdll().NtCreateProcessEx, "NtCreateProcessEx")?;
                NTSTATUS(nt_create_process_ex(
                    addr_of!(process_handle) as _,
                    PROCESS_ALL_ACCESS,
                    addr_of!(object_attributes) as _,
                    NT_CURRENT_PROCESS,
                    ntpsapi::PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                    section_handle,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(process_handle)) }
    }
}

pub fn get_process_basic_info(process_handle: HANDLE) -> NtResult<ntpsapi::PROCESS_BASIC_INFORMATION> {
    unsafe {
        let basic_info = ntpsapi::PROCESS_BASIC_INFORMATION::default();

        let nt_query_information_process = require_sys_api(api_ctx::ntdll().NtQueryInformationProcess, "NtQueryInformationProcess")?;
        let status = NTSTATUS(nt_query_information_process(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessBasicInformation,
            addr_of!(basic_info) as _,
            size_of::<ntpsapi::PROCESS_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(basic_info) }
    }
}

pub fn get_process_wow64_info(process_handle: HANDLE) -> NtResult<bool> {
    unsafe {
        let wow64_info: usize = 0;

        let nt_query_information_process = require_sys_api(api_ctx::ntdll().NtQueryInformationProcess, "NtQueryInformationProcess")?;
        let status = NTSTATUS(nt_query_information_process(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessWow64Information,
            addr_of!(wow64_info) as _,
            size_of::<usize>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wow64_info == 0) }
    }
}

fn query_system_process_information(
    info_class: ntexapi::SYSTEM_INFORMATION_CLASS,
) -> NtResult<Vec<u8>> {
    unsafe {
        let nt_query_system_information = require_sys_api(api_ctx::ntdll().NtQuerySystemInformation, "NtQuerySystemInformation")?;
        let mut size = SYSTEM_PROCESS_INFORMATION_INITIAL_SIZE;

        loop {
            let mut data = vec![0u8; size];
            let mut return_length: ULONG = 0;
            let status = NTSTATUS(nt_query_system_information(
                info_class,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of_mut!(return_length) as _,
            ));

            if status.is_ok() {
                return Ok(data);
            }

            if !matches!(
                status.0,
                ntstatus::STATUS_INFO_LENGTH_MISMATCH |
                ntstatus::STATUS_BUFFER_OVERFLOW |
                ntstatus::STATUS_BUFFER_TOO_SMALL
            ) {
                return Err(NtStatusError::new("NtQuerySystemInformation", status));
            }

            let next_size = (return_length as usize)
                .max(size.saturating_mul(2))
                .saturating_add(0x1000);

            if next_size <= size || next_size > SYSTEM_PROCESS_INFORMATION_MAX_SIZE {
                return Err(NtStatusError::new("NtQuerySystemInformation", status));
            }

            size = next_size;
        }
    }
}

pub fn system_processes() -> NtResult<Vec<SystemProcessInfo>> {
    match system_processes_by_class(ntexapi::SYSTEM_INFORMATION_CLASS::SystemExtendedProcessInformation, true) {
        Ok(processes) => Ok(processes),
        Err(error) if matches!(
            error.status.0,
            ntstatus::STATUS_INVALID_INFO_CLASS | ntstatus::STATUS_NOT_IMPLEMENTED
        ) => system_processes_by_class(ntexapi::SYSTEM_INFORMATION_CLASS::SystemProcessInformation, false),
        Err(error) => Err(error),
    }
}

fn system_processes_by_class(
    info_class: ntexapi::SYSTEM_INFORMATION_CLASS,
    extended_threads: bool,
) -> NtResult<Vec<SystemProcessInfo>> {
    let data = query_system_process_information(info_class)?;
    let mut processes = Vec::new();
    let mut offset = 0usize;
    let min_entry_size = offset_of!(ntexapi::SYSTEM_PROCESS_INFORMATION, Threads);

    loop {
        if offset.checked_add(min_entry_size).is_none_or(|end| end > data.len()) {
            return Err(NtStatusError::new("NtQuerySystemInformation", NTSTATUS(ntstatus::STATUS_INFO_LENGTH_MISMATCH)));
        }

        let info = unsafe { &*(data.as_ptr().add(offset) as *const ntexapi::SYSTEM_PROCESS_INFORMATION) };
        let entry_end = if info.NextEntryOffset == 0 {
            data.len()
        } else {
            offset
                .checked_add(info.NextEntryOffset as usize)
                .ok_or_else(|| NtStatusError::new("NtQuerySystemInformation", NTSTATUS(ntstatus::STATUS_INTEGER_OVERFLOW)))?
        };

        if entry_end <= offset || entry_end > data.len() {
            return Err(NtStatusError::new("NtQuerySystemInformation", NTSTATUS(ntstatus::STATUS_INFO_LENGTH_MISMATCH)));
        }

        let thread_count = info.NumberOfThreads as usize;
        let thread_size = if extended_threads {
            size_of::<ntexapi::SYSTEM_EXTENDED_THREAD_INFORMATION>()
        } else {
            size_of::<ntexapi::SYSTEM_THREAD_INFORMATION>()
        };
        let thread_bytes = thread_count
            .checked_mul(thread_size)
            .ok_or_else(|| NtStatusError::new("NtQuerySystemInformation", NTSTATUS(ntstatus::STATUS_INTEGER_OVERFLOW)))?;
        let thread_start = offset + offset_of!(ntexapi::SYSTEM_PROCESS_INFORMATION, Threads);

        if thread_start.checked_add(thread_bytes).is_none_or(|end| end > entry_end) {
            return Err(NtStatusError::new("NtQuerySystemInformation", NTSTATUS(ntstatus::STATUS_INFO_LENGTH_MISMATCH)));
        }

        let threads = if extended_threads {
            extended_process_threads(unsafe { data.as_ptr().add(thread_start) }, thread_count)
        } else {
            basic_process_threads(unsafe { data.as_ptr().add(thread_start) }, thread_count)
        };

        processes.push(SystemProcessInfo {
            process_id: info.UniqueProcessId as usize as u32,
            image_name: system_process_image_name(info),
            threads,
        });

        if info.NextEntryOffset == 0 {
            return Ok(processes);
        }

        offset = entry_end;
    }
}

fn basic_process_threads(
    thread_start: *const u8,
    thread_count: usize,
) -> Vec<SystemProcessThreadInfo> {
    let threads = unsafe {
        slice::from_raw_parts(thread_start as *const ntexapi::SYSTEM_THREAD_INFORMATION, thread_count)
    };

    threads
        .iter()
        .map(|thread| SystemProcessThreadInfo {
            thread_id: thread.ClientId.UniqueThread as usize as u32,
            system_start_address: thread.StartAddress as usize as u64,
            win32_start_address: None,
            teb_address: None,
            stack_base: None,
            stack_limit: None,
        })
        .collect()
}

fn extended_process_threads(
    thread_start: *const u8,
    thread_count: usize,
) -> Vec<SystemProcessThreadInfo> {
    let threads = unsafe {
        slice::from_raw_parts(thread_start as *const ntexapi::SYSTEM_EXTENDED_THREAD_INFORMATION, thread_count)
    };

    threads
        .iter()
        .map(|thread| {
            let thread_info = unsafe { thread.a1.ThreadInfo.as_ref() };

            SystemProcessThreadInfo {
                thread_id: thread_info.ClientId.UniqueThread as usize as u32,
                system_start_address: thread_info.StartAddress as usize as u64,
                win32_start_address: nonzero_address(thread.Win32StartAddress as usize as u64),
                teb_address: nonzero_address(thread.TebBaseAddress as usize as u64),
                stack_base: nonzero_address(thread.StackBase as u64),
                stack_limit: nonzero_address(thread.StackLimit as u64),
            }
        })
        .collect()
}

fn nonzero_address(address: u64) -> Option<u64> {
    (address != 0).then_some(address)
}

fn system_process_image_name(info: &ntexapi::SYSTEM_PROCESS_INFORMATION) -> Option<String> {
    if info.ImageName.Length == 0 || info.ImageName.Buffer.is_null() {
        return None;
    }

    Some(to_u16cstring(&info.ImageName).to_string_lossy())
}

pub fn find_process(name: &str) -> NtResult<u32> {
    let mut pid = 0;
    for process in system_processes()? {
        let Some(image_name) = process.image_name else {
            continue;
        };

        if !name.eq_ignore_ascii_case(&image_name) {
            continue;
        }

        if pid != 0 {
            return Err(NTSTATUS(ntstatus::STATUS_TOO_MANY_NAMES).into());
        }

        pid = process.process_id;
    }

    if pid == 0 { Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND).into()) } else { Ok(pid) }
}

pub fn get_processes_pid_name() -> NtResult<HashMap<u32, String>> {
    Ok(system_processes()?
        .into_iter()
        .filter_map(|process| process.image_name.map(|name| (process.process_id, name)))
        .collect())
}

pub fn open_process_by_hwnd(hwnd: HWND, access_mask: winbase::ACCESS_MASK) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_user_get_window_process_handle = require_sys_api(
            api_ctx::win32u().NtUserGetWindowProcessHandle,
            "NtUserGetWindowProcessHandle"
        )?;
        let process_handle = nt_user_get_window_process_handle(hwnd, access_mask);
        if process_handle.is_null() {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL).into())
        } else {
            Ok(wrap_handle(process_handle))
        }
    }
}

pub fn open_process(pid: u32, access_mask: u32) -> NtResult<UniqueHandle> {
    unsafe {
        let process_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let client_id = ntdef::CLIENT_ID {
            UniqueProcess: pid as _,
            ..Default::default()
        };

        let nt_open_process = require_sys_api(api_ctx::ntdll().NtOpenProcess, "NtOpenProcess")?;
        let status = NTSTATUS(nt_open_process(
            addr_of!(process_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(client_id) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(process_handle)) }
    }
}

pub fn suspend_process(process_handle: HANDLE) -> NtResult<()> {
    suspend_process_by_nt_suspend_process(process_handle)
}

pub fn suspend_process_by_nt_suspend_process(process_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_suspend_process = require_sys_api(api_ctx::ntdll().NtSuspendProcess, "NtSuspendProcess")?;
        let status = NTSTATUS(nt_suspend_process(process_handle));
        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn resume_process(process_handle: HANDLE) -> NtResult<()> {
    resume_process_by_nt_resume_process(process_handle)
}

pub fn resume_process_by_nt_resume_process(process_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_resume_process = require_sys_api(api_ctx::ntdll().NtResumeProcess, "NtResumeProcess")?;
        let status = NTSTATUS(nt_resume_process(process_handle));
        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn suspend_process_by_state_change(process_handle: HANDLE) -> NtResult<()> {
    change_process_state(process_handle, ntpsapi::PROCESS_STATE_CHANGE_TYPE::ProcessStateChangeSuspend)
}

pub fn resume_process_by_state_change(process_handle: HANDLE) -> NtResult<()> {
    change_process_state(process_handle, ntpsapi::PROCESS_STATE_CHANGE_TYPE::ProcessStateChangeResume)
}

fn change_process_state(process_handle: HANDLE, state_change_type: ntpsapi::PROCESS_STATE_CHANGE_TYPE) -> NtResult<()> {
    unsafe {
        let state_change_handle: HANDLE = ptr::null_mut();
        let nt_create_process_state_change = require_sys_api(api_ctx::ntdll().NtCreateProcessStateChange, "NtCreateProcessStateChange")?;
        let status = NTSTATUS(nt_create_process_state_change(
            addr_of!(state_change_handle) as _,
            ntpsapi::STATECHANGE_SET_ATTRIBUTES,
            ptr::null_mut(),
            process_handle,
            0,
        ));

        if !status.is_ok() {
            return Err(status.into());
        }

        let state_change_handle = wrap_handle(state_change_handle);
        let nt_change_process_state = require_sys_api(api_ctx::ntdll().NtChangeProcessState, "NtChangeProcessState")?;
        let status = NTSTATUS(nt_change_process_state(
            *state_change_handle,
            process_handle,
            state_change_type,
            ptr::null_mut(),
            0,
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn open_next_thread(process_handle: HANDLE, thread_handle: HANDLE, access_mask: winbase::ACCESS_MASK) -> NtResult<UniqueHandle> {
    unsafe {
        let new_thread_handle: HANDLE = ptr::null_mut();

        let nt_get_next_thread = require_sys_api(api_ctx::ntdll().NtGetNextThread, "NtGetNextThread")?;
        let status = NTSTATUS(nt_get_next_thread(
            process_handle,
            thread_handle,
            access_mask,
            0,
            0,
            addr_of!(new_thread_handle) as _,
        ));

        if !status.is_ok() {
            if status.0 != ntstatus::STATUS_NO_MORE_ENTRIES {
                return Err(status.into());
            }

            return Ok(wrap_handle(new_thread_handle));
        }

        Ok(wrap_handle(new_thread_handle))
    }
}

pub fn open_thread(pid: u32, tid: u32, access_mask: winbase::ACCESS_MASK) -> NtResult<UniqueHandle> {
    unsafe {
        let thread_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let client_id = ntdef::CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: tid as _
        };

        let nt_open_thread = require_sys_api(api_ctx::ntdll().NtOpenThread, "NtOpenThread")?;
        let status = NTSTATUS(nt_open_thread(
            addr_of!(thread_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(client_id) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(thread_handle)) }
    }
}

pub fn query_thread_win32_start_address(thread_handle: HANDLE) -> NtResult<u64> {
    unsafe {
        let mut start_address: PVOID = ptr::null_mut();

        let nt_query_information_thread = require_sys_api(api_ctx::ntdll().NtQueryInformationThread, "NtQueryInformationThread")?;
        let status = NTSTATUS(nt_query_information_thread(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadQuerySetWin32StartAddress,
            addr_of_mut!(start_address) as _,
            size_of::<PVOID>() as _,
            ptr::null_mut(),
        ));

        status
            .is_ok()
            .then_some(start_address as usize as u64)
            .ok_or_else(|| NtStatusError::new("NtQueryInformationThread", status))
    }
}

pub fn query_process_threads(process_id: u32) -> NtResult<Vec<ProcessThreadInfo>> {
    let Some(process) = system_processes()?
        .into_iter()
        .find(|process| process.process_id == process_id)
    else {
        return Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND).into());
    };

    Ok(process
        .threads
        .into_iter()
        .map(|thread| {
            ProcessThreadInfo {
                process_id,
                thread_id: thread.thread_id,
                system_start_address: thread.system_start_address,
                win32_start_address: thread.win32_start_address,
                teb_address: thread.teb_address,
                stack_base: thread.stack_base,
                stack_limit: thread.stack_limit,
            }
        })
        .collect())
}

fn create_thread_stack(process_handle: HANDLE, initial_teb: ntpsapi::PINITIAL_TEB) -> NtResult<()> {
    unsafe {
        let sys_info = system_basic_information()?;

        //
        // if stack is in the current process, then default to
        // the parameters from the image
        //

        let mut maximum_stack_size = sys_info.AllocationGranularity;
        let committed_stack_size = sys_info.PageSize;

        //
        // Enforce a minimal stack commit if there is a PEB setting
        // for this.
        //

        if committed_stack_size >= maximum_stack_size {
            maximum_stack_size = committed_stack_size.next_multiple_of(1024 * 1024);
        }

        let mut committed_stack_size = committed_stack_size.next_multiple_of(sys_info.PageSize);
        let maximum_stack_size = maximum_stack_size.next_multiple_of(sys_info.AllocationGranularity);

        let mut stack = allocate_virtual_memory(
            maximum_stack_size as _,
            PAGE_READWRITE,
            process_handle,
            ptr::null_mut(),
            MEM_RESERVE,
        )?;

        (*initial_teb).OldInitialTeb.OldStackBase = ptr::null_mut();
        (*initial_teb).OldInitialTeb.OldStackLimit = ptr::null_mut();
        (*initial_teb).StackAllocationBase = stack;
        (*initial_teb).StackBase = stack.add(maximum_stack_size as _);

        let mut guard_page = false;

        stack = stack.add((maximum_stack_size - committed_stack_size) as _);
        if maximum_stack_size > committed_stack_size {
            stack = stack.sub(sys_info.PageSize as _);
            committed_stack_size += sys_info.PageSize;
            guard_page = true;
        }

        stack = allocate_virtual_memory(
            committed_stack_size as _,
            PAGE_READWRITE,
            process_handle,
            stack,
            MEM_COMMIT,
        )?;

        (*initial_teb).StackLimit = stack;

        //
        // if we have space, create a guard page.
        //

        if guard_page {
            let region_size = sys_info.PageSize;
            let protect = PAGE_READWRITE | PAGE_GUARD;

            protect_virtual_memory(stack, region_size as _, protect, process_handle)?;

            (*initial_teb).StackLimit = (*initial_teb).StackLimit.add(region_size as _);
        }

        Ok(())
    }
}

pub fn create_thread(process_handle: HANDLE, start_address: PVOID, arg: Option<PVOID>) -> NtResult<UniqueHandle> {
    unsafe {
        let thread_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status = match api_ctx::sys_api_dispatch().create_thread {
            CreateThread::NtCreateThread => {
                if arg.is_some() {
                    return Err(NTSTATUS(ntstatus::STATUS_NOT_IMPLEMENTED).into());
                }

                let client_id = allocate_virtual_memory(
                    size_of::<ntdef::CLIENT_ID>(),
                    PAGE_READWRITE,
                    process_handle,
                    ptr::null_mut(),
                    MEM_COMMIT | MEM_RESERVE,
                )? as ntdef::PCLIENT_ID;
                let initial_teb = allocate_virtual_memory(
                    size_of::<ntpsapi::INITIAL_TEB>(),
                    PAGE_READWRITE,
                    process_handle,
                    ptr::null_mut(),
                    MEM_COMMIT | MEM_RESERVE,
                )? as ntpsapi::PINITIAL_TEB;
                let context = allocate_virtual_memory(
                    size_of::<CONTEXT>(),
                    PAGE_READWRITE,
                    process_handle,
                    ptr::null_mut(),
                    MEM_COMMIT | MEM_RESERVE,
                )? as winbase::PCONTEXT;

                create_thread_stack(process_handle, initial_teb)?;

                api_ctx::ntdll().RtlInitializeContext.unwrap()(
                    process_handle,
                    context,
                    ptr::null_mut(),
                    start_address as _,
                    (*initial_teb).StackBase,
                );

                let nt_create_thread = require_sys_api(api_ctx::ntdll().NtCreateThread, "NtCreateThread")?;
                NTSTATUS(nt_create_thread(
                    addr_of!(thread_handle) as _,
                    THREAD_ALL_ACCESS,
                    addr_of!(object_attributes) as _,
                    process_handle,
                    client_id as _,
                    context as _,
                    initial_teb as _,
                    false as _,
                ))
            }
            CreateThread::NtCreateThreadEx => {
                let arg = arg.unwrap_or(ptr::null_mut());

                let nt_create_thread_ex = require_sys_api(api_ctx::ntdll().NtCreateThreadEx, "NtCreateThreadEx")?;
                NTSTATUS(nt_create_thread_ex(
                    addr_of!(thread_handle) as _,
                    THREAD_ALL_ACCESS,
                    addr_of!(object_attributes) as _,
                    process_handle,
                    start_address,
                    arg,
                    0,
                    0,
                    0,
                    0,
                    ptr::null_mut(),
                ))
            }
        };

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_ACCESS_DENIED {
                log::warn!("the target process probably has a 'ControlFlowGuard' protection");
            }

            Err(status.into())
        } else {
            Ok(wrap_handle(thread_handle))
        }
    }
}

pub fn suspend_thread(thread_handle: HANDLE) -> NtResult<()> {
    suspend_thread_by_nt_suspend_thread(thread_handle)
}

pub fn suspend_thread_by_nt_suspend_thread(thread_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_suspend_thread = require_sys_api(api_ctx::ntdll().NtSuspendThread, "NtSuspendThread")?;
        let status = NTSTATUS(nt_suspend_thread(thread_handle, ptr::null_mut()));
        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn resume_thread(thread_handle: HANDLE) -> NtResult<()> {
    resume_thread_by_nt_resume_thread(thread_handle)
}

pub fn resume_thread_by_nt_resume_thread(thread_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_resume_thread = require_sys_api(api_ctx::ntdll().NtResumeThread, "NtResumeThread")?;
        let status = NTSTATUS(nt_resume_thread(thread_handle, ptr::null_mut()));
        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn suspend_thread_by_state_change(thread_handle: HANDLE) -> NtResult<()> {
    change_thread_state(thread_handle, ntpsapi::THREAD_STATE_CHANGE_TYPE::ThreadStateChangeSuspend)
}

pub fn resume_thread_by_state_change(thread_handle: HANDLE) -> NtResult<()> {
    change_thread_state(thread_handle, ntpsapi::THREAD_STATE_CHANGE_TYPE::ThreadStateChangeResume)
}

fn change_thread_state(thread_handle: HANDLE, state_change_type: ntpsapi::THREAD_STATE_CHANGE_TYPE) -> NtResult<()> {
    unsafe {
        let state_change_handle: HANDLE = ptr::null_mut();
        let nt_create_thread_state_change = require_sys_api(api_ctx::ntdll().NtCreateThreadStateChange, "NtCreateThreadStateChange")?;
        let status = NTSTATUS(nt_create_thread_state_change(
            addr_of!(state_change_handle) as _,
            ntpsapi::STATECHANGE_SET_ATTRIBUTES,
            ptr::null_mut(),
            thread_handle,
            0,
        ));

        if !status.is_ok() {
            return Err(status.into());
        }

        let state_change_handle = wrap_handle(state_change_handle);
        let nt_change_thread_state = require_sys_api(api_ctx::ntdll().NtChangeThreadState, "NtChangeThreadState")?;
        let status = NTSTATUS(nt_change_thread_state(
            *state_change_handle,
            thread_handle,
            state_change_type,
            ptr::null_mut(),
            0,
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn get_thread_basic_info(thread_handle: HANDLE) -> NtResult<ntpsapi::THREAD_BASIC_INFORMATION> {
    unsafe {
        let basic_info = ntpsapi::THREAD_BASIC_INFORMATION::default();

        let nt_query_information_thread = require_sys_api(api_ctx::ntdll().NtQueryInformationThread, "NtQueryInformationThread")?;
        let status = NTSTATUS(nt_query_information_thread(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadBasicInformation,
            addr_of!(basic_info) as _,
            size_of::<ntpsapi::THREAD_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(basic_info) }
    }
}

pub fn get_thread_context(thread_handle: HANDLE) -> NtResult<CONTEXT> {
    unsafe {
        let mut context = AlignedContext::default();
        context.ctx.ContextFlags = winbase::CONTEXT_FULL;

        let nt_get_context_thread = require_sys_api(api_ctx::ntdll().NtGetContextThread, "NtGetContextThread")?;
        let status = NTSTATUS(nt_get_context_thread(thread_handle, addr_of!(context) as _));

        if !status.is_ok() { Err(status.into()) } else { Ok(context.ctx) }
    }
}

pub fn get_thread_wow64_context(thread_handle: HANDLE) -> NtResult<WOW64_CONTEXT> {
    unsafe {
        let context = AlignedWow64Context::default();

        let nt_query_information_thread = require_sys_api(api_ctx::ntdll().NtQueryInformationThread, "NtQueryInformationThread")?;
        let status = NTSTATUS(nt_query_information_thread(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            addr_of!(context) as _,
            size_of::<AlignedWow64Context>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(context.ctx) }
    }
}

pub fn set_thread_context(thread_handle: HANDLE, ctx: &CONTEXT) -> NtResult<()> {
    unsafe {
        let context = AlignedContext { ctx: *ctx };

        let nt_set_context_thread = require_sys_api(api_ctx::ntdll().NtSetContextThread, "NtSetContextThread")?;
        let status = NTSTATUS(nt_set_context_thread(thread_handle, addr_of!(context) as _));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn set_thread_wow64_context(thread_handle: HANDLE, ctx: &WOW64_CONTEXT) -> NtResult<()> {
    unsafe {
        let context = AlignedWow64Context { ctx: *ctx };

        let nt_set_information_thread = require_sys_api(api_ctx::ntdll().NtSetInformationThread, "NtSetInformationThread")?;
        let status = NTSTATUS(nt_set_information_thread(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            addr_of!(context) as _,
            size_of::<AlignedWow64Context>() as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn allocate_virtual_memory(
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
    allocation_type: ULONG,
) -> NtResult<PVOID> {
    unsafe {
        let mut base_address = base_address;
        let mut region_size = size;

        let status = match api_ctx::sys_api_dispatch().allocate_virtual_memory {
            AllocateVirtualMemory::NtAllocateVirtualMemory => {
                let nt_allocate_virtual_memory = require_sys_api(api_ctx::ntdll().NtAllocateVirtualMemory, "NtAllocateVirtualMemory")?;
                NTSTATUS(nt_allocate_virtual_memory(
                    process_handle,
                    addr_of_mut!(base_address) as _,
                    0,
                    addr_of_mut!(region_size) as _,
                    allocation_type,
                    protect,
                ))
            }
            AllocateVirtualMemory::NtAllocateVirtualMemoryEx => {
                let nt_allocate_virtual_memory_ex = require_sys_api(api_ctx::ntdll().NtAllocateVirtualMemoryEx, "NtAllocateVirtualMemoryEx")?;
                NTSTATUS(nt_allocate_virtual_memory_ex(
                    process_handle,
                    addr_of_mut!(base_address) as _,
                    addr_of_mut!(region_size) as _,
                    allocation_type,
                    protect,
                    ptr::null_mut(),
                    0,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(base_address) }
    }
}

pub fn create_section(size: usize) -> NtResult<UniqueHandle> {
    unsafe {
        let section_handle: HANDLE = ptr::null_mut();

        let maximum_size = ntwin::LARGE_INTEGER::from(size as i64);

        let status = match api_ctx::sys_api_dispatch().create_section {
            CreateSection::NtCreateSection => {
                let nt_create_section = require_sys_api(api_ctx::ntdll().NtCreateSection, "NtCreateSection")?;
                NTSTATUS(nt_create_section(
                    addr_of!(section_handle) as _,
                    SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                    ptr::null_mut(),
                    addr_of!(maximum_size) as _,
                    PAGE_EXECUTE_READWRITE,
                    SEC_COMMIT,
                    ptr::null_mut(),
                ))
            }
            CreateSection::NtCreateSectionEx => {
                let nt_create_section_ex = require_sys_api(api_ctx::ntdll().NtCreateSectionEx, "NtCreateSectionEx")?;
                NTSTATUS(nt_create_section_ex(
                    addr_of!(section_handle) as _,
                    SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                    ptr::null_mut(),
                    addr_of!(maximum_size) as _,
                    PAGE_EXECUTE_READWRITE,
                    SEC_COMMIT,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(section_handle)) }
    }
}

pub fn create_file_section(
    file_handle: HANDLE,
    access_mask: u32,
    protection: SECTION_FLAGS,
    as_image: bool,
    size: Option<usize>,
) -> NtResult<UniqueHandle> {
    unsafe {
        let section_handle: HANDLE = ptr::null_mut();

        let mut maximum_size = ntwin::LARGE_INTEGER::default();
        if let Some(size) = size {
            *maximum_size.QuadPart.as_mut() = size as i64;
        }

        let status = match api_ctx::sys_api_dispatch().create_section {
            CreateSection::NtCreateSection => {
                let nt_create_section = require_sys_api(api_ctx::ntdll().NtCreateSection, "NtCreateSection")?;
                NTSTATUS(nt_create_section(
                    addr_of!(section_handle) as _,
                    access_mask,
                    ptr::null_mut(),
                    addr_of!(maximum_size) as _,
                    protection,
                    if as_image { SEC_IMAGE } else { SEC_COMMIT },
                    file_handle,
                ))
            }
            CreateSection::NtCreateSectionEx => {
                let nt_create_section_ex = require_sys_api(api_ctx::ntdll().NtCreateSectionEx, "NtCreateSectionEx")?;
                NTSTATUS(nt_create_section_ex(
                    addr_of!(section_handle) as _,
                    access_mask,
                    ptr::null_mut(),
                    addr_of!(maximum_size) as _,
                    protection,
                    if as_image { SEC_IMAGE } else { SEC_COMMIT },
                    file_handle,
                    ptr::null_mut(),
                    0,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(section_handle)) }
    }
}

pub fn map_view_of_section(
    section_handle: HANDLE,
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
) -> NtResult<PVOID> {
    unsafe {
        let status = match api_ctx::sys_api_dispatch().map_view_of_section {
            MapViewOfSection::NtMapViewOfSection => {
                let nt_map_view_of_section = require_sys_api(api_ctx::ntdll().NtMapViewOfSection, "NtMapViewOfSection")?;
                NTSTATUS(nt_map_view_of_section(
                    section_handle,
                    process_handle,
                    addr_of!(base_address) as _,
                    0,
                    0,
                    ptr::null_mut(),
                    addr_of!(size) as _,
                    ntmmapi::SECTION_INHERIT::ViewUnmap,
                    0,
                    protect,
                ))
            }
            MapViewOfSection::NtMapViewOfSectionEx => {
                let nt_map_view_of_section_ex = require_sys_api(api_ctx::ntdll().NtMapViewOfSectionEx, "NtMapViewOfSectionEx")?;
                NTSTATUS(nt_map_view_of_section_ex(
                    section_handle,
                    process_handle,
                    addr_of!(base_address) as _,
                    ptr::null_mut(),
                    addr_of!(size) as _,
                    0,
                    protect,
                    ptr::null_mut(),
                    0,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(base_address) }
    }
}

pub fn unmap_view_of_section(base_address: PVOID, process_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let status = match api_ctx::sys_api_dispatch().unmap_view_of_section {
            UnmapViewOfSection::NtUnmapViewOfSection => {
                let nt_unmap_view_of_section = require_sys_api(api_ctx::ntdll().NtUnmapViewOfSection, "NtUnmapViewOfSection")?;
                NTSTATUS(nt_unmap_view_of_section(process_handle, base_address))
            }
            UnmapViewOfSection::NtUnmapViewOfSectionEx => {
                let nt_unmap_view_of_section_ex = require_sys_api(api_ctx::ntdll().NtUnmapViewOfSectionEx, "NtUnmapViewOfSectionEx")?;
                NTSTATUS(nt_unmap_view_of_section_ex(process_handle, base_address, 0))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn protect_virtual_memory(base_address: PVOID, size: usize, protect: PAGE_PROTECTION_FLAGS, process_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let new_protect = protect;

        let nt_protect_virtual_memory = require_sys_api(api_ctx::ntdll().NtProtectVirtualMemory, "NtProtectVirtualMemory")?;
        let status = NTSTATUS(nt_protect_virtual_memory(
            process_handle,
            addr_of!(base_address) as _,
            addr_of!(size) as _,
            protect,
            addr_of!(new_protect) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn flush_instruction_cache(process_handle: HANDLE, base_address: PVOID, length: usize) -> NtResult<()> {
    unsafe {
        let nt_flush_instruction_cache = require_sys_api(api_ctx::ntdll().NtFlushInstructionCache, "NtFlushInstructionCache")?;
        let status = NTSTATUS(nt_flush_instruction_cache(process_handle, base_address, length));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn query_virtual_memory(process_handle: HANDLE, base_address: PVOID) -> NtResult<MemoryRegion> {
    unsafe {
        let mut basic_info = MEMORY_BASIC_INFORMATION::default();
        let mut return_length: usize = 0;

        let nt_query_virtual_memory = require_sys_api(api_ctx::ntdll().NtQueryVirtualMemory, "NtQueryVirtualMemory")?;
        let status = NTSTATUS(nt_query_virtual_memory(
            process_handle,
            base_address,
            ntmmapi::MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
            addr_of_mut!(basic_info) as _,
            size_of::<MEMORY_BASIC_INFORMATION>(),
            addr_of_mut!(return_length) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(basic_info.into()) }
    }
}

pub fn query_virtual_memory_mapped_path(process_handle: HANDLE, base_address: PVOID) -> NtResult<Option<String>> {
    unsafe {
        let mut buffer = vec![0u8; 0x10000];
        let mut return_length: usize = 0;

        let nt_query_virtual_memory = require_sys_api(api_ctx::ntdll().NtQueryVirtualMemory, "NtQueryVirtualMemory")?;
        let status = NTSTATUS(nt_query_virtual_memory(
            process_handle,
            base_address,
            ntmmapi::MEMORY_INFORMATION_CLASS::MemoryMappedFilenameInformation,
            buffer.as_mut_ptr() as _,
            buffer.len(),
            addr_of_mut!(return_length) as _,
        ));

        if status.0 == ntstatus::STATUS_OBJECT_NAME_NOT_FOUND
            || status.0 == ntstatus::STATUS_NOT_MAPPED_VIEW
            || status.0 == ntstatus::STATUS_NOT_MAPPED_DATA
            || status.0 == ntstatus::STATUS_ACCESS_DENIED
            || status.0 == ntstatus::STATUS_INVALID_ADDRESS
        {
            return Ok(None);
        }

        if !status.is_ok() {
            return Err(status.into());
        }

        Ok(unicode_string_buffer_to_u16cstring(&buffer)
            .and_then(|name| name.to_string().ok()))
    }
}

pub fn enumerate_memory_regions(process_handle: HANDLE) -> NtResult<Vec<MemoryRegion>> {
    let mut regions = Vec::new();
    let mut address = 0usize;

    for _ in 0..MAX_MEMORY_REGIONS {
        let mut region = match query_virtual_memory(process_handle, address as _) {
            Ok(region) => region,
            Err(error) if is_memory_query_end(error) => return Ok(regions),
            Err(error) => return Err(error.with_operation("NtQueryVirtualMemory")),
        };
        region.mapped_path = query_virtual_memory_mapped_path(process_handle, region.base_address as _)
            .unwrap_or(None);

        let base_address = region.base_address as usize;
        let Some(next_address) = base_address.checked_add(region.region_size) else {
            regions.push(region);
            return Ok(regions);
        };

        if next_address <= address || region.region_size == 0 {
            regions.push(region);
            return Ok(regions);
        }

        regions.push(region);
        address = next_address;
    }

    Ok(regions)
}

pub fn system_basic_information() -> NtResult<ntexapi::SYSTEM_BASIC_INFORMATION> {
    unsafe {
        let mut sys_info = ntexapi::SYSTEM_BASIC_INFORMATION { ..Default::default() };

        let nt_query_system_information = require_sys_api(api_ctx::ntdll().NtQuerySystemInformation, "NtQuerySystemInformation")?;
        let status = NTSTATUS(nt_query_system_information(
            ntexapi::SYSTEM_INFORMATION_CLASS::SystemBasicInformation,
            addr_of_mut!(sys_info) as _,
            size_of::<ntexapi::SYSTEM_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ));

        status
            .is_ok()
            .then_some(sys_info)
            .ok_or_else(|| NtStatusError::new("NtQuerySystemInformation", status))
    }
}

pub fn system_page_size() -> NtResult<usize> {
    Ok(system_basic_information()?.PageSize as usize)
}

pub fn query_working_set_pages(process_handle: HANDLE, addresses: &[u64]) -> NtResult<Vec<WorkingSetPage>> {
    if addresses.is_empty() {
        return Ok(Vec::new());
    }

    let buffer_size = addresses
        .len()
        .checked_mul(size_of::<ntmmapi::MEMORY_WORKING_SET_EX_INFORMATION>())
        .ok_or_else(|| NtStatusError::new("NtQueryVirtualMemory", NTSTATUS(ntstatus::STATUS_INTEGER_OVERFLOW)))?;

    let mut entries = addresses
        .iter()
        .map(|address| ntmmapi::MEMORY_WORKING_SET_EX_INFORMATION {
            VirtualAddress: *address as usize as _,
            VirtualAttributes: Default::default(),
        })
        .collect::<Vec<_>>();

    unsafe {
        let mut return_length: usize = 0;
        let nt_query_virtual_memory = require_sys_api(api_ctx::ntdll().NtQueryVirtualMemory, "NtQueryVirtualMemory")?;
        let status = NTSTATUS(nt_query_virtual_memory(
            process_handle,
            ptr::null_mut(),
            ntmmapi::MEMORY_INFORMATION_CLASS::MemoryWorkingSetExInformation,
            entries.as_mut_ptr() as _,
            buffer_size,
            addr_of_mut!(return_length) as _,
        ));

        if !status.is_ok() { return Err(NtStatusError::new("NtQueryVirtualMemory", status)); }
    }

    let pages = entries
        .into_iter()
        .zip(addresses.iter().copied())
        .map(|(entry, address)| WorkingSetPage {
            address,
            flags: unsafe { *entry.VirtualAttributes.Flags.as_ref() },
        })
        .collect();

    Ok(pages)
}

pub fn query_working_set_region(process_handle: HANDLE, region: &MemoryRegion) -> NtResult<WorkingSetRegionSummary> {
    let page_size = system_page_size()?;
    let queried_pages = region.is_committed()
        .then_some(page_count(region.region_size, page_size))
        .unwrap_or(0);
    let mut summary = WorkingSetRegionSummary::new(region.clone(), page_size, queried_pages);

    if !region.is_committed() || region.region_size == 0 {
        return Ok(summary);
    }

    let mut offset = 0usize;
    while offset < region.region_size {
        let remaining_pages = page_count(region.region_size - offset, page_size);
        let chunk_pages = remaining_pages.min(WORKING_SET_QUERY_CHUNK_PAGES);
        let addresses = (0..chunk_pages)
            .filter_map(|page| {
                let page_offset = offset.checked_add(page.checked_mul(page_size)?)?;
                Some(region.base_address.saturating_add(page_offset as u64))
            })
            .collect::<Vec<_>>();

        for page in query_working_set_pages(process_handle, &addresses)? {
            summary.push_page(page);
        }

        let chunk_size = chunk_pages
            .checked_mul(page_size)
            .ok_or_else(|| NtStatusError::new("NtQueryVirtualMemory", NTSTATUS(ntstatus::STATUS_INTEGER_OVERFLOW)))?;
        offset = offset.saturating_add(chunk_size);
    }

    Ok(summary)
}

pub fn query_working_set_regions(process_handle: HANDLE, regions: &[MemoryRegion]) -> NtResult<Vec<WorkingSetRegionSummary>> {
    regions
        .iter()
        .map(|region| query_working_set_region(process_handle, region))
        .collect()
}

pub fn write_virtual_memory<T>(buffer: T, base_address: PVOID, process_handle: HANDLE) -> NtResult<()>
where
    T: AsRef<[u8]>,
{
    unsafe {
        let slice = buffer.as_ref();
        let data = slice.as_ptr() as PVOID;
        let size = slice.len();

        let number_of_bytes_written: usize = 0;

        let nt_write_virtual_memory = require_sys_api(api_ctx::ntdll().NtWriteVirtualMemory, "NtWriteVirtualMemory")?;
        let status = NTSTATUS(nt_write_virtual_memory(
            process_handle,
            base_address,
            data,
            size,
            addr_of!(number_of_bytes_written) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn read_virtual_memory<T>(mut buffer: T, base_address: PVOID, process_handle: HANDLE) -> NtResult<usize>
where
    T: AsMut<[u8]>,
{
    unsafe {
        let slice = buffer.as_mut();
        let data = slice.as_mut_ptr() as PVOID;
        let size = slice.len();

        let number_of_bytes_read: usize = 0;

        let status = match api_ctx::sys_api_dispatch().read_virtual_memory {
            ReadVirtualMemory::NtReadVirtualMemory => {
                let nt_read_virtual_memory = require_sys_api(api_ctx::ntdll().NtReadVirtualMemory, "NtReadVirtualMemory")?;
                NTSTATUS(nt_read_virtual_memory(
                    process_handle,
                    base_address,
                    data,
                    size,
                    addr_of!(number_of_bytes_read) as _,
                ))
            }
            ReadVirtualMemory::NtReadVirtualMemoryEx => {
                let nt_read_virtual_memory_ex = require_sys_api(api_ctx::ntdll().NtReadVirtualMemoryEx, "NtReadVirtualMemoryEx")?;
                NTSTATUS(nt_read_virtual_memory_ex(
                    process_handle,
                    base_address,
                    data,
                    size,
                    addr_of!(number_of_bytes_read) as _,
                    0, //
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(number_of_bytes_read) }
    }
}

pub fn create_transaction(path: &str) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let transaction_handle: HANDLE = ptr::null_mut();

        let nt_create_transaction = require_sys_api(api_ctx::ntdll().NtCreateTransaction, "NtCreateTransaction")?;
        let status = NTSTATUS(nt_create_transaction(
            addr_of!(transaction_handle) as _,
            winbase::TRANSACTION_ALL_ACCESS,
            addr_of!(object_attributes) as _,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(transaction_handle)) }
    }
}

pub fn rollback_transaction(transaction_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_rollback_transaction = require_sys_api(api_ctx::ntdll().NtRollbackTransaction, "NtRollbackTransaction")?;
        let status = NTSTATUS(nt_rollback_transaction(transaction_handle, true as _));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn set_transaction(transaction_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let res = api_ctx::ntdll().RtlSetCurrentTransaction.unwrap()(transaction_handle);

        if res == 0 { Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL).into()) } else { Ok(()) }
    }
}

pub fn queue_apc_thread(
    thread_handle: HANDLE,
    apc_routine: winbase::PPS_APC_ROUTINE,
    apc_argument1: PVOID,
    apc_argument2: PVOID,
    apc_argument3: PVOID,
) -> NtResult<()> {
    unsafe {
        let status = match api_ctx::sys_api_dispatch().queue_apc_thread {
            QueueApcThread::NtQueueApcThread => {
                let nt_queue_apc_thread = require_sys_api(api_ctx::ntdll().NtQueueApcThread, "NtQueueApcThread")?;
                NTSTATUS(nt_queue_apc_thread(
                    thread_handle,
                    apc_routine,
                    apc_argument1,
                    apc_argument2,
                    apc_argument3
                ))
            }
            QueueApcThread::NtQueueApcThreadEx => {
                let nt_queue_apc_thread_ex = require_sys_api(api_ctx::ntdll().NtQueueApcThreadEx, "NtQueueApcThreadEx")?;
                NTSTATUS(nt_queue_apc_thread_ex(
                    thread_handle,
                    ptr::null_mut(),
                    apc_routine,
                    apc_argument1,
                    apc_argument2,
                    apc_argument3
                ))
            }
            QueueApcThread::NtQueueApcThreadEx2 => {
                let nt_queue_apc_thread_ex2 = require_sys_api(api_ctx::ntdll().NtQueueApcThreadEx2, "NtQueueApcThreadEx2")?;
                NTSTATUS(nt_queue_apc_thread_ex2(
                    thread_handle,
                    ptr::null_mut(),
                    ntpsapi::QUEUE_USER_APC_FLAGS_NONE,
                    apc_routine,
                    apc_argument1,
                    apc_argument2,
                    apc_argument3
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn create_event() -> NtResult<UniqueHandle> {
    unsafe {
        let event_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let nt_create_event = require_sys_api(api_ctx::ntdll().NtCreateEvent, "NtCreateEvent")?;
        let status = NTSTATUS(nt_create_event(
            addr_of!(event_handle) as _,
            EVENT_ALL_ACCESS,
            addr_of!(object_attributes) as _,
            ntdef::EVENT_TYPE::NotificationEvent as _,
            false as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(event_handle)) }
    }
}

pub fn set_event(event_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let mut previous_state: winbase::LONG = 0;
        let nt_set_event = require_sys_api(api_ctx::ntdll().NtSetEvent, "NtSetEvent")?;
        let status = NTSTATUS(nt_set_event(event_handle, addr_of_mut!(previous_state) as _));
        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn set_timer2(timer_handle: HANDLE, due_time: i64) -> NtResult<()> {
    unsafe {
        let mut due_time = ntwin::LARGE_INTEGER::from(due_time);
        let mut parameters = ntexapi::T2_SET_PARAMETERS::default();

        let nt_set_timer2 = require_sys_api(api_ctx::ntdll().NtSetTimer2, "NtSetTimer2")?;
        let status = NTSTATUS(nt_set_timer2(
            timer_handle,
            addr_of_mut!(due_time) as _,
            ptr::null_mut(),
            addr_of_mut!(parameters) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn get_worker_factory_basic_info(worker_factory_handle: HANDLE) -> NtResult<ntexapi::WORKER_FACTORY_BASIC_INFORMATION> {
    unsafe {
        let mut worker_factory_info = ntexapi::WORKER_FACTORY_BASIC_INFORMATION::default();
        let nt_query_information_worker_factory = require_sys_api(
            api_ctx::ntdll().NtQueryInformationWorkerFactory,
            "NtQueryInformationWorkerFactory"
        )?;
        let status = NTSTATUS(nt_query_information_worker_factory(
            worker_factory_handle,
            ntexapi::WORKERFACTORYINFOCLASS::WorkerFactoryBasicInformation,
            addr_of_mut!(worker_factory_info) as _,
            size_of::<ntexapi::WORKER_FACTORY_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(worker_factory_info) }
    }
}

pub fn set_worker_factory_thread_minimum(worker_factory_handle: HANDLE, thread_minimum: u32) -> NtResult<()> {
    unsafe {
        let nt_set_information_worker_factory = require_sys_api(
            api_ctx::ntdll().NtSetInformationWorkerFactory,
            "NtSetInformationWorkerFactory"
        )?;
        let status = NTSTATUS(nt_set_information_worker_factory(
            worker_factory_handle,
            ntexapi::WORKERFACTORYINFOCLASS::WorkerFactoryThreadMinimum,
            addr_of!(thread_minimum) as _,
            size_of::<u32>() as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn set_io_completion(
    io_completion_handle: HANDLE,
    key_context: PVOID,
    apc_context: PVOID,
    io_status: windows_sys::Win32::Foundation::NTSTATUS,
    io_status_information: usize,
) -> NtResult<()> {
    unsafe {
        let nt_set_io_completion = require_sys_api(api_ctx::ntdll().NtSetIoCompletion, "NtSetIoCompletion")?;
        let status = NTSTATUS(nt_set_io_completion(
            io_completion_handle,
            key_context,
            apc_context,
            io_status,
            io_status_information,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn associate_wait_completion_packet(
    wait_completion_packet_handle: HANDLE,
    io_completion_handle: HANDLE,
    target_object_handle: HANDLE,
    key_context: PVOID,
    apc_context: PVOID,
    io_status: windows_sys::Win32::Foundation::NTSTATUS,
    io_status_information: usize,
) -> NtResult<bool> {
    unsafe {
        let mut already_signaled = false;
        let nt_associate_wait_completion_packet = require_sys_api(
            api_ctx::ntdll().NtAssociateWaitCompletionPacket,
            "NtAssociateWaitCompletionPacket"
        )?;
        let status = NTSTATUS(nt_associate_wait_completion_packet(
            wait_completion_packet_handle,
            io_completion_handle,
            target_object_handle,
            key_context,
            apc_context,
            io_status,
            io_status_information,
            addr_of_mut!(already_signaled) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(already_signaled) }
    }
}

pub fn set_file_completion_information(
    file_handle: HANDLE,
    io_completion_handle: HANDLE,
    completion_key: PVOID,
) -> NtResult<()> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_information = ntioapi::FILE_COMPLETION_INFORMATION {
            Port: io_completion_handle,
            Key: completion_key,
        };

        let nt_set_information_file = require_sys_api(api_ctx::ntdll().NtSetInformationFile, "NtSetInformationFile")?;
        let status = NTSTATUS(nt_set_information_file(
            file_handle,
            addr_of!(io_status_block) as _,
            addr_of!(file_information) as _,
            size_of::<ntioapi::FILE_COMPLETION_INFORMATION>() as _,
            ntioapi::FILE_INFORMATION_CLASS::FileReplaceCompletionInformation,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn create_alpc_port(name: Option<&str>, flags: u32, max_message_length: u32) -> NtResult<UniqueHandle> {
    unsafe {
        let mut port_handle: HANDLE = ptr::null_mut();
        let nt_name = name.map(|name| U16CString::from_str(name).unwrap());
        let nt_name = nt_name.as_ref().map(to_unicode_string);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: nt_name.as_ref().map_or(ptr::null_mut(), |name| addr_of!(*name) as _),
            Attributes: if nt_name.is_some() { ntdef::OBJ_CASE_INSENSITIVE } else { 0 },
            ..Default::default()
        };
        let mut port_attributes = ntlpcapi::ALPC_PORT_ATTRIBUTES {
            Flags: flags,
            MaxMessageLength: max_message_length as _,
            ..Default::default()
        };

        let nt_alpc_create_port = require_sys_api(api_ctx::ntdll().NtAlpcCreatePort, "NtAlpcCreatePort")?;
        let status = NTSTATUS(nt_alpc_create_port(
            addr_of_mut!(port_handle) as _,
            addr_of!(object_attributes) as _,
            addr_of_mut!(port_attributes) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(port_handle)) }
    }
}

pub fn set_alpc_completion_port(
    alpc_port_handle: HANDLE,
    io_completion_handle: HANDLE,
    completion_key: PVOID,
) -> NtResult<()> {
    unsafe {
        let mut completion_port = ntlpcapi::ALPC_PORT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: completion_key,
            CompletionPort: io_completion_handle,
        };

        let nt_alpc_set_information = require_sys_api(api_ctx::ntdll().NtAlpcSetInformation, "NtAlpcSetInformation")?;
        let status = NTSTATUS(nt_alpc_set_information(
            alpc_port_handle,
            ntlpcapi::ALPC_PORT_INFORMATION_CLASS::AlpcAssociateCompletionPortInformation,
            addr_of_mut!(completion_port) as _,
            size_of::<ntlpcapi::ALPC_PORT_ASSOCIATE_COMPLETION_PORT>() as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn connect_alpc_port(name: &str, message_size: usize, timeout: i64) -> NtResult<()> {
    unsafe {
        let nt_name = U16CString::from_str(name).unwrap();
        let nt_name = to_unicode_string(&nt_name);
        let mut client_port_handle: HANDLE = ptr::null_mut();
        let mut port_attributes = ntlpcapi::ALPC_PORT_ATTRIBUTES {
            MaxMessageLength: message_size as _,
            ..Default::default()
        };
        let mut connection_message = vec![0u8; message_size];
        let mut buffer_length = connection_message.len();
        let mut timeout = ntwin::LARGE_INTEGER::from(timeout as i64);

        let message = connection_message.as_mut_ptr() as *mut ntlpcapi::PORT_MESSAGE;
        let data_length = message_size.saturating_sub(size_of::<ntlpcapi::PORT_MESSAGE>()) as u32;
        *(*message).u1.Length.as_mut() = ((message_size as u32) << 16) | data_length;

        let nt_alpc_connect_port = require_sys_api(api_ctx::ntdll().NtAlpcConnectPort, "NtAlpcConnectPort")?;
        let status = NTSTATUS(nt_alpc_connect_port(
            addr_of_mut!(client_port_handle) as _,
            addr_of!(nt_name) as _,
            ptr::null_mut(),
            addr_of_mut!(port_attributes) as _,
            0,
            ptr::null_mut(),
            message,
            addr_of_mut!(buffer_length) as _,
            ptr::null_mut(),
            ptr::null_mut(),
            addr_of_mut!(timeout) as _,
        ));
        let _client_port_handle = (!client_port_handle.is_null()).then(|| wrap_handle(client_port_handle));

        if status.0 == ntstatus::STATUS_TIMEOUT {
            Ok(())
        } else if !status.is_ok() {
            Err(status.into())
        } else {
            Ok(())
        }
    }
}

pub fn create_job_object() -> NtResult<UniqueHandle> {
    unsafe {
        let mut job_handle: HANDLE = ptr::null_mut();
        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let nt_create_job_object = require_sys_api(api_ctx::ntdll().NtCreateJobObject, "NtCreateJobObject")?;
        let status = NTSTATUS(nt_create_job_object(
            addr_of_mut!(job_handle) as _,
            ntpsapi::JOB_OBJECT_ALL_ACCESS,
            addr_of!(object_attributes) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(job_handle)) }
    }
}

pub fn set_job_completion_port(
    job_handle: HANDLE,
    io_completion_handle: HANDLE,
    completion_key: PVOID,
) -> NtResult<()> {
    unsafe {
        let mut job_completion_port = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: completion_key,
            CompletionPort: io_completion_handle,
        };

        let nt_set_information_job_object = require_sys_api(api_ctx::ntdll().NtSetInformationJobObject, "NtSetInformationJobObject")?;
        let status = NTSTATUS(nt_set_information_job_object(
            job_handle,
            ntpsapi::JobObjectAssociateCompletionPortInformation as _,
            addr_of_mut!(job_completion_port) as _,
            size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn assign_process_to_job_object(job_handle: HANDLE, process_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let nt_assign_process_to_job_object = require_sys_api(api_ctx::ntdll().NtAssignProcessToJobObject, "NtAssignProcessToJobObject")?;
        let status = NTSTATUS(nt_assign_process_to_job_object(job_handle, process_handle));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn create_named_pipe(name: &str, sd: PVOID) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_name = format!("\\Device\\NamedPipe\\{name}");
        let nt_name = U16CString::from_str(nt_name).unwrap();
        let nt_name = to_unicode_string(&nt_name);

        let file_handle: HANDLE = ptr::null_mut();
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_name) as _,
            SecurityDescriptor: sd,
            ..Default::default()
        };

        let default_timeout = ntwin::LARGE_INTEGER::from(-1_200_000_000); // 120 seconds

        let nt_create_named_pipe_file = require_sys_api(api_ctx::ntdll().NtCreateNamedPipeFile, "NtCreateNamedPipeFile")?;
        let status = NTSTATUS(nt_create_named_pipe_file(
            addr_of!(file_handle) as _,
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ntioapi::FILE_CREATE,
            ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ntioapi::FILE_PIPE_BYTE_STREAM_TYPE,
            ntioapi::FILE_PIPE_BYTE_STREAM_MODE,
            ntioapi::FILE_PIPE_QUEUE_OPERATION,
            1,
            4096,
            4096,
            addr_of!(default_timeout) as _,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn open_named_pipe(name: &str) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_name = format!("\\Device\\NamedPipe\\{name}");
        let nt_name = U16CString::from_str(nt_name).unwrap();
        let nt_name = to_unicode_string(&nt_name);

        let file_handle: HANDLE = ptr::null_mut();
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_name) as _,
            ..Default::default()
        };

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of!(file_handle) as _,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            0,
            ntioapi::FILE_OPEN,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn open_file(path: &str) -> NtResult<UniqueHandle> {
    open_file_by_nt_create_file(
        path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT
    )
}

pub fn open_file_by_nt_open_file(
    path: &str,
    access_mask: u32,
    share_access: u32,
    open_options: u32,
) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_handle: HANDLE = ptr::null_mut();

        let nt_open_file = require_sys_api(api_ctx::ntdll().NtOpenFile, "NtOpenFile")?;
        let status = NTSTATUS(nt_open_file(
            addr_of!(file_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            share_access,
            open_options,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn open_file_by_nt_create_file(
    path: &str,
    access_mask: u32,
    share_access: u32,
    create_options: u32,
) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let mut file_handle: HANDLE = ptr::null_mut();

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of_mut!(file_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            ntioapi::FILE_OPEN,
            create_options,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn create_file_by_nt_create_file_with_options(
    path: &str,
    access_mask: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    allocation_size: Option<usize>,
) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let allocation_size = allocation_size.map(|size| ntwin::LARGE_INTEGER::from(size as i64));
        let allocation_size_ptr = allocation_size
            .as_ref()
            .map_or(ptr::null(), |allocation_size| addr_of!(*allocation_size)) as _;
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_handle: HANDLE = ptr::null_mut();

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of!(file_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            allocation_size_ptr,
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            create_disposition,
            create_options,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn delete_file(path: &str) -> NtResult<()> {
    delete_file_by_nt_delete_file(path)
}

pub fn delete_file_by_nt_delete_file(path: &str) -> NtResult<()> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let nt_delete_file = require_sys_api(api_ctx::ntdll().NtDeleteFile, "NtDeleteFile")?;
        let status = NTSTATUS(nt_delete_file(addr_of!(object_attributes) as _));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn delete_file_by_nt_open_file_delete_on_close(path: &str) -> NtResult<()> {
    let _file_handle = open_file_by_nt_open_file(
        path,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT | ntioapi::FILE_DELETE_ON_CLOSE
    )?;

    Ok(())
}

pub fn delete_file_by_nt_create_file_delete_on_close(path: &str) -> NtResult<()> {
    let _file_handle = open_file_by_nt_create_file(
        path,
        DELETE | SYNCHRONIZE,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT | ntioapi::FILE_DELETE_ON_CLOSE
    )?;

    Ok(())
}

pub fn delete_file_by_set_information_file(path: &str) -> NtResult<()> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_handle: HANDLE = ptr::null_mut();

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of!(file_handle) as _,
            DELETE | SYNCHRONIZE,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
            ntioapi::FILE_OPEN,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() {
            return Err(status.into());
        }

        let file_handle = wrap_handle(file_handle);
        set_file_delete_disposition(*file_handle)
    }
}

fn set_file_delete_disposition(file_handle: HANDLE) -> NtResult<()> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let nt_set_information_file = require_sys_api(api_ctx::ntdll().NtSetInformationFile, "NtSetInformationFile")?;

        let status = match api_ctx::sys_api_dispatch().set_information_delete {
            SetInformation_Delete::FileDispositionInformation => {
                let file_information = ntioapi::FILE_DISPOSITION_INFORMATION { DeleteFileW: 1 };
                NTSTATUS(nt_set_information_file(
                    file_handle,
                    addr_of!(io_status_block) as _,
                    addr_of!(file_information) as _,
                    size_of::<ntioapi::FILE_DISPOSITION_INFORMATION>() as _,
                    ntioapi::FILE_INFORMATION_CLASS::FileDispositionInformation,
                ))
            }
            SetInformation_Delete::FileDispositionInformationEx => {
                let file_information = winbase::FILE_DISPOSITION_INFORMATION_EX {
                    Flags: winbase::FILE_DISPOSITION_DELETE,
                };
                NTSTATUS(nt_set_information_file(
                    file_handle,
                    addr_of!(io_status_block) as _,
                    addr_of!(file_information) as _,
                    size_of::<winbase::FILE_DISPOSITION_INFORMATION_EX>() as _,
                    ntioapi::FILE_INFORMATION_CLASS::FileDispositionInformationEx,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn rename_file(path: &str, new_path: &str) -> NtResult<()> {
    rename_file_by_rename(path, new_path)
}

pub fn rename_file_by_rename(path: &str, new_path: &str) -> NtResult<()> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_handle: HANDLE = ptr::null_mut();

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of!(file_handle) as _,
            DELETE | SYNCHRONIZE,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
            ntioapi::FILE_OPEN,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() {
            return Err(status.into());
        }

        let file_handle = wrap_handle(file_handle);
        set_file_rename_information(*file_handle, new_path)
    }
}

pub fn rename_file_by_copy_delete(path: &str, new_path: &str) -> NtResult<()> {
    {
        let (_, _, src_data) = fs::map_file(path)?;
        let dst_file = create_file(new_path, FILE_GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, src_data.len())?;
        write_file(*dst_file, src_data.as_ptr() as _, src_data.len())?;
    }

    delete_file(path)
}

pub fn zero_file_by_open_file(path: &str, file_open: impl FnOnce(&str) -> NtResult<UniqueHandle>) -> NtResult<()> {
    let file_handle = file_open(path)?;
    let file_size = get_file_size(*file_handle)?;
    let zeroes = vec![0u8; 0x10000.min(file_size)];
    let mut bytes_left = file_size;

    while bytes_left > 0 {
        let write_size = zeroes.len().min(bytes_left);
        write_file(*file_handle, zeroes.as_ptr() as _, write_size)?;
        bytes_left -= write_size;
    }

    Ok(())
}

pub fn zero_file_by_file_mapping(path: &str) -> NtResult<()> {
    unsafe {
        let file_handle = open_file_by_nt_create_file(
            path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT
        )?;
        let file_size = get_file_size(*file_handle)?;

        if file_size == 0 {
            return Ok(());
        }

        let section_handle = create_file_section(
            *file_handle,
            SECTION_MAP_WRITE,
            PAGE_READWRITE,
            false,
            None
        )?;
        let file_data = map_view_of_section(
            *section_handle,
            file_size,
            PAGE_READWRITE,
            NT_CURRENT_PROCESS,
            ptr::null_mut()
        )?;

        ptr::write_bytes(file_data as *mut u8, 0, file_size);
        unmap_view_of_section(file_data, NT_CURRENT_PROCESS)
    }
}

fn set_file_rename_information(file_handle: HANDLE, new_path: &str) -> NtResult<()> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let nt_set_information_file = require_sys_api(api_ctx::ntdll().NtSetInformationFile, "NtSetInformationFile")?;
        let nt_new_path = format!("\\??\\{new_path}");
        let nt_new_path: Vec<u16> = nt_new_path.encode_utf16().collect();

        let status = match api_ctx::sys_api_dispatch().set_information_rename {
            SetInformation_Rename::FileRenameInformation => {
                let file_name_offset = offset_of!(ntioapi::FILE_RENAME_INFORMATION, FileName);
                let file_name_size = nt_new_path.len() * size_of::<u16>();
                let mut file_information = vec![0u8; file_name_offset + file_name_size];
                let file_information_ptr = file_information.as_mut_ptr() as *mut ntioapi::FILE_RENAME_INFORMATION;

                (*file_information_ptr).RootDirectory = ptr::null_mut();
                (*file_information_ptr).FileNameLength = file_name_size as _;
                ptr::copy_nonoverlapping(
                    nt_new_path.as_ptr(),
                    (*file_information_ptr).FileName.as_mut_ptr(),
                    nt_new_path.len()
                );

                NTSTATUS(nt_set_information_file(
                    file_handle,
                    addr_of!(io_status_block) as _,
                    file_information.as_mut_ptr() as _,
                    file_information.len() as _,
                    ntioapi::FILE_INFORMATION_CLASS::FileRenameInformation,
                ))
            }
            SetInformation_Rename::FileRenameInformationEx => {
                let file_name_offset = offset_of!(ntioapi::FILE_RENAME_INFORMATION_EX, FileName);
                let file_name_size = nt_new_path.len() * size_of::<u16>();
                let mut file_information = vec![0u8; file_name_offset + file_name_size];
                let file_information_ptr = file_information.as_mut_ptr() as *mut ntioapi::FILE_RENAME_INFORMATION_EX;

                (*file_information_ptr).Flags = 0;
                (*file_information_ptr).RootDirectory = ptr::null_mut();
                (*file_information_ptr).FileNameLength = file_name_size as _;
                ptr::copy_nonoverlapping(
                    nt_new_path.as_ptr(),
                    (*file_information_ptr).FileName.as_mut_ptr(),
                    nt_new_path.len()
                );

                NTSTATUS(nt_set_information_file(
                    file_handle,
                    addr_of!(io_status_block) as _,
                    file_information.as_mut_ptr() as _,
                    file_information.len() as _,
                    ntioapi::FILE_INFORMATION_CLASS::FileRenameInformationEx,
                ))
            }
        };

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn create_file(path: &str, access_mask: u32, share_access: u32, size: usize) -> NtResult<UniqueHandle> {
    unsafe {
        let nt_path = format!("\\??\\{path}");
        let nt_path = U16CString::from_str(nt_path).unwrap();
        let nt_path = to_unicode_string(&nt_path);

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: addr_of!(nt_path) as _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_handle: HANDLE = ptr::null_mut();

        let allocation_size = ntwin::LARGE_INTEGER::from(size as i64);

        let nt_create_file = require_sys_api(api_ctx::ntdll().NtCreateFile, "NtCreateFile")?;
        let status = NTSTATUS(nt_create_file(
            addr_of!(file_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
            addr_of!(allocation_size) as _,
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            ntioapi::FILE_OVERWRITE_IF,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(wrap_handle(file_handle)) }
    }
}

pub fn write_file(file_handle: HANDLE, data: PVOID, size: usize) -> NtResult<bool> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let nt_write_file = require_sys_api(api_ctx::ntdll().NtWriteFile, "NtWriteFile")?;
        let status = NTSTATUS(nt_write_file(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            addr_of!(io_status_block) as _,
            data,
            size as _,
            ptr::null_mut(),
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(io_status_block.Information == size) }
    }
}

pub fn write_file_at(file_handle: HANDLE, data: PVOID, size: usize, byte_offset: i64) -> NtResult<bool> {
    unsafe {
        let nt_write_file = require_sys_api(api_ctx::ntdll().NtWriteFile, "NtWriteFile")?;
        let io_status_block = Box::into_raw(Box::new(ntioapi::IO_STATUS_BLOCK::default()));
        let byte_offset = Box::into_raw(Box::new(ntwin::LARGE_INTEGER::from(byte_offset as i64)));

        let status = NTSTATUS(nt_write_file(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            io_status_block as _,
            data,
            size as _,
            byte_offset as _,
            ptr::null_mut(),
        ));

        if status.0 == ntstatus::STATUS_PENDING {
            return Ok(false);
        }

        let information = (*io_status_block).Information;
        drop(Box::from_raw(io_status_block));
        drop(Box::from_raw(byte_offset));

        if !status.is_ok() { Err(status.into()) } else { Ok(information == size) }
    }
}

pub fn read_file(file_handle: HANDLE, data: PVOID, size: usize) -> NtResult<bool> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let nt_read_file = require_sys_api(api_ctx::ntdll().NtReadFile, "NtReadFile")?;
        let status = NTSTATUS(nt_read_file(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            addr_of!(io_status_block) as _,
            data,
            size as _,
            ptr::null_mut(),
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(io_status_block.Information == size) }
    }
}

pub fn get_file_size(file_handle: HANDLE) -> NtResult<usize> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_information = ntioapi::FILE_STANDARD_INFORMATION::default();

        let nt_query_information_file = require_sys_api(api_ctx::ntdll().NtQueryInformationFile, "NtQueryInformationFile")?;
        let status = NTSTATUS(nt_query_information_file(
            file_handle,
            addr_of!(io_status_block) as _,
            addr_of!(file_information) as _,
            size_of::<ntioapi::FILE_STANDARD_INFORMATION>() as _,
            ntioapi::FILE_INFORMATION_CLASS::FileStandardInformation,
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(*file_information.EndOfFile.QuadPart.as_ref() as _) }
    }
}

pub fn adjust_privilege(privilege: u32) -> NtResult<()> {
    unsafe {
        let was_enabled: bool = false;

        let status = NTSTATUS(api_ctx::ntdll().RtlAdjustPrivilege.unwrap()(privilege, true as _, false as _, addr_of!(was_enabled) as _));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn load_library_copy(module_path: &str) -> NtResult<HMODULE> {
    unsafe {
        let temp_folder = PathBuf::from(to_u16cstring(&(*(*peb()).ProcessParameters).CurrentDirectory.DosPath).to_string_lossy());

        let module_path_buf = PathBuf::from(&module_path);
        let module_name = module_path_buf.file_name().unwrap();
        let temp_module_path = temp_folder.join(module_name).to_string_lossy().into_owned();

        {
            let (_, _, src_data) = fs::map_file(&module_path)?;

            let file_mode = fs::FsFileMode::ReadWrite;
            let module_copy_handle = create_file(
                &temp_module_path,
                file_mode.access_rights(),
                file_mode.share_mode(),
                src_data.len()
            )?;

            let module_copy_section_handle = create_file_section(
                *module_copy_handle,
                SECTION_ALL_ACCESS,
                PAGE_READWRITE,
                false,
                Some(src_data.len())
            )?;

            let module_copy_data = map_view_of_section(
                *module_copy_section_handle,
                src_data.len(),
                PAGE_READWRITE,
                NT_CURRENT_PROCESS,
                ptr::null_mut(),
            )?;

            let dst_data = slice::from_raw_parts_mut(module_copy_data as *mut u8, src_data.len());
            dst_data.copy_from_slice(src_data);

            unmap_view_of_section(src_data.as_ptr() as _, NT_CURRENT_PROCESS)?;
            unmap_view_of_section(dst_data.as_ptr() as _, NT_CURRENT_PROCESS)?;
        }

        let hr = HMODULE(LoadLibraryA(CString::new(temp_module_path).unwrap().into_raw() as _));
        if hr.is_invalid() { Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL).into()) } else { Ok(hr) }
    }
}

pub fn dump_live_system(file_handle: HANDLE) -> NtResult<()> {
    unsafe {
        if adjust_privilege(ntseapi::SE_DEBUG_PRIVILEGE).is_err() {
            return Err(NTSTATUS(ntstatus::STATUS_PRIVILEGE_NOT_HELD).into());
        }

        let mut live_dump_control = ntexapi::SYSDBG_LIVEDUMP_CONTROL::default();
        live_dump_control.Version = 1;
        live_dump_control.BugCheckCode = 0x161;
        live_dump_control.DumpFileHandle = file_handle;
        // live_dump_control.Flags.CompressMemoryPagesData = 1;
        // live_dump_control.Flags.IncludeUserSpaceMemoryPages = 1;
        *live_dump_control.Flags.AsUlong.as_mut() = 6;

        let nt_system_debug_control = require_sys_api(api_ctx::ntdll().NtSystemDebugControl, "NtSystemDebugControl")?;
        let status = NTSTATUS(nt_system_debug_control(
            ntexapi::SYSDBG_COMMAND::SysDbgGetLiveKernelDump,
            addr_of!(live_dump_control) as _,
            offset_of!(ntexapi::SYSDBG_LIVEDUMP_CONTROL, SelectiveControl) as _,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        ));

        if !status.is_ok() { Err(status.into()) } else { Ok(()) }
    }
}

pub fn get_process_handles(pid: u32) -> NtResult<Vec<HANDLE>> {
    unsafe {
        let data_size: ULONG = 0;
        let mut data = Vec::<u8>::new();
        let nt_query_system_information = require_sys_api(api_ctx::ntdll().NtQuerySystemInformation, "NtQuerySystemInformation")?;

        loop {
            let status = NTSTATUS(nt_query_system_information(
                ntexapi::SYSTEM_INFORMATION_CLASS::SystemHandleInformation,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of!(data_size) as _,
            ));

            if status.is_ok() {
                break;
            }

            if status.0 == ntstatus::STATUS_INFO_LENGTH_MISMATCH {
                data.resize(data_size as usize, 0);
                continue;
            }

            return Err(status.into());
        }

        let mut res = Vec::<HANDLE>::new();

        let handle_info: ntexapi::PSYSTEM_HANDLE_INFORMATION = data.as_ptr() as _;
        for i in 0..(*handle_info).NumberOfHandles {
            let handle = (*handle_info).Handles.as_ptr().wrapping_add(i as usize);

            if (*handle).UniqueProcessId as u32 == pid {
                res.push((*handle).HandleValue as _);
            }
        }

        Ok(res)
    }
}

pub fn get_process_handle_snapshot(process_handle: HANDLE) -> NtResult<Vec<HANDLE>> {
    unsafe {
        let mut data_size: ULONG = 0x1000;
        let mut data = vec![0u8; data_size as usize];
        let nt_query_information_process = require_sys_api(api_ctx::ntdll().NtQueryInformationProcess, "NtQueryInformationProcess")?;

        loop {
            let status = NTSTATUS(nt_query_information_process(
                process_handle,
                ntpsapi::PROCESSINFOCLASS::ProcessHandleInformation,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of_mut!(data_size) as _,
            ));

            if status.is_ok() {
                break;
            }

            if status.0 == ntstatus::STATUS_INFO_LENGTH_MISMATCH || status.0 == ntstatus::STATUS_BUFFER_OVERFLOW {
                data.resize(data_size as usize + size_of::<ntpsapi::PROCESS_HANDLE_TABLE_ENTRY_INFO>() * 16, 0);
                continue;
            }

            return Err(status.into());
        }

        let snapshot = data.as_ptr() as ntpsapi::PPROCESS_HANDLE_SNAPSHOT_INFORMATION;
        let handles = slice::from_raw_parts((*snapshot).Handles.as_ptr(), (*snapshot).NumberOfHandles as usize);
        let handle_values = handles.iter()
            .map(|handle| handle.HandleValue)
            .collect();

        Ok(handle_values)
    }
}

pub fn get_handle_type(handle: HANDLE) -> NtResult<String> {
    unsafe {
        let mut data_size: ULONG = 0;
        let mut data = Vec::<u8>::new();
        let nt_query_object = require_sys_api(api_ctx::ntdll().NtQueryObject, "NtQueryObject")?;

        loop {
            let status = NTSTATUS(nt_query_object(
                handle,
                ntobapi::OBJECT_INFORMATION_CLASS::ObjectTypeInformation,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of_mut!(data_size) as _,
            ));

            if status.is_ok() {
                break;
            }

            if status.0 == ntstatus::STATUS_INFO_LENGTH_MISMATCH {
                data.resize(data_size as usize, 0);
                continue;
            }

            return Err(status.into());
        }

        let info = data.as_ptr() as ntobapi::POBJECT_TYPE_INFORMATION;
        let type_name = (*info).TypeName.to_u16cstring();

        Ok(type_name.to_string_lossy().to_string())
    }
}

pub fn get_handle_info(handle: HANDLE) -> NtResult<(String, String)> {
    unsafe {
        let data_size: ULONG = 0;
        let mut data = Vec::<u8>::new();
        let nt_query_object = require_sys_api(api_ctx::ntdll().NtQueryObject, "NtQueryObject")?;

        loop {
            let status = NTSTATUS(nt_query_object(
                handle,
                ntobapi::OBJECT_INFORMATION_CLASS::ObjectNameInformation,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of!(data_size) as _,
            ));

            if status.is_ok() {
                break;
            }

            if status.0 == ntstatus::STATUS_INFO_LENGTH_MISMATCH {
                data.resize(data_size as usize, 0);
                continue;
            }

            return Err(status.into());
        }

        let info = data.as_ptr() as ntobapi::POBJECT_NAME_INFORMATION;
        let name = (*info).Name.to_u16cstring();

        loop {
            let status = NTSTATUS(nt_query_object(
                handle,
                ntobapi::OBJECT_INFORMATION_CLASS::ObjectTypeInformation,
                data.as_mut_ptr() as _,
                data.len() as _,
                addr_of!(data_size) as _,
            ));

            if status.is_ok() {
                break;
            }

            if status.0 == ntstatus::STATUS_INFO_LENGTH_MISMATCH {
                data.resize(data_size as usize, 0);
                continue;
            }

            return Err(status.into());
        }

        let info = data.as_ptr() as ntobapi::POBJECT_TYPE_INFORMATION;
        let type_name = (*info).TypeName.to_u16cstring();

        Ok((name.to_string_lossy().to_string(), type_name.to_string_lossy().to_string()))
    }
}

pub fn process_open_alertable_thread(process_handle: HANDLE) -> NtResult<UniqueHandle> {
    unsafe {
        let mut thread_handle = open_next_thread(process_handle, ptr::null_mut(), THREAD_ALL_ACCESS)?;

        let nt_set_event_addr = api_ctx::get_proc_address("ntdll.dll", "NtSetEvent").map_err(|_| {
            log::error!("unable to find NtSetEvent address");
            NTSTATUS(ntstatus::STATUS_PROCEDURE_NOT_FOUND)
        })?;
        let nt_wait_for_single_object = require_sys_api(api_ctx::ntdll().NtWaitForSingleObject, "NtWaitForSingleObject")?;

        while !thread_handle.is_null() {
            let local_event = create_event()?;

            let remote_event = match duplicate_handle(process_handle, *local_event, NT_CURRENT_PROCESS) {
                Ok(event) => event,
                Err(_) => {
                    thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                    continue;
                }
            };

            if suspend_thread(*thread_handle).is_err() {
                thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                continue;
            }

            if queue_apc_thread(*thread_handle, nt_set_event_addr as _, *remote_event, ptr::null_mut(), ptr::null_mut()).is_err() {
                thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                continue;
            }

            if resume_thread(*thread_handle).is_err() {
                thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                continue;
            }

            let mut timeout = ntwin::LARGE_INTEGER::from(-10_000_000);

            let status = NTSTATUS(nt_wait_for_single_object(*local_event, FALSE as _, &mut timeout));
            if status.is_err() {
                log::error!("unable to wait for event, {}", status.0);
                thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                continue;
            }

            if status.0 == ntstatus::STATUS_TIMEOUT {
                log::debug!("probably not an alertable thread (HANDLE = 0x{:x})", *thread_handle as usize);
                thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
                continue;
            }

            log::debug!("alertable thread found, HANDLE = 0x{:x}", *thread_handle as usize);
            return Ok(thread_handle);
        }

        log::error!("unable to find alertable thread, process (HANDLE = 0x{:x})", process_handle as usize);

        Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND).into())
    }
}

pub fn process_enumerate_threads<F>(process_handle: HANDLE, f: F) -> NtResult<()>
where
    F: Fn(HANDLE) -> bool,
{
    let mut thread_handle = open_next_thread(process_handle, ptr::null_mut(), THREAD_ALL_ACCESS)?;

    while !thread_handle.is_null() {
        if !f(*thread_handle) {
            break;
        }

        thread_handle = open_next_thread(process_handle, *thread_handle, THREAD_ALL_ACCESS)?;
    }

    Ok(())
}
