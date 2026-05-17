use crate::prelude::*;
use crate::sysapi;

use super::backend::{DirectSyscallError, DirectSyscallStubs, SysApiBackend};

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{HMODULE, NTSTATUS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

use strum_macros::EnumString;

use windef::*;

static SYSAPI: AtomicPtr<SysApiCtx> = AtomicPtr::new(ptr::null_mut());

#[derive(Debug, thiserror::Error)]
pub enum SysApiCtxError {
    #[error("SysApiCtx is not initialized")]
    NotInitialized,
    #[error("module is not loaded: {0}")]
    ModuleNotLoaded(String),
    #[error("procedure not found: {proc_name} ({module_name})")]
    ProcedureNotFound { module_name: String, proc_name: String },
    #[error("module name contains an interior NUL: {0}")]
    InvalidModuleName(String),
    #[error("procedure name contains an interior NUL: {0}")]
    InvalidProcedureName(String),
    #[error("failed to load a copy of {path}: {status}")]
    LoadLibraryCopy { path: &'static str, status: String },
    #[error(transparent)]
    DirectSyscall(#[from] DirectSyscallError),
}

#[allow(unused, non_snake_case)]
pub struct NtDllApi {
    module: Option<HMODULE>,

    pub PssNtCaptureSnapshot: Option<ntpsapi::PFN_PssNtCaptureSnapshot>,
    pub PssNtQuerySnapshot: Option<ntpsapi::PFN_PssNtQuerySnapshot>,
    pub PssNtFreeSnapshot: Option<ntpsapi::PFN_PssNtFreeSnapshot>,
    pub NtReadFile: Option<ntioapi::PFN_NtReadFile>,
    pub NtQuerySystemInformation: Option<ntexapi::PFN_NtQuerySystemInformation>,
    pub NtAllocateVirtualMemory: Option<ntmmapi::PFN_NtAllocateVirtualMemory>,
    pub NtQueryVirtualMemory: Option<ntmmapi::PFN_NtQueryVirtualMemory>,
    pub NtReadVirtualMemory: Option<ntmmapi::PFN_NtReadVirtualMemory>,
    pub NtWriteVirtualMemory: Option<ntmmapi::PFN_NtWriteVirtualMemory>,
    pub NtProtectVirtualMemory: Option<ntmmapi::PFN_NtProtectVirtualMemory>,
    pub NtCreateSection: Option<ntmmapi::PFN_NtCreateSection>,
    pub NtMapViewOfSection: Option<ntmmapi::PFN_NtMapViewOfSection>,
    pub NtUnmapViewOfSection: Option<ntmmapi::PFN_NtUnmapViewOfSection>,
    pub NtClose: Option<ntobapi::PFN_NtClose>,
    pub NtWaitForSingleObject: Option<ntobapi::PFN_NtWaitForSingleObject>,
    pub NtQueryObject: Option<ntobapi::PFN_NtQueryObject>,
    pub NtDuplicateObject: Option<ntobapi::PFN_NtDuplicateObject>,
    pub NtOpenProcess: Option<ntpsapi::PFN_NtOpenProcess>,
    pub NtQueryInformationProcess: Option<ntpsapi::PFN_NtQueryInformationProcess>,
    pub NtSuspendThread: Option<ntpsapi::PFN_NtSuspendThread>,
    pub NtResumeThread: Option<ntpsapi::PFN_NtResumeThread>,
    pub NtGetContextThread: Option<ntpsapi::PFN_NtGetContextThread>,
    pub NtSetContextThread: Option<ntpsapi::PFN_NtSetContextThread>,
    pub NtQueryInformationThread: Option<ntpsapi::PFN_NtQueryInformationThread>,
    pub NtSetInformationThread: Option<ntpsapi::PFN_NtSetInformationThread>,
    pub NtCreateUserProcess: Option<ntpsapi::PFN_NtCreateUserProcess>,
    pub NtCreateProcessEx: Option<ntpsapi::PFN_NtCreateProcessEx>,
    pub NtCreateThreadEx: Option<ntpsapi::PFN_NtCreateThreadEx>,
    pub NtOpenThread: Option<ntpsapi::PFN_NtOpenThread>,
    pub NtGetNextThread: Option<ntpsapi::PFN_NtGetNextThread>,
    pub NtCreateFile: Option<ntioapi::PFN_NtCreateFile>,
    pub NtWriteFile: Option<ntioapi::PFN_NtWriteFile>,
    pub NtCreateTransaction: Option<nttmapi::PFN_NtCreateTransaction>,
    pub NtRollbackTransaction: Option<nttmapi::PFN_NtRollbackTransaction>,
    pub NtQueryInformationFile: Option<ntioapi::PFN_NtQueryInformationFile>,
    pub NtQueueApcThread: Option<ntpsapi::PFN_NtQueueApcThread>,
    pub NtQueueApcThreadEx: Option<ntpsapi::PFN_NtQueueApcThreadEx>,
    pub NtCreateEvent: Option<ntexapi::PFN_NtCreateEvent>,
    pub NtCreateNamedPipeFile: Option<ntioapi::PFN_NtCreateNamedPipeFile>,
    pub NtSystemDebugControl: Option<ntexapi::PFN_NtSystemDebugControl>,
    pub RtlAdjustPrivilege: Option<ntrtl::PFN_RtlAdjustPrivilege>,
    pub RtlCreateProcessParametersEx: Option<ntrtl::PFN_RtlCreateProcessParametersEx>,
    pub RtlDestroyProcessParameters: Option<ntrtl::PFN_RtlDestroyProcessParameters>,
    pub RtlInitializeContext: Option<ntrtl::PFN_RtlInitializeContext>,
    pub RtlCreateEnvironmentEx: Option<ntrtl::PFN_RtlCreateEnvironmentEx>,
    pub RtlDestroyEnvironment: Option<ntrtl::PFN_RtlDestroyEnvironment>,
    pub RtlSetCurrentTransaction: Option<ntrtl::PFN_RtlSetCurrentTransaction>,
    // Dispatch-configurable system API alternatives
    pub NtCreateProcess: Option<ntpsapi::PFN_NtCreateProcess>,
    pub NtCreateThread: Option<ntpsapi::PFN_NtCreateThread>,
    pub NtCreateSectionEx: Option<ntmmapi::PFN_NtCreateSectionEx>,
    pub NtMapViewOfSectionEx: Option<ntmmapi::PFN_NtMapViewOfSectionEx>,
    pub NtUnmapViewOfSectionEx: Option<ntmmapi::PFN_NtUnmapViewOfSectionEx>,
    pub NtAllocateVirtualMemoryEx: Option<ntmmapi::PFN_NtAllocateVirtualMemoryEx>,
    pub NtReadVirtualMemoryEx: Option<ntmmapi::PFN_NtReadVirtualMemoryEx>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum CreateProcess {
    NtCreateProcess,
    #[default]
    NtCreateProcessEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum CreateThread {
    NtCreateThread,
    #[default]
    NtCreateThreadEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum CreateSection {
    #[default]
    NtCreateSection,
    NtCreateSectionEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum MapViewOfSection {
    #[default]
    NtMapViewOfSection,
    NtMapViewOfSectionEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum UnmapViewOfSection {
    #[default]
    NtUnmapViewOfSection,
    NtUnmapViewOfSectionEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum AllocateVirtualMemory {
    #[default]
    NtAllocateVirtualMemory,
    NtAllocateVirtualMemoryEx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum ReadVirtualMemory {
    #[default]
    NtReadVirtualMemory,
    NtReadVirtualMemoryEx,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SysApiDispatchConfig {
    pub create_process: CreateProcess,
    pub create_thread: CreateThread,
    pub create_section: CreateSection,
    pub map_view_of_section: MapViewOfSection,
    pub unmap_view_of_section: UnmapViewOfSection,
    pub allocate_virtual_memory: AllocateVirtualMemory,
    pub read_virtual_memory: ReadVirtualMemory,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InitOptions {
    pub sys_api_backend: SysApiBackend,
    pub sys_api_dispatch: SysApiDispatchConfig,
}

impl NtDllApi {
    fn get_proc_address_impl<T>(module: HMODULE, proc_name: &str, log_error: bool) -> Option<T> {
        unsafe {
            let proc = CString::new(proc_name).ok()?;
            let address = GetProcAddress(module, proc.as_ptr() as _);
            if let Some(address) = address {
                Some(mem::transmute_copy(&address))
            } else {
                if log_error {
                    log::error!("Unable to get address of \"{proc_name}\" from ntdll.dll");
                }
                None
            }
        }
    }

    fn get_proc_address<T>(module: HMODULE, proc_name: &str) -> Option<T> {
        Self::get_proc_address_impl(module, proc_name, true)
    }

    fn get_proc_address_opt<T>(module: HMODULE, proc_name: &str) -> Option<T> {
        Self::get_proc_address_impl(module, proc_name, false)
    }

    pub fn new(opts: &InitOptions) -> Result<Self, SysApiCtxError> {
        unsafe {
            let module = if opts.sys_api_backend.uses_dll_copy() {
                const NTDLL_PATH: &str = "c:\\windows\\system32\\ntdll.dll";
                sysapi::load_library_copy(NTDLL_PATH)
                    .map_err(|error| SysApiCtxError::LoadLibraryCopy { path: NTDLL_PATH, status: error.to_string() })?
                    .0
            } else {
                GetModuleHandleA(c"ntdll.dll".as_ptr() as _)
            };

            if module.is_null() {
                return Err(SysApiCtxError::ModuleNotLoaded("ntdll.dll".to_string()));
            }

            Ok(Self {
                module: Some(module),

                PssNtCaptureSnapshot: Self::get_proc_address(module, "PssNtCaptureSnapshot"),
                PssNtQuerySnapshot: Self::get_proc_address(module, "PssNtQuerySnapshot"),
                PssNtFreeSnapshot: Self::get_proc_address(module, "PssNtFreeSnapshot"),
                NtReadFile: Self::get_proc_address(module, "NtReadFile"),
                NtQuerySystemInformation: Self::get_proc_address(module, "NtQuerySystemInformation"),
                NtAllocateVirtualMemory: Self::get_proc_address(module, "NtAllocateVirtualMemory"),
                NtQueryVirtualMemory: Self::get_proc_address(module, "NtQueryVirtualMemory"),
                NtReadVirtualMemory: Self::get_proc_address(module, "NtReadVirtualMemory"),
                NtWriteVirtualMemory: Self::get_proc_address(module, "NtWriteVirtualMemory"),
                NtProtectVirtualMemory: Self::get_proc_address(module, "NtProtectVirtualMemory"),
                NtCreateSection: Self::get_proc_address(module, "NtCreateSection"),
                NtMapViewOfSection: Self::get_proc_address(module, "NtMapViewOfSection"),
                NtUnmapViewOfSection: Self::get_proc_address(module, "NtUnmapViewOfSection"),
                NtClose: Self::get_proc_address(module, "NtClose"),
                NtWaitForSingleObject: Self::get_proc_address(module, "NtWaitForSingleObject"),
                NtQueryObject: Self::get_proc_address(module, "NtQueryObject"),
                NtDuplicateObject: Self::get_proc_address(module, "NtDuplicateObject"),
                NtOpenProcess: Self::get_proc_address(module, "NtOpenProcess"),
                NtQueryInformationProcess: Self::get_proc_address(module, "NtQueryInformationProcess"),
                NtSuspendThread: Self::get_proc_address(module, "NtSuspendThread"),
                NtResumeThread: Self::get_proc_address(module, "NtResumeThread"),
                NtGetContextThread: Self::get_proc_address(module, "NtGetContextThread"),
                NtSetContextThread: Self::get_proc_address(module, "NtSetContextThread"),
                NtQueryInformationThread: Self::get_proc_address(module, "NtQueryInformationThread"),
                NtSetInformationThread: Self::get_proc_address(module, "NtSetInformationThread"),
                NtCreateUserProcess: Self::get_proc_address(module, "NtCreateUserProcess"),
                NtCreateProcessEx: Self::get_proc_address(module, "NtCreateProcessEx"),
                NtCreateThreadEx: Self::get_proc_address(module, "NtCreateThreadEx"),
                NtOpenThread: Self::get_proc_address(module, "NtOpenThread"),
                NtGetNextThread: Self::get_proc_address(module, "NtGetNextThread"),
                NtCreateFile: Self::get_proc_address(module, "NtCreateFile"),
                NtWriteFile: Self::get_proc_address(module, "NtWriteFile"),
                NtCreateTransaction: Self::get_proc_address(module, "NtCreateTransaction"),
                NtRollbackTransaction: Self::get_proc_address(module, "NtRollbackTransaction"),
                NtQueryInformationFile: Self::get_proc_address(module, "NtQueryInformationFile"),
                NtQueueApcThread: Self::get_proc_address(module, "NtQueueApcThread"),
                NtQueueApcThreadEx: Self::get_proc_address(module, "NtQueueApcThreadEx"),
                NtCreateEvent: Self::get_proc_address(module, "NtCreateEvent"),
                NtCreateNamedPipeFile: Self::get_proc_address(module, "NtCreateNamedPipeFile"),
                NtSystemDebugControl: Self::get_proc_address(module, "NtSystemDebugControl"),
                RtlAdjustPrivilege: Self::get_proc_address(module, "RtlAdjustPrivilege"),
                RtlCreateProcessParametersEx: Self::get_proc_address(module, "RtlCreateProcessParametersEx"),
                RtlDestroyProcessParameters: Self::get_proc_address(module, "RtlDestroyProcessParameters"),
                RtlInitializeContext: Self::get_proc_address(module, "RtlInitializeContext"),
                RtlCreateEnvironmentEx: Self::get_proc_address(module, "RtlCreateEnvironmentEx"),
                RtlDestroyEnvironment: Self::get_proc_address(module, "RtlDestroyEnvironment"),
                RtlSetCurrentTransaction: Self::get_proc_address(module, "RtlSetCurrentTransaction"),
                // Dispatch-configurable system API alternatives
                NtCreateProcess: Self::get_proc_address_opt(module, "NtCreateProcess"),
                NtCreateThread: Self::get_proc_address_opt(module, "NtCreateThread"),
                NtCreateSectionEx: Self::get_proc_address_opt(module, "NtCreateSectionEx"),
                NtMapViewOfSectionEx: Self::get_proc_address_opt(module, "NtMapViewOfSectionEx"),
                NtUnmapViewOfSectionEx: Self::get_proc_address_opt(module, "NtUnmapViewOfSectionEx"),
                NtAllocateVirtualMemoryEx: Self::get_proc_address_opt(module, "NtAllocateVirtualMemoryEx"),
                NtReadVirtualMemoryEx: Self::get_proc_address_opt(module, "NtReadVirtualMemoryEx"),
            })
        }
    }
}

#[allow(non_snake_case)]
pub struct Win32uApi {
    pub NtUserGetWindowProcessHandle: Option<ntwin::PFN_NtUserGetWindowProcessHandle>,
}

impl Win32uApi {
    fn get_proc_address<T>(module: HMODULE, proc_name: &str) -> Option<T> {
        unsafe {
            let proc = CString::new(proc_name).ok()?;
            let address = GetProcAddress(module, proc.as_ptr() as _);
            if let Some(address) = address {
                Some(mem::transmute_copy(&address))
            } else {
                log::error!("Unable to get address of \"{proc_name}\" from win32u.dll");
                None
            }
        }
    }

    pub fn new(opts: &InitOptions) -> Result<Self, SysApiCtxError> {
        let module = if opts.sys_api_backend.uses_dll_copy() {
            const WIN32U_PATH: &str = "c:\\windows\\system32\\win32u.dll";
            sysapi::load_library_copy(WIN32U_PATH)
                .map_err(|error| SysApiCtxError::LoadLibraryCopy { path: WIN32U_PATH, status: error.to_string() })?
                .0
        } else {
            unsafe { LoadLibraryA(c"win32u.dll".as_ptr() as _) }
        };
        if module.is_null() {
            return Err(SysApiCtxError::ModuleNotLoaded("win32u.dll".to_string()));
        }

        Ok(Self {
            NtUserGetWindowProcessHandle: Self::get_proc_address(module, "NtUserGetWindowProcessHandle")
        })
    }
}

pub struct SysApiCtx {
    ntstatus_decoder: HashMap<NTSTATUS, &'static str>,
    proc_addresses: RefCell<HashMap<String, PVOID>>,

    ntdll: NtDllApi,
    win32u: Win32uApi,
    direct_syscall_stubs: DirectSyscallStubs,
    sys_api_backend: SysApiBackend,
    sys_api_dispatch: SysApiDispatchConfig,
}

impl SysApiCtx {
    pub fn init(opts: InitOptions) -> Result<(), SysApiCtxError> {
        let opts_native = InitOptions { sys_api_backend: SysApiBackend::Dll, ..opts };

        let ctx_native = SysApiCtx {
            ntstatus_decoder: ntstatus::create_ntstatus_decoder(),
            proc_addresses: RefCell::new(HashMap::new()),
            ntdll: NtDllApi::new(&opts_native)?,
            win32u: Win32uApi::new(&opts_native)?,
            direct_syscall_stubs: DirectSyscallStubs::new(),
            sys_api_backend: opts_native.sys_api_backend,
            sys_api_dispatch: opts.sys_api_dispatch,
        };

        SYSAPI.store(Box::into_raw(Box::new(ctx_native)), Ordering::Relaxed);

        // we had to initialize the original API first to use sysapi during loading copy
        if opts.sys_api_backend.uses_dll_copy() {
            let ctx = SysApiCtx {
                ntstatus_decoder: ntstatus::create_ntstatus_decoder(),
                proc_addresses: RefCell::new(HashMap::new()),
                ntdll: NtDllApi::new(&opts)?,
                win32u: Win32uApi::new(&opts)?,
                direct_syscall_stubs: DirectSyscallStubs::new(),
                sys_api_backend: opts.sys_api_backend,
                sys_api_dispatch: opts.sys_api_dispatch,
            };

            SYSAPI.store(Box::into_raw(Box::new(ctx)), Ordering::Relaxed);
        }

        Ok(())
    }

    fn try_ctx() -> Result<&'static SysApiCtx, SysApiCtxError> {
        unsafe {
            let api = SYSAPI.load(Ordering::Relaxed);
            if api.is_null() {
                return Err(SysApiCtxError::NotInitialized);
            }

            Ok(&*api)
        }
    }

    pub fn ntdll() -> &'static NtDllApi {
        &Self::try_ctx()
            .expect("SysApiCtx is not initialized").ntdll
    }

    pub fn win32u() -> &'static Win32uApi {
        &Self::try_ctx()
            .expect("SysApiCtx is not initialized").win32u
    }

    pub fn ntstatus_decoder() -> &'static HashMap<NTSTATUS, &'static str> {
        &Self::try_ctx()
            .expect("SysApiCtx is not initialized").ntstatus_decoder
    }

    pub fn sys_api_dispatch() -> &'static SysApiDispatchConfig {
        &Self::try_ctx()
            .expect("SysApiCtx is not initialized").sys_api_dispatch
    }

    pub fn sys_api_backend() -> SysApiBackend {
        Self::try_ctx()
            .expect("SysApiCtx is not initialized").sys_api_backend
    }

    pub fn direct_syscall<T: Copy>(proc_name: &'static str, api: T) -> Result<T, SysApiCtxError> {
        Ok(Self::try_ctx()?.direct_syscall_stubs.get(proc_name, api)?)
    }

    pub fn get_proc_address(module_name: &str, proc_name: &str) -> Result<PVOID, SysApiCtxError> {
        unsafe {
            let api = Self::try_ctx()?;
            let mut proc_addresses = api.proc_addresses.borrow_mut();
            let cache_key = format!("{module_name}!{proc_name}");

            let address = proc_addresses.get(&cache_key);
            if let Some(address) = address {
                return Ok(*address);
            }

            let module = CString::new(module_name)
                .map_err(|_| SysApiCtxError::InvalidModuleName(module_name.to_string()))?;

            let proc = CString::new(proc_name)
                .map_err(|_| SysApiCtxError::InvalidProcedureName(proc_name.to_string()))?;

            let module_handle = GetModuleHandleA(module.as_ptr() as _);
            if module_handle.is_null() {
                return Err(SysApiCtxError::ModuleNotLoaded(module_name.to_string()));
            }

            match GetProcAddress(module_handle, proc.as_ptr() as _) {
                Some(addr) => {
                    let address_raw = mem::transmute::<_, PVOID>(addr);
                    proc_addresses.insert(cache_key, address_raw);
                    Ok(address_raw)
                }
                None => {
                    log::error!("Unable to get address of \"{proc_name}\" from {module_name}");
                    Err(SysApiCtxError::ProcedureNotFound { module_name: module_name.to_string(), proc_name: proc_name.to_string() })
                }
            }
        }
    }
}
