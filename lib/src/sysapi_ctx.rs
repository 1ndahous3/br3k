use crate::prelude::*;
use crate::sysapi;

use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{HMODULE, NTSTATUS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, LoadLibraryA, GetProcAddress};

use windef::*;

static SYSAPI: AtomicPtr<SysApiCtx> = AtomicPtr::new(ptr::null_mut());


#[allow(unused, non_snake_case)]
pub struct NtDllApi {
    module: Option<HMODULE>,

    pub PssNtCaptureSnapshot: Option<ntpsapi::PFN_PssNtCaptureSnapshot>,
    pub PssNtQuerySnapshot: Option<ntpsapi::PFN_PssNtQuerySnapshot>,
    pub PssNtFreeSnapshot: Option<ntpsapi::PFN_PssNtFreeSnapshot>,
    pub NtReadFile: Option<ntioapi::PFN_NtReadFile>,
    pub NtQuerySystemInformation: Option<ntexapi::PFN_NtQuerySystemInformation>,
    pub NtAllocateVirtualMemory: Option<ntmmapi::PFN_NtAllocateVirtualMemory>,
    pub NtReadVirtualMemory: Option<ntmmapi::PFN_NtReadVirtualMemory>,
    pub NtWriteVirtualMemory: Option<ntmmapi::PFN_NtWriteVirtualMemory>,
    pub NtProtectVirtualMemory: Option<ntmmapi::PFN_NtProtectVirtualMemory>,
    pub NtCreateSection: Option<ntmmapi::PFN_NtCreateSection>,
    pub NtMapViewOfSection: Option<ntmmapi::PFN_NtMapViewOfSection>,
    pub NtUnmapViewOfSection: Option<ntmmapi::PFN_NtUnmapViewOfSection>,
    pub NtClose: Option<ntobapi::PFN_NtClose>,
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
    // Alternative API
    pub NtCreateProcess: Option<ntpsapi::PFN_NtCreateProcess>,
    pub NtCreateThread: Option<ntpsapi::PFN_NtCreateThread>,
    pub NtCreateSectionEx: Option<ntmmapi::PFN_NtCreateSectionEx>,
    pub NtMapViewOfSectionEx: Option<ntmmapi::PFN_NtMapViewOfSectionEx>,
    pub NtUnmapViewOfSectionEx: Option<ntmmapi::PFN_NtUnmapViewOfSectionEx>,
    pub NtAllocateVirtualMemoryEx: Option<ntmmapi::PFN_NtAllocateVirtualMemoryEx>,
    pub NtReadVirtualMemoryEx: Option<ntmmapi::PFN_NtReadVirtualMemoryEx>,
}

pub struct InitOptions {
    pub ntdll_copy: bool,
    pub ntdll_alt_api: bool,
}

impl NtDllApi {
    fn get_proc_address<T>(module: HMODULE, proc_name: &str) -> Option<T> {
        unsafe {
            let proc = CString::new(proc_name).unwrap();
            let address = GetProcAddress(module, proc.as_ptr() as _);
            if let Some(address) = address {
                Some(mem::transmute_copy(&address))
            } else {
                log::error!("Unable to get address of \"{proc_name}\" from ntdll.dll");
                None
            }
        }
    }

    pub fn new(opts: &InitOptions) -> Self {
        unsafe {
            let module = if opts.ntdll_copy {
                sysapi::load_library_copy("c:\\windows\\system32\\ntdll.dll").unwrap().0
            } else {
                GetModuleHandleA(c"ntdll.dll".as_ptr() as _)
            };

            if module.is_null() {
                panic!("Failed to get handle for ntdll.dll");
            }

            Self {
                module: Some(module),

                PssNtCaptureSnapshot: Self::get_proc_address(module, "PssNtCaptureSnapshot"),
                PssNtQuerySnapshot: Self::get_proc_address(module, "PssNtQuerySnapshot"),
                PssNtFreeSnapshot: Self::get_proc_address(module, "PssNtFreeSnapshot"),
                NtReadFile: Self::get_proc_address(module, "NtReadFile"),
                NtQuerySystemInformation: Self::get_proc_address(module, "NtQuerySystemInformation"),
                NtAllocateVirtualMemory: Self::get_proc_address(module, "NtAllocateVirtualMemory"),
                NtReadVirtualMemory: Self::get_proc_address(module, "NtReadVirtualMemory"),
                NtWriteVirtualMemory: Self::get_proc_address(module, "NtWriteVirtualMemory"),
                NtProtectVirtualMemory: Self::get_proc_address(module, "NtProtectVirtualMemory"),
                NtCreateSection: Self::get_proc_address(module, "NtCreateSection"),
                NtMapViewOfSection: Self::get_proc_address(module, "NtMapViewOfSection"),
                NtUnmapViewOfSection: Self::get_proc_address(module, "NtUnmapViewOfSection"),
                NtClose: Self::get_proc_address(module, "NtClose"),
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
                // Alternative API
                NtCreateProcess: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtCreateProcess")
                } else {
                    None
                },
                NtCreateThread: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtCreateThread")
                } else {
                    None
                },
                NtCreateSectionEx: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtCreateSectionEx")
                } else {
                    None
                },
                NtMapViewOfSectionEx: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtMapViewOfSectionEx")
                } else {
                    None
                },
                NtUnmapViewOfSectionEx: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtUnmapViewOfSectionEx")
                } else {
                    None
                },
                NtAllocateVirtualMemoryEx: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtAllocateVirtualMemoryEx")
                } else {
                    None
                },
                NtReadVirtualMemoryEx: if opts.ntdll_alt_api {
                    Self::get_proc_address(module, "NtReadVirtualMemoryEx")
                } else {
                    None
                },
            }
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
            let proc = CString::new(proc_name).unwrap();
            let address = GetProcAddress(module, proc.as_ptr() as _);
            if let Some(address) = address {
                Some(mem::transmute_copy(&address))
            } else {
                log::error!("Unable to get address of \"{proc_name}\" from win32u.dll");
                None
            }
        }
    }

    pub fn new() -> Self {
        let module = unsafe { LoadLibraryA(c"win32u.dll".as_ptr() as _) };
        if module.is_null() {
            panic!("Failed to get handle for win32u.dll");
        }

        Self {
            NtUserGetWindowProcessHandle: Self::get_proc_address(
                module,
                "NtUserGetWindowProcessHandle",
            ),
        }
    }
}

pub struct SysApiCtx {
    ntstatus_decoder: HashMap<NTSTATUS, &'static str>,
    proc_addresses: RefCell<HashMap<String, PVOID>>,

    ntdll: NtDllApi,
    win32u: Win32uApi,
}

impl SysApiCtx {
    pub fn init(opts: InitOptions) {

        let opts_native = InitOptions {
            ntdll_copy: false,
            ..opts
        };

        let ctx_native = SysApiCtx {
            ntstatus_decoder: ntstatus::create_ntstatus_decoder(),
            proc_addresses: RefCell::new(HashMap::new()),
            ntdll: NtDllApi::new(&opts_native),
            win32u: Win32uApi::new(),
        };

        SYSAPI.store(Box::into_raw(Box::new(ctx_native)), Ordering::Relaxed);

        // we had to initialize the original API first to use sysapi during loading copy
        if opts.ntdll_copy {
            let ctx = SysApiCtx {
                ntstatus_decoder: ntstatus::create_ntstatus_decoder(),
                proc_addresses: RefCell::new(HashMap::new()),
                ntdll: NtDllApi::new(&opts),
                win32u: Win32uApi::new(),
            };

            SYSAPI.store(Box::into_raw(Box::new(ctx)), Ordering::Relaxed);
        }
    }

    pub fn ntdll() -> &'static NtDllApi {
        unsafe {
            let api = SYSAPI.load(Ordering::Relaxed);
            if api.is_null() {
                panic!("SysApiCtx is not initialized");
            }

            &(*api).ntdll
        }
    }

    pub fn win32u() -> &'static Win32uApi {
        unsafe {
            let api = SYSAPI.load(Ordering::Relaxed);
            if api.is_null() {
                panic!("SysApiCtx is not initialized");
            }

            &(*api).win32u
        }
    }

    pub fn ntstatus_decoder() -> &'static HashMap<NTSTATUS, &'static str> {
        unsafe {
            let api = SYSAPI.load(Ordering::Relaxed);
            if api.is_null() {
                panic!("SysApiCtx is not initialized");
            }

            &(*api).ntstatus_decoder
        }
    }

    pub fn get_proc_address(
        module_name: &str,
        proc_name: &str,
    ) -> Result<PVOID, ()> {
        unsafe {
            let proc_addresses = &mut (*SYSAPI.load(Ordering::Relaxed))
                .proc_addresses
                .borrow_mut();

            let address = proc_addresses.get(proc_name);
            if let Some(address) = address {
                return Ok(*address);
            }

            let module = CString::new(module_name).unwrap();
            let proc = CString::new(proc_name).unwrap();

            match GetProcAddress(
                GetModuleHandleA(module.as_ptr() as _),
                proc.as_ptr() as _,
            ) {
                Some(addr) => {
                    let address_raw = mem::transmute::<_, PVOID>(addr);
                    proc_addresses.insert(proc_name.to_string(), address_raw);
                    Ok(address_raw)
                }
                None => {
                    log::error!("Unable to get address of \"{proc_name}\" from {module_name}");
                    Err(())
                }
            }
        }
    }
}
