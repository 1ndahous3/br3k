#![allow(non_snake_case)]
use crate::prelude::*;
use crate::str::*;

use crate::sysapi_ctx::SysApiCtx as api_ctx;
use crate::unique_resource::*;

use path::PathBuf;

use windows::Win32::Foundation::{HMODULE, NTSTATUS};
use windows::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, WOW64_CONTEXT};
use windows_sys::Win32::System::Threading::{
    EVENT_ALL_ACCESS, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, LoadLibraryA};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_GUARD,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, SEC_COMMIT, SEC_IMAGE,
    SECTION_FLAGS, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_ALL_ACCESS
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ
};

use windef::{
    ntdef, ntexapi, ntioapi, ntmmapi, ntpebteb, ntseapi,
    ntpsapi, ntrtl, ntstatus, ntwin, winbase
};
use winbase::{ULONG, NT_CURRENT_PROCESS};

pub type Result<T> = result::Result<T, NTSTATUS>;

pub type UniqueHandle = UniqueResource<HANDLE, fn(HANDLE)>;

pub fn ntstatus_decode(status: NTSTATUS) -> String {
    format!(
        "0x{:x} ({})",
        status.0 as u32,
        api_ctx::ntstatus_decoder().get(&status.0).unwrap()
    )
}

pub fn HandleClose(handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtClose.unwrap()(handle));
        status.is_ok().then_some(()).ok_or(status)
    }
}

pub fn HandleDuplicate(
    target_process_handle: HANDLE,
    source_handle: HANDLE,
    source_process_handle: HANDLE,
) -> Result<HANDLE> {
    unsafe {
        let mut target_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtDuplicateObject.unwrap()(
            source_process_handle,
            source_handle,
            target_process_handle,
            &mut target_handle,
            0, // DesiredAccess
            0, // Attributes
            winbase::DUPLICATE_SAME_ACCESS,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(target_handle)
        }
    }
}

pub fn HandleWrap(handle: HANDLE) -> UniqueHandle {
    fn handle_close_deleter(handle: HANDLE) {
        let _ = HandleClose(handle);
    }
    UniqueResource::new(handle, handle_close_deleter)
}
pub fn Peb() -> ntpebteb::PPEB {
    #[cfg(target_pointer_width = "64")]
    {
        unsafe {
            let peb: u64;
            std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            peb as ntpebteb::PPEB
        }
    }
    #[cfg(target_pointer_width = "32")]
    {
        unsafe {
            let peb: u32;
            std::arch::asm!("mov {}, gs:[0x30]", out(reg) peb);
            peb as ntpebteb::PPEB
        }
    }
}

pub type UniqueProcessParameters = UniqueResource<
    ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
    fn(ntpebteb::PRTL_USER_PROCESS_PARAMETERS),
>;

pub fn ProcessParametersCreate(
    name: &str,
) -> Result<ntpebteb::PRTL_USER_PROCESS_PARAMETERS> {
    unsafe {
        let nt_name = format!("\\??\\{}", name);
        let nt_name = U16CString::from_str(nt_name).unwrap();

        let mut current_directory = [0u16; winbase::MAX_PATH];
        GetCurrentDirectoryW(Some(&mut current_directory));

        let peb = Peb();

        let mut process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
        let status = NTSTATUS(api_ctx::ntdll().RtlCreateProcessParametersEx.unwrap()(
            &mut process_parameters,
            &mut to_unicode_string(&nt_name) as *mut _ as *mut _,
            &mut (*(*peb).ProcessParameters).DllPath as *mut _ as *mut _,
            &mut to_unicode_string(&current_directory) as *mut _ as *mut _,
            &mut to_unicode_string(&nt_name) as *mut _ as *mut _,
            (*(*peb).ProcessParameters).Environment,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(process_parameters)
        }
    }
}

pub fn ProcessParametersDestroy(process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS) {
    unsafe {
        api_ctx::ntdll().RtlDestroyProcessParameters.unwrap()(process_parameters);
    }
}

pub fn ProcessParametersWrap(
    process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
) -> UniqueProcessParameters {
    fn process_parameters_destroy_deleter(
        process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
    ) {
        let _ = ProcessParametersDestroy(process_parameters);
    }
    UniqueResource::new(process_parameters, process_parameters_destroy_deleter)
}

// ProcessHandle, ThreadHandle
pub fn ProcessCreateUser(name: &str, suspended: bool) -> Result<(HANDLE, HANDLE)> {
    unsafe {
        let nt_name = format!("\\??\\{}", name);
        let nt_name = U16CString::from_str(nt_name).unwrap();

        let mut process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
        let status = NTSTATUS(api_ctx::ntdll().RtlCreateProcessParametersEx.unwrap()(
            &mut process_parameters,
            &mut to_unicode_string(&nt_name) as *mut _ as *mut _,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ntrtl::RTL_USER_PROC_PARAMS_NORMALIZED,
        ));

        if !status.is_ok() {
            return Err(status);
        }

        let mut create_info = ntpsapi::PS_CREATE_INFO {
            Size: size_of::<ntpsapi::PS_CREATE_INFO>(),
            State: ntpsapi::PS_CREATE_STATE::PsCreateInitialState,
            ..Default::default()
        };

        let mut attribute_list = ntpsapi::PS_ATTRIBUTE_LIST {
            TotalLength: size_of::<ntpsapi::PS_ATTRIBUTE_LIST>(),
            Attributes: [ntpsapi::PS_ATTRIBUTE {
                ..Default::default()
            }],
        };

        attribute_list.Attributes[0].Attribute = winbase::PS_ATTRIBUTE_IMAGE_NAME as usize;
        attribute_list.Attributes[0].Size = nt_name.len() * 2;
        attribute_list.Attributes[0].a1.bindgen_union_field = nt_name.as_ptr() as u64;

        let mut process_handle: HANDLE = ptr::null_mut();
        let mut thread_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtCreateUserProcess.unwrap()(
            &mut process_handle,
            &mut thread_handle,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            if suspended {
                ntpsapi::THREAD_CREATE_FLAGS_CREATE_SUSPENDED
            } else {
                ntpsapi::THREAD_CREATE_FLAGS_NONE
            },
            process_parameters as *mut _,
            &mut create_info,
            &mut attribute_list,
        ));

        ProcessParametersDestroy(process_parameters);

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_OBJECT_PATH_INVALID {
                log::warn!(
                    "the process \"{}\" probably has an IFEO key without a 'Debugger' value",
                    name
                );
            }

            Err(status)
        } else {
            Ok((process_handle, thread_handle))
        }
    }
}

pub fn ProcessCreate(SectionHandle: HANDLE) -> Result<HANDLE> {
    unsafe {
        let mut process_handle: HANDLE = ptr::null_mut();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status: NTSTATUS = if api_ctx::ntdll().NtCreateProcess.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateProcess.unwrap()(
                &mut process_handle,
                PROCESS_ALL_ACCESS,
                &mut object_attributes,
                winbase::NT_CURRENT_PROCESS,
                true.into(),
                SectionHandle,
                ptr::null_mut(),
                ptr::null_mut(),
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateProcessEx.unwrap()(
                &mut process_handle,
                PROCESS_ALL_ACCESS,
                &mut object_attributes,
                winbase::NT_CURRENT_PROCESS,
                ntpsapi::PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                SectionHandle,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(process_handle)
        }
    }
}

pub fn ProcessGetBasicInfo(
    process_handle: HANDLE,
) -> Result<ntpsapi::PROCESS_BASIC_INFORMATION> {
    unsafe {
        let mut basic_info = ntpsapi::PROCESS_BASIC_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationProcess.unwrap()(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessBasicInformation,
            &mut basic_info as *mut _ as *mut _,
            size_of::<ntpsapi::PROCESS_BASIC_INFORMATION>() as u32,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(basic_info)
        }
    }
}

pub fn ProcessGetWow64Info(process_handle: HANDLE) -> Result<bool> {
    unsafe {
        let mut wow64_info: usize = 0;

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationProcess.unwrap()(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessWow64Information,
            &mut wow64_info as *mut _ as *mut _,
            size_of::<usize>() as u32,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wow64_info == 0)
        }
    }
}

pub fn ProcessFind(name: &str) -> Result<u32> {
    unsafe {
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL));
        }

        if Process32FirstW(snapshot, &mut entry) == 0 {
            return Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND));
        }

        let mut pid = 0;
        loop {
            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }

            let exe_name_u = U16CString::from_ptr_str(entry.szExeFile.as_ptr());
            let exe_name = exe_name_u.to_string_lossy();

            if !name.eq_ignore_ascii_case(&exe_name) {
                continue;
            }

            if pid != 0 {
                return Err(NTSTATUS(ntstatus::STATUS_TOO_MANY_NAMES));
            }

            pid = entry.th32ProcessID;
        }

        if pid == 0 {
            Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND))
        } else {
            Ok(pid)
        }
    }
}

pub fn ProcessOpenByHwnd(
    hwnd: HWND,
    access_mask: winbase::ACCESS_MASK,
) -> Result<HANDLE> {
    unsafe {
        let process_handle =
            api_ctx::win32u().NtUserGetWindowProcessHandle.unwrap()(hwnd, access_mask);
        if process_handle.is_null() {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(process_handle)
        }
    }
}

pub fn ProcessOpen(pid: u32, access_mask: u32) -> Result<HANDLE> {
    unsafe {
        let mut process_handle: HANDLE = ptr::null_mut();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let mut client_id = ntdef::CLIENT_ID {
            UniqueProcess: pid as _,
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtOpenProcess.unwrap()(
            &mut process_handle,
            access_mask,
            &mut object_attributes,
            &mut client_id as *mut _ as *mut _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(process_handle)
        }
    }
}

pub fn ThreadOpenNext(
    process_handle: HANDLE,
    thread_handle: HANDLE,
    access_mask: winbase::ACCESS_MASK,
) -> Result<HANDLE> {
    unsafe {
        let mut new_thread_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtGetNextThread.unwrap()(
            process_handle,
            thread_handle,
            access_mask,
            0,
            0,
            &mut new_thread_handle,
        ));

        if !status.is_ok() {
            if status.0 != ntstatus::STATUS_NO_MORE_ENTRIES {
                return Err(status);
            }

            return Ok(new_thread_handle);
        }

        Ok(new_thread_handle)
    }
}

pub fn ThreadOpen(
    pid: u32,
    tid: u32,
    access_mask: winbase::ACCESS_MASK,
) -> Result<HANDLE> {
    unsafe {
        let mut thread_handle: HANDLE = ptr::null_mut();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let mut client_id = ntdef::CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: tid as _,
        };

        let status = NTSTATUS(api_ctx::ntdll().NtOpenThread.unwrap()(
            &mut thread_handle,
            access_mask,
            &mut object_attributes,
            &mut client_id as *mut _ as *mut _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(thread_handle)
        }
    }
}

fn ThreadCreateStack(
    process_handle: HANDLE,
    initial_teb: ntpsapi::PINITIAL_TEB,
) -> Result<()> {
    unsafe {
        let sys_info = ntexapi::SYSTEM_BASIC_INFORMATION {
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtQuerySystemInformation.unwrap()(
            ntexapi::SYSTEM_INFORMATION_CLASS::SystemBasicInformation,
            &sys_info as *const _ as *mut _,
            size_of::<ntexapi::SYSTEM_BASIC_INFORMATION>() as u32,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            return Err(status);
        }

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
        let maximum_stack_size =
            maximum_stack_size.next_multiple_of(sys_info.AllocationGranularity);

        let mut stack = VirtualMemoryAllocate(
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

        stack = VirtualMemoryAllocate(
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

            VirtualMemoryProtect(stack, region_size as _, protect, process_handle)?;

            (*initial_teb).StackLimit = (*initial_teb).StackLimit.add(region_size as _);
        }

        Ok(())
    }
}

pub fn ThreadCreate(
    process_handle: HANDLE,
    start_address: PVOID,
) -> Result<HANDLE> {
    unsafe {
        let mut thread_handle: HANDLE = ptr::null_mut();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status = if api_ctx::ntdll().NtCreateThread.is_some() {
            let client_id = VirtualMemoryAllocate(
                size_of::<ntdef::CLIENT_ID>(),
                PAGE_READWRITE,
                process_handle,
                ptr::null_mut(),
                MEM_COMMIT | MEM_RESERVE,
            )? as ntdef::PCLIENT_ID;
            let initial_teb = VirtualMemoryAllocate(
                size_of::<ntpsapi::INITIAL_TEB>(),
                PAGE_READWRITE,
                process_handle,
                ptr::null_mut(),
                MEM_COMMIT | MEM_RESERVE,
            )? as ntpsapi::PINITIAL_TEB;
            let context = VirtualMemoryAllocate(
                size_of::<CONTEXT>(),
                PAGE_READWRITE,
                process_handle,
                ptr::null_mut(),
                MEM_COMMIT | MEM_RESERVE,
            )? as winbase::PCONTEXT;

            ThreadCreateStack(process_handle, initial_teb)?;

            api_ctx::ntdll().RtlInitializeContext.unwrap()(
                process_handle,
                context,
                ptr::null_mut(),
                start_address as *mut _,
                (*initial_teb).StackBase,
            );

            NTSTATUS(api_ctx::ntdll().NtCreateThread.unwrap()(
                &mut thread_handle,
                THREAD_ALL_ACCESS,
                &mut object_attributes,
                process_handle,
                client_id as *mut _ as *mut _,
                context as *mut _ as *mut _,
                initial_teb as *mut _ as *mut _,
                false as _,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateThreadEx.unwrap()(
                &mut thread_handle,
                THREAD_ALL_ACCESS,
                &mut object_attributes,
                process_handle,
                start_address,
                ptr::null_mut(),
                0,
                0,
                0,
                0,
                ptr::null_mut(),
            ))
        };

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_ACCESS_DENIED {
                log::warn!("the target process probably has a 'ControlFlowGuard' protection");
            }

            Err(status)
        } else {
            Ok(thread_handle)
        }
    }
}

pub fn ThreadSuspend(thread_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtSuspendThread.unwrap()(
            thread_handle,
            ptr::null_mut(),
        ));
        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn ThreadResume(thread_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtResumeThread.unwrap()(
            thread_handle,
            ptr::null_mut(),
        ));
        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn ThreadGetBasicInfo(
    thread_handle: HANDLE,
) -> Result<ntpsapi::THREAD_BASIC_INFORMATION> {
    unsafe {
        let mut basic_info = ntpsapi::THREAD_BASIC_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadBasicInformation,
            &mut basic_info as *mut _ as *mut _,
            size_of::<ntpsapi::THREAD_BASIC_INFORMATION>() as u32,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(basic_info)
        }
    }
}

// WORKAROUND: https://github.com/microsoft/win32metadata/issues/1044

#[repr(align(16))]
#[derive(Default)]
struct AlignedContext {
    ctx: CONTEXT,
}

#[repr(align(16))]
#[derive(Default)]
struct AlignedWow64Context {
    ctx: WOW64_CONTEXT,
}

pub fn ThreadGetContext(thread_handle: HANDLE) -> Result<CONTEXT> {
    unsafe {
        let mut context = AlignedContext::default();
        context.ctx.ContextFlags = winbase::CONTEXT_FULL;

        let status = NTSTATUS(api_ctx::ntdll().NtGetContextThread.unwrap()(
            thread_handle,
            &mut context as *mut _ as *mut _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(context.ctx)
        }
    }
}

pub fn ThreadGetWow64Context(thread_handle: HANDLE) -> Result<WOW64_CONTEXT> {
    unsafe {
        let mut context = AlignedWow64Context::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            &mut context as *mut _ as *mut _,
            size_of::<AlignedWow64Context>() as u32,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(context.ctx)
        }
    }
}

pub fn ThreadSetContext(thread_handle: HANDLE, ctx: &CONTEXT) -> Result<()> {
    unsafe {
        let context = AlignedContext { ctx: *ctx };

        let status = NTSTATUS(api_ctx::ntdll().NtSetContextThread.unwrap()(
            thread_handle,
            &context as *const _ as *mut _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn ThreadSetWow64Context(thread_handle: HANDLE, ctx: &WOW64_CONTEXT) -> Result<()> {
    unsafe {
        let context = AlignedWow64Context { ctx: *ctx };

        let status = NTSTATUS(api_ctx::ntdll().NtSetInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            &context as *const _ as *mut _,
            size_of::<AlignedWow64Context>() as u32,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn VirtualMemoryAllocate(
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
    allocation_type: ULONG,
) -> Result<PVOID> {
    unsafe {
        let mut base_address = base_address;
        let mut size = size;

        let status = if api_ctx::ntdll().NtAllocateVirtualMemoryEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtAllocateVirtualMemoryEx.unwrap()(
                process_handle,
                &mut base_address as *mut _ as *mut _,
                &mut size as *mut _ as *mut _,
                allocation_type,
                protect,
                ptr::null_mut(),
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtAllocateVirtualMemory.unwrap()(
                process_handle,
                &mut base_address as *mut _ as *mut _,
                0,
                &mut size as *mut _ as *mut _,
                allocation_type,
                protect,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(base_address)
        }
    }
}

pub fn SectionCreate(size: usize) -> Result<HANDLE> {
    unsafe {
        let mut section_handle: HANDLE = ptr::null_mut();

        let mut maximum_size = ntwin::LARGE_INTEGER::default();
        maximum_size.bindgen_union_field = size as u64;

        let status = if api_ctx::ntdll().NtCreateSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateSectionEx.unwrap()(
                &mut section_handle,
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                ptr::null_mut(),
                &mut maximum_size,
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateSection.unwrap()(
                &mut section_handle,
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                ptr::null_mut(),
                &mut maximum_size,
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(),
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(section_handle)
        }
    }
}

pub fn SectionFileCreate(
    file_handle: HANDLE,
    access_mask: u32,
    protection: SECTION_FLAGS,
    as_image: bool,
    size: Option<usize>,
) -> Result<HANDLE> {
    unsafe {
        let mut section_handle: HANDLE = ptr::null_mut();

        let mut maximum_size = ntwin::LARGE_INTEGER::default();
        if let Some(size) = size {
            maximum_size.bindgen_union_field = size as u64;
        }

        let status = if api_ctx::ntdll().NtCreateSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateSectionEx.unwrap()(
                &mut section_handle,
                access_mask,
                ptr::null_mut(),
                &mut maximum_size,
                protection,
                if as_image { SEC_IMAGE } else { SEC_COMMIT },
                file_handle,
                ptr::null_mut(),
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateSection.unwrap()(
                &mut section_handle,
                access_mask,
                ptr::null_mut(),
                &mut maximum_size,
                protection,
                if as_image { SEC_IMAGE } else { SEC_COMMIT },
                file_handle,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(section_handle)
        }
    }
}

pub fn SectionMapView(
    section_handle: HANDLE,
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
) -> Result<PVOID> {
    unsafe {
        let mut base_address = base_address;
        let mut size = size;

        let status = if api_ctx::ntdll().NtMapViewOfSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtMapViewOfSectionEx.unwrap()(
                section_handle,
                process_handle,
                &mut base_address as *mut _ as *mut _,
                ptr::null_mut(),
                &mut size as *mut _ as *mut _,
                0,
                protect,
                ptr::null_mut(),
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtMapViewOfSection.unwrap()(
                section_handle,
                process_handle,
                &mut base_address as *mut _ as *mut _,
                0,
                0,
                ptr::null_mut(),
                &mut size as *mut _ as *mut _,
                ntmmapi::SECTION_INHERIT::ViewUnmap,
                0,
                protect,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(base_address)
        }
    }
}

pub fn SectionUnmapView(
    base_address: PVOID,
    process_handle: HANDLE,
) -> Result<()> {
    unsafe {
        let status = if api_ctx::ntdll().NtUnmapViewOfSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtUnmapViewOfSectionEx.unwrap()(
                process_handle,
                base_address,
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtUnmapViewOfSection.unwrap()(
                process_handle,
                base_address,
            ))
        };

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn VirtualMemoryProtect(
    base_address: PVOID,
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
) -> Result<()> {
    unsafe {
        let mut base_address = base_address;
        let mut size = size;

        let mut new_protect = protect;

        let status = NTSTATUS(api_ctx::ntdll().NtProtectVirtualMemory.unwrap()(
            process_handle,
            &mut base_address as *mut _ as *mut _,
            &mut size as *mut _ as *mut _,
            protect,
            &mut new_protect as *mut _ as *mut _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn VirtualMemoryWrite(
    data: PVOID,
    size: usize,
    base_address: PVOID,
    process_handle: HANDLE,
) -> Result<()> {
    unsafe {
        let mut number_of_bytes_written: usize = 0;

        let status = NTSTATUS(api_ctx::ntdll().NtWriteVirtualMemory.unwrap()(
            process_handle,
            base_address,
            data,
            size,
            &mut number_of_bytes_written as *mut _ as *mut _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn VirtualMemoryRead<T>(
    mut buffer: T,
    base_address: PVOID,
    process_handle: HANDLE,
) -> Result<usize>
where
    T: AsMut<[u8]>,
{
    unsafe {
        let slice = buffer.as_mut();
        let data = slice.as_mut_ptr() as PVOID;
        let size = slice.len();

        let mut number_of_bytes_read: usize = 0;

        let status = if api_ctx::ntdll().NtReadVirtualMemoryEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtReadVirtualMemoryEx.unwrap()(
                process_handle,
                base_address,
                data,
                size,
                &mut number_of_bytes_read as *mut _ as *mut _,
                0, //
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtReadVirtualMemory.unwrap()(
                process_handle,
                base_address,
                data,
                size,
                &mut number_of_bytes_read as *mut _ as *mut _,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(number_of_bytes_read)
        }
    }
}

pub fn TransactionCreate(path: &str) -> Result<HANDLE> {
    unsafe {
        let nt_path = format!("\\??\\{}", path);
        let nt_path = U16CString::from_str(nt_path).unwrap();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: &mut to_unicode_string(&nt_path) as *mut _ as *mut _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let mut transaction_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtCreateTransaction.unwrap()(
            &mut transaction_handle,
            winbase::TRANSACTION_ALL_ACCESS,
            &mut object_attributes,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(transaction_handle)
        }
    }
}

pub fn TransactionRollback(transaction_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtRollbackTransaction.unwrap()(
            transaction_handle,
            true as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn TransactionSet(transaction_handle: HANDLE) -> Result<()> {
    unsafe {
        let res = api_ctx::ntdll().RtlSetCurrentTransaction.unwrap()(transaction_handle);

        if res == 0 {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(())
        }
    }
}

pub fn ThreadQueueUserApc(
    thread_handle: HANDLE,
    apc_routine: winbase::PPS_APC_ROUTINE,
    apc_argument1: PVOID,
    apc_argument2: PVOID,
    apc_argument3: PVOID,
) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtQueueApcThread.unwrap()(
            thread_handle,
            apc_routine,
            apc_argument1,
            apc_argument2,
            apc_argument3,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn EventCreate() -> Result<HANDLE> {
    unsafe {
        let mut event_handle: HANDLE = ptr::null_mut();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtCreateEvent.unwrap()(
            &mut event_handle,
            EVENT_ALL_ACCESS,
            &mut object_attributes,
            ntdef::EVENT_TYPE::NotificationEvent as _,
            false as _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(event_handle)
        }
    }
}

pub fn FileOpen(path: &str) -> Result<HANDLE> {
    unsafe {
        let nt_path = format!("\\??\\{}", path);
        let nt_path = U16CString::from_str(nt_path).unwrap();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: &mut to_unicode_string(&nt_path) as *mut _ as *mut _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let mut io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let mut file_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtCreateFile.unwrap()(
            &mut file_handle,
            FILE_GENERIC_READ,
            &mut object_attributes,
            &mut io_status_block as *mut _ as *mut _,
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            ntioapi::FILE_OPEN,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(file_handle)
        }
    }
}

pub fn FileCreate(
    path: &str,
    access_mask: u32,
    share_access: u32,
    size: usize,
) -> Result<HANDLE> {
    unsafe {
        let nt_path = format!("\\??\\{}", path);
        let nt_path = U16CString::from_str(nt_path).unwrap();

        let mut object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ObjectName: &mut to_unicode_string(&nt_path) as *mut _ as *mut _,
            Attributes: ntdef::OBJ_CASE_INSENSITIVE,
            ..Default::default()
        };

        let mut io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let mut file_handle: HANDLE = ptr::null_mut();

        let mut allocation_size = ntwin::LARGE_INTEGER::default();
        allocation_size.bindgen_union_field = size as u64;

        let status = NTSTATUS(api_ctx::ntdll().NtCreateFile.unwrap()(
            &mut file_handle,
            access_mask,
            &mut object_attributes,
            &mut io_status_block as *mut _ as *mut _,
            &mut allocation_size,
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            ntioapi::FILE_OVERWRITE_IF,
            ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null_mut(),
            0,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(file_handle)
        }
    }
}

pub fn FileWrite(file_handle: HANDLE, data: PVOID, size: usize) -> Result<bool> {
    unsafe {
        let mut io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let status = NTSTATUS(api_ctx::ntdll().NtWriteFile.unwrap()(
            file_handle,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut io_status_block as *mut _ as *mut _,
            data,
            size as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(io_status_block.Information == size)
        }
    }
}

pub fn FileGetSize(file_handle: HANDLE) -> Result<usize> {
    unsafe {
        let mut io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let mut file_information = ntioapi::FILE_STANDARD_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationFile.unwrap()(
            file_handle,
            &mut io_status_block as *mut _ as *mut _,
            &mut file_information as *mut _ as *mut _,
            size_of::<ntioapi::FILE_STANDARD_INFORMATION>() as u32,
            ntioapi::FILE_INFORMATION_CLASS::FileStandardInformation,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(file_information.EndOfFile.bindgen_union_field as usize)
        }
    }
}

pub fn AdjustPrivilege(privilege: u32) -> Result<()> {
    unsafe {
        let mut was_enabled: bool = false;

        let status = NTSTATUS(api_ctx::ntdll().RtlAdjustPrivilege.unwrap()(
            privilege,
            true as _,
            false as _,
            &mut was_enabled as *mut _ as *mut _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn GetModuleHandle(module_name: &CStr) -> Option<HANDLE> {
    unsafe {
        let module_handle = GetModuleHandleA(module_name.as_ptr() as _);

        if module_handle.is_null() {
            None
        } else {
            Some(module_handle)
        }
    }
}

pub fn LoadLibraryCopy(module_path: &str) -> Result<HMODULE> {
    unsafe {
        let temp_folder = PathBuf::from(
            to_u16cstring(&(*(*Peb()).ProcessParameters).CurrentDirectory.DosPath).to_string_lossy()
        );

        let module_path_buf = PathBuf::from(&module_path);
        let module_name = module_path_buf.file_name().unwrap();
        let temp_module_path = temp_folder.join(module_name).to_string_lossy().into_owned();

        {
            let (handle, section_handle, src_data) = crate::fs::map_file(&module_path)?;
            let _ = HandleWrap(handle);
            let _ = HandleWrap(section_handle);

            let file_mode = crate::fs::FsFileMode::ReadWrite;
            let module_copy_handle = HandleWrap(FileCreate(
                &temp_module_path,
                file_mode.access_rights(),
                file_mode.share_mode(),
                src_data.len())?
            );
            let module_copy_section_handle = HandleWrap(SectionFileCreate(
                *module_copy_handle,
                SECTION_ALL_ACCESS,
                PAGE_READWRITE,
                false,
                Some(src_data.len()))?
            );

            let module_copy_data = SectionMapView(
                *module_copy_section_handle,
                src_data.len(),
                PAGE_READWRITE,
                NT_CURRENT_PROCESS,
                ptr::null_mut(),
            )?;

            let dst_data = slice::from_raw_parts_mut(module_copy_data as *mut u8, src_data.len());

            dst_data.copy_from_slice(src_data);

            SectionUnmapView(src_data.as_ptr() as _, NT_CURRENT_PROCESS)?;
            SectionUnmapView(dst_data.as_ptr() as _, NT_CURRENT_PROCESS)?;
        }

        let hr = HMODULE(LoadLibraryA(CString::new(temp_module_path).unwrap().into_raw() as _));
        if hr.is_invalid() {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(hr)
        }
    }
}

pub fn DumpLiveSystem(
    file_handle: HANDLE,
) -> Result<()> {
    unsafe {
        if AdjustPrivilege(ntseapi::SE_DEBUG_PRIVILEGE).is_err() {
            return Err(NTSTATUS(ntstatus::STATUS_PRIVILEGE_NOT_HELD));
        }

        let mut live_dump_control = ntexapi::SYSDBG_LIVEDUMP_CONTROL::default();
        live_dump_control.Version = 1;
        live_dump_control.BugCheckCode = 0x161;
        live_dump_control.DumpFileHandle = file_handle;
        // live_dump_control.Flags.CompressMemoryPagesData = 1;
        // live_dump_control.Flags.IncludeUserSpaceMemoryPages = 1;
        live_dump_control.Flags.bindgen_union_field = 6;

        let status = NTSTATUS(api_ctx::ntdll().NtSystemDebugControl.unwrap()(
            ntexapi::SYSDBG_COMMAND::SysDbgGetLiveKernelDump,
            addr_of!(live_dump_control) as _,
            offset_of!(ntexapi::SYSDBG_LIVEDUMP_CONTROL, SelectiveControl) as _,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(())
        }
    }
}
