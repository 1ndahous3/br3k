use crate::prelude::*;
use crate::str::*;
use crate::fs;

use crate::sysapi_ctx::SysApiCtx as api_ctx;
use crate::unique_resource::*;

use path::PathBuf;
use collections::HashMap;

use windows::Win32::Foundation::{HMODULE, NTSTATUS};
use windows::Win32::System::Environment::GetCurrentDirectoryW;
use windows_sys::Win32::Foundation::{HANDLE, HWND, FALSE};
use windows_sys::Win32::System::Diagnostics::Debug::{CONTEXT, WOW64_CONTEXT};
use windows_sys::Win32::System::Threading::{
    EVENT_ALL_ACCESS, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
};
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_GUARD,
    PAGE_PROTECTION_FLAGS, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, SEC_COMMIT, SEC_IMAGE,
    SECTION_FLAGS, SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_ALL_ACCESS
};
use windows_sys::Win32::Storage::FileSystem::{
    SYNCHRONIZE,
    FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_DATA, FILE_WRITE_DATA,
    FILE_SHARE_READ, FILE_SHARE_WRITE
};

use windef::*;
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

pub fn close_handle(handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtClose.unwrap()(handle));
        status.is_ok().then_some(()).ok_or(status)
    }
}

pub fn duplicate_handle(
    target_process_handle: HANDLE,
    source_handle: HANDLE,
    source_process_handle: HANDLE,
) -> Result<UniqueHandle> {
    unsafe {
        let target_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtDuplicateObject.unwrap()(
            source_process_handle,
            source_handle,
            target_process_handle,
            addr_of!(target_handle) as _,
            0,
            0,
            winbase::DUPLICATE_SAME_ACCESS,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(target_handle))
        }
    }
}

fn wrap_handle(handle: HANDLE) -> UniqueHandle {
    fn handle_close_deleter(handle: HANDLE) {
        let _ = close_handle(handle);
    }
    UniqueResource::new(handle, handle_close_deleter)
}

pub fn null_handle() -> UniqueHandle {
    fn handle_close_deleter(handle: HANDLE) {
        let _ = close_handle(handle);
    }
    UniqueResource::new(ptr::null_mut(), handle_close_deleter)
}

pub fn peb() -> ntpebteb::PPEB {
    #[cfg(target_pointer_width = "64")]
    {
        unsafe {
            let peb: u64;
            arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            peb as _
        }
    }
    #[cfg(target_pointer_width = "32")]
    {
        unsafe {
            let peb: u32;
            arch::asm!("mov {}, fs:[0x30]", out(reg) peb);
            peb as _
        }
    }
}

pub fn teb() -> ntexapi::PTEB {
    #[cfg(target_pointer_width = "64")]
    {
        unsafe {
            let teb: u64;
            arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
            teb as _
        }
    }
    #[cfg(target_pointer_width = "32")]
    {
        unsafe {
            let peb: u32;
            arch::asm!("mov {}, fs:[0x18]", out(reg) teb);
            teb as _
        }
    }
}

pub type UniqueProcessParameters = UniqueResource<
    ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
    fn(ntpebteb::PRTL_USER_PROCESS_PARAMETERS),
>;

pub fn create_process_parameters(
    name: &str,
) -> Result<UniqueProcessParameters> {
    unsafe {
        let nt_name = format!("\\??\\{name}");
        let nt_name = U16CString::from_str(nt_name).unwrap();
        let nt_name = to_unicode_string(&nt_name);

        let mut current_directory = [0u16; winbase::MAX_PATH];
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_process_parameters(process_parameters))
        }
    }
}

pub fn destroy_process_parameters(process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS) {
    unsafe {
        api_ctx::ntdll().RtlDestroyProcessParameters.unwrap()(process_parameters);
    }
}
fn wrap_process_parameters(
    process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
) -> UniqueProcessParameters {
    fn process_parameters_destroy_deleter(
        process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS,
    ) {
        destroy_process_parameters(process_parameters);
    }
    UniqueResource::new(process_parameters, process_parameters_destroy_deleter)
}

// ProcessHandle, ThreadHandle
pub fn create_user_process(name: &str, suspended: bool) -> Result<(UniqueHandle, UniqueHandle)> {
    unsafe {
        let nt_name = format!("\\??\\{name}");
        let nt_name = U16CString::from_str(nt_name).unwrap();
        let nt_name = to_unicode_string(&nt_name);

        let process_parameters: ntpebteb::PRTL_USER_PROCESS_PARAMETERS = ptr::null_mut();
        let status = NTSTATUS(api_ctx::ntdll().RtlCreateProcessParametersEx.unwrap()(
            addr_of!(process_parameters) as _,
            addr_of!(nt_name) as _,
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

        let create_info = ntpsapi::PS_CREATE_INFO {
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

        attribute_list.Attributes[0].Attribute = winbase::PS_ATTRIBUTE_IMAGE_NAME as _;
        attribute_list.Attributes[0].Size = nt_name.Length as _;
        attribute_list.Attributes[0].a1.bindgen_union_field = nt_name.Buffer as _;

        let process_handle: HANDLE = ptr::null_mut();
        let thread_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtCreateUserProcess.unwrap()(
            addr_of!(process_handle) as _,
            addr_of!(thread_handle) as _,
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
            process_parameters as _,
            addr_of!(create_info) as _,
            addr_of!(attribute_list) as _,
        ));

        destroy_process_parameters(process_parameters);

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_OBJECT_PATH_INVALID {
                log::warn!(
                    "the process \"{name}\" probably has an IFEO key without a 'Debugger' value"
                );
            }

            Err(status)
        } else {
            Ok((wrap_handle(process_handle), wrap_handle(thread_handle)))
        }
    }
}

pub fn create_process(section_handle: HANDLE) -> Result<UniqueHandle> {
    unsafe {
        let process_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status: NTSTATUS = if api_ctx::ntdll().NtCreateProcess.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateProcess.unwrap()(
                addr_of!(process_handle) as _,
                PROCESS_ALL_ACCESS,
                addr_of!(object_attributes) as _,
                NT_CURRENT_PROCESS,
                true.into(),
                section_handle,
                ptr::null_mut(),
                ptr::null_mut(),
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateProcessEx.unwrap()(
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
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(process_handle))
        }
    }
}

pub fn get_process_basic_info(
    process_handle: HANDLE,
) -> Result<ntpsapi::PROCESS_BASIC_INFORMATION> {
    unsafe {
        let basic_info = ntpsapi::PROCESS_BASIC_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationProcess.unwrap()(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessBasicInformation,
            addr_of!(basic_info) as _,
            size_of::<ntpsapi::PROCESS_BASIC_INFORMATION>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(basic_info)
        }
    }
}

pub fn get_process_wow64_info(process_handle: HANDLE) -> Result<bool> {
    unsafe {
        let wow64_info: usize = 0;

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationProcess.unwrap()(
            process_handle,
            ntpsapi::PROCESSINFOCLASS::ProcessWow64Information,
            addr_of!(wow64_info) as _,
            size_of::<usize>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wow64_info == 0)
        }
    }
}

pub fn find_process(name: &str) -> Result<u32> {
    unsafe {
        let entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as _,
            ..Default::default()
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL));
        }

        if Process32FirstW(snapshot, addr_of!(entry) as _) == 0 {
            return Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND));
        }

        let mut pid = 0;
        loop {
            if Process32NextW(snapshot, addr_of!(entry) as _) == 0 {
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

pub fn get_processes_pid_name() -> Result<HashMap<u32, String>> {
    unsafe {
        let entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as _,
            ..Default::default()
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot.is_null() {
            return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL));
        }

        if Process32FirstW(snapshot, addr_of!(entry) as _) == 0 {
            return Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND));
        }

        let mut res = HashMap::<u32, String>::new();

        loop {
            if Process32NextW(snapshot, addr_of!(entry) as _) == 0 {
                break;
            }

            let exe_name_u = U16CString::from_ptr_str(entry.szExeFile.as_ptr());
            res.entry(entry.th32ProcessID).insert_entry(exe_name_u.to_string_lossy());
        }

        Ok(res)
    }
}

pub fn open_process_by_hwnd(
    hwnd: HWND,
    access_mask: winbase::ACCESS_MASK,
) -> Result<UniqueHandle> {
    unsafe {
        let process_handle =
            api_ctx::win32u().NtUserGetWindowProcessHandle.unwrap()(hwnd, access_mask);
        if process_handle.is_null() {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(wrap_handle(process_handle))
        }
    }
}

pub fn open_process(pid: u32, access_mask: u32) -> Result<UniqueHandle> {
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

        let status = NTSTATUS(api_ctx::ntdll().NtOpenProcess.unwrap()(
            addr_of!(process_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(client_id) as _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(process_handle))
        }
    }
}

pub fn open_next_thread(
    process_handle: HANDLE,
    thread_handle: HANDLE,
    access_mask: winbase::ACCESS_MASK,
) -> Result<UniqueHandle> {
    unsafe {
        let new_thread_handle: HANDLE = ptr::null_mut();

        let status = NTSTATUS(api_ctx::ntdll().NtGetNextThread.unwrap()(
            process_handle,
            thread_handle,
            access_mask,
            0,
            0,
            addr_of!(new_thread_handle) as _,
        ));

        if !status.is_ok() {
            if status.0 != ntstatus::STATUS_NO_MORE_ENTRIES {
                return Err(status);
            }

            return Ok(wrap_handle(new_thread_handle));
        }

        Ok(wrap_handle(new_thread_handle))
    }
}

pub fn open_thread(
    pid: u32,
    tid: u32,
    access_mask: winbase::ACCESS_MASK,
) -> Result<UniqueHandle> {
    unsafe {
        let thread_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let client_id = ntdef::CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: tid as _,
        };

        let status = NTSTATUS(api_ctx::ntdll().NtOpenThread.unwrap()(
            addr_of!(thread_handle) as _,
            access_mask,
            addr_of!(object_attributes) as _,
            addr_of!(client_id) as _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(thread_handle))
        }
    }
}

fn create_thread_stack(
    process_handle: HANDLE,
    initial_teb: ntpsapi::PINITIAL_TEB,
) -> Result<()> {
    unsafe {
        let sys_info = ntexapi::SYSTEM_BASIC_INFORMATION {
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtQuerySystemInformation.unwrap()(
            ntexapi::SYSTEM_INFORMATION_CLASS::SystemBasicInformation,
            addr_of!(sys_info) as _,
            size_of::<ntexapi::SYSTEM_BASIC_INFORMATION>() as _,
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

pub fn create_thread(
    process_handle: HANDLE,
    start_address: PVOID,
    arg: Option<PVOID>,
) -> Result<UniqueHandle> {
    unsafe {
        let thread_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status = if api_ctx::ntdll().NtCreateThread.is_some() {
            if arg.is_some() {
                return Err(NTSTATUS(ntstatus::STATUS_NOT_IMPLEMENTED));
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

            NTSTATUS(api_ctx::ntdll().NtCreateThread.unwrap()(
                addr_of!(thread_handle) as _,
                THREAD_ALL_ACCESS,
                addr_of!(object_attributes) as _,
                process_handle,
                client_id as _,
                context as _,
                initial_teb as _,
                false as _,
            ))
        } else {
            let arg = arg.unwrap_or(ptr::null_mut());

            NTSTATUS(api_ctx::ntdll().NtCreateThreadEx.unwrap()(
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
        };

        if !status.is_ok() {
            if status.0 == ntstatus::STATUS_ACCESS_DENIED {
                log::warn!("the target process probably has a 'ControlFlowGuard' protection");
            }

            Err(status)
        } else {
            Ok(wrap_handle(thread_handle))
        }
    }
}

pub fn suspend_thread(thread_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtSuspendThread.unwrap()(
            thread_handle,
            ptr::null_mut(),
        ));
        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn resume_thread(thread_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtResumeThread.unwrap()(
            thread_handle,
            ptr::null_mut(),
        ));
        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn get_thread_basic_info(
    thread_handle: HANDLE,
) -> Result<ntpsapi::THREAD_BASIC_INFORMATION> {
    unsafe {
        let basic_info = ntpsapi::THREAD_BASIC_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadBasicInformation,
            addr_of!(basic_info) as _,
            size_of::<ntpsapi::THREAD_BASIC_INFORMATION>() as _,
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

pub fn get_thread_context(thread_handle: HANDLE) -> Result<CONTEXT> {
    unsafe {
        let mut context = AlignedContext::default();
        context.ctx.ContextFlags = winbase::CONTEXT_FULL;

        let status = NTSTATUS(api_ctx::ntdll().NtGetContextThread.unwrap()(
            thread_handle,
            addr_of!(context) as _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(context.ctx)
        }
    }
}

pub fn get_thread_wow64_context(thread_handle: HANDLE) -> Result<WOW64_CONTEXT> {
    unsafe {
        let context = AlignedWow64Context::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            addr_of!(context) as _,
            size_of::<AlignedWow64Context>() as _,
            ptr::null_mut(),
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(context.ctx)
        }
    }
}

pub fn set_thread_context(thread_handle: HANDLE, ctx: &CONTEXT) -> Result<()> {
    unsafe {
        let context = AlignedContext { ctx: *ctx };

        let status = NTSTATUS(api_ctx::ntdll().NtSetContextThread.unwrap()(
            thread_handle,
            addr_of!(context) as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn set_thread_wow64_context(thread_handle: HANDLE, ctx: &WOW64_CONTEXT) -> Result<()> {
    unsafe {
        let context = AlignedWow64Context { ctx: *ctx };

        let status = NTSTATUS(api_ctx::ntdll().NtSetInformationThread.unwrap()(
            thread_handle,
            ntpsapi::THREADINFOCLASS::ThreadWow64Context,
            addr_of!(context) as _,
            size_of::<AlignedWow64Context>() as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn allocate_virtual_memory(
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
    allocation_type: ULONG,
) -> Result<PVOID> {
    unsafe {

        let status = if api_ctx::ntdll().NtAllocateVirtualMemoryEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtAllocateVirtualMemoryEx.unwrap()(
                process_handle,
                addr_of!(base_address) as _,
                addr_of!(size) as _,
                allocation_type,
                protect,
                ptr::null_mut(),
                0,
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtAllocateVirtualMemory.unwrap()(
                process_handle,
                addr_of!(base_address) as _,
                0,
                addr_of!(size) as _,
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

pub fn create_section(size: usize) -> Result<UniqueHandle> {
    unsafe {
        let section_handle: HANDLE = ptr::null_mut();

        let maximum_size = ntwin::LARGE_INTEGER {
            bindgen_union_field: size as _,
            ..Default::default()
        };

        let status = if api_ctx::ntdll().NtCreateSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateSectionEx.unwrap()(
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
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateSection.unwrap()(
                addr_of!(section_handle) as _,
                SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                ptr::null_mut(),
                addr_of!(maximum_size) as _,
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT,
                ptr::null_mut(),
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(section_handle))
        }
    }
}

pub fn create_file_section(
    file_handle: HANDLE,
    access_mask: u32,
    protection: SECTION_FLAGS,
    as_image: bool,
    size: Option<usize>,
) -> Result<UniqueHandle> {
    unsafe {
        let section_handle: HANDLE = ptr::null_mut();

        let mut maximum_size = ntwin::LARGE_INTEGER::default();
        if let Some(size) = size {
            maximum_size.bindgen_union_field = size as _;
        }

        let status = if api_ctx::ntdll().NtCreateSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtCreateSectionEx.unwrap()(
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
        } else {
            NTSTATUS(api_ctx::ntdll().NtCreateSection.unwrap()(
                addr_of!(section_handle) as _,
                access_mask,
                ptr::null_mut(),
                addr_of!(maximum_size) as _,
                protection,
                if as_image { SEC_IMAGE } else { SEC_COMMIT },
                file_handle,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(section_handle))
        }
    }
}

pub fn map_view_of_section(
    section_handle: HANDLE,
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
    base_address: PVOID,
) -> Result<PVOID> {
    unsafe {

        let status = if api_ctx::ntdll().NtMapViewOfSectionEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtMapViewOfSectionEx.unwrap()(
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
        } else {
            NTSTATUS(api_ctx::ntdll().NtMapViewOfSection.unwrap()(
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
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(base_address)
        }
    }
}

pub fn unmap_view_of_section(
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

pub fn protect_virtual_memory(
    base_address: PVOID,
    size: usize,
    protect: PAGE_PROTECTION_FLAGS,
    process_handle: HANDLE,
) -> Result<()> {
    unsafe {

        let new_protect = protect;

        let status = NTSTATUS(api_ctx::ntdll().NtProtectVirtualMemory.unwrap()(
            process_handle,
            addr_of!(base_address) as _,
            addr_of!(size) as _,
            protect,
            addr_of!(new_protect) as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn write_virtual_memory<T>(
    buffer: T,
    base_address: PVOID,
    process_handle: HANDLE,
) -> Result<()>
where
    T: AsRef<[u8]>,
{
    unsafe {
        let slice = buffer.as_ref();
        let data = slice.as_ptr() as PVOID;
        let size = slice.len();

        let number_of_bytes_written: usize = 0;

        let status = NTSTATUS(api_ctx::ntdll().NtWriteVirtualMemory.unwrap()(
            process_handle,
            base_address,
            data,
            size,
            addr_of!(number_of_bytes_written) as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn read_virtual_memory<T>(
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

        let number_of_bytes_read: usize = 0;

        let status = if api_ctx::ntdll().NtReadVirtualMemoryEx.is_some() {
            NTSTATUS(api_ctx::ntdll().NtReadVirtualMemoryEx.unwrap()(
                process_handle,
                base_address,
                data,
                size,
                addr_of!(number_of_bytes_read) as _,
                0, //
            ))
        } else {
            NTSTATUS(api_ctx::ntdll().NtReadVirtualMemory.unwrap()(
                process_handle,
                base_address,
                data,
                size,
                addr_of!(number_of_bytes_read) as _,
            ))
        };

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(number_of_bytes_read)
        }
    }
}

pub fn create_transaction(path: &str) -> Result<UniqueHandle> {
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

        let status = NTSTATUS(api_ctx::ntdll().NtCreateTransaction.unwrap()(
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(transaction_handle))
        }
    }
}

pub fn rollback_transaction(transaction_handle: HANDLE) -> Result<()> {
    unsafe {
        let status = NTSTATUS(api_ctx::ntdll().NtRollbackTransaction.unwrap()(
            transaction_handle,
            true as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn set_transaction(transaction_handle: HANDLE) -> Result<()> {
    unsafe {
        let res = api_ctx::ntdll().RtlSetCurrentTransaction.unwrap()(transaction_handle);

        if res == 0 {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(())
        }
    }
}

pub fn queue_apc_thread(
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

pub fn create_event() -> Result<UniqueHandle> {
    unsafe {
        let event_handle: HANDLE = ptr::null_mut();

        let object_attributes = winbase::OBJECT_ATTRIBUTES {
            Length: size_of::<winbase::OBJECT_ATTRIBUTES>() as _,
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtCreateEvent.unwrap()(
            addr_of!(event_handle) as _,
            EVENT_ALL_ACCESS,
            addr_of!(object_attributes) as _,
            ntdef::EVENT_TYPE::NotificationEvent as _,
            false as _,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(event_handle))
        }
    }
}

pub fn create_named_pipe(name: &str, sd: PVOID) -> Result<UniqueHandle> {
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

        let mut default_timeout: ntwin::LARGE_INTEGER = mem::zeroed();
        default_timeout.bindgen_union_field = -1200000000 as _; // 120 seconds

        let status = NTSTATUS(api_ctx::ntdll().NtCreateNamedPipeFile.unwrap()(
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
            addr_of!(default_timeout) as _
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(file_handle))
        }
    }
}

pub fn open_named_pipe(name: &str) -> Result<UniqueHandle> {
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

        let status = NTSTATUS(api_ctx::ntdll().NtCreateFile.unwrap()(
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(file_handle))
        }
    }
}

pub fn open_file(path: &str) -> Result<UniqueHandle> {
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

        let status = NTSTATUS(api_ctx::ntdll().NtCreateFile.unwrap()(
            addr_of!(file_handle) as _,
            FILE_GENERIC_READ,
            addr_of!(object_attributes) as _,
            addr_of!(io_status_block) as _,
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
            Ok(wrap_handle(file_handle))
        }
    }
}

pub fn create_file(
    path: &str,
    access_mask: u32,
    share_access: u32,
    size: usize,
) -> Result<UniqueHandle> {
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

        let allocation_size = ntwin::LARGE_INTEGER {
            bindgen_union_field: size as _,
            ..Default::default()
        };

        let status = NTSTATUS(api_ctx::ntdll().NtCreateFile.unwrap()(
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(wrap_handle(file_handle))
        }
    }
}

pub fn write_file(file_handle: HANDLE, data: PVOID, size: usize) -> Result<bool> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let status = NTSTATUS(api_ctx::ntdll().NtWriteFile.unwrap()(
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(io_status_block.Information == size)
        }
    }
}

pub fn read_file(file_handle: HANDLE, data: PVOID, size: usize) -> Result<bool> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();

        let status = NTSTATUS(api_ctx::ntdll().NtReadFile.unwrap()(
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

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(io_status_block.Information == size)
        }
    }
}

pub fn get_file_size(file_handle: HANDLE) -> Result<usize> {
    unsafe {
        let io_status_block = ntioapi::IO_STATUS_BLOCK::default();
        let file_information = ntioapi::FILE_STANDARD_INFORMATION::default();

        let status = NTSTATUS(api_ctx::ntdll().NtQueryInformationFile.unwrap()(
            file_handle,
            addr_of!(io_status_block) as _,
            addr_of!(file_information) as _,
            size_of::<ntioapi::FILE_STANDARD_INFORMATION>() as _,
            ntioapi::FILE_INFORMATION_CLASS::FileStandardInformation,
        ));

        if !status.is_ok() {
            Err(status)
        } else {
            Ok(file_information.EndOfFile.bindgen_union_field as _)
        }
    }
}

pub fn adjust_privilege(privilege: u32) -> Result<()> {
    unsafe {
        let was_enabled: bool = false;

        let status = NTSTATUS(api_ctx::ntdll().RtlAdjustPrivilege.unwrap()(
            privilege,
            true as _,
            false as _,
            addr_of!(was_enabled) as _,
        ));

        if !status.is_ok() { Err(status) } else { Ok(()) }
    }
}

pub fn load_library_copy(module_path: &str) -> Result<HMODULE> {
    unsafe {
        let temp_folder = PathBuf::from(
            to_u16cstring(&(*(*peb()).ProcessParameters).CurrentDirectory.DosPath).to_string_lossy()
        );

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
        if hr.is_invalid() {
            Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL))
        } else {
            Ok(hr)
        }
    }
}

pub fn dump_live_system(
    file_handle: HANDLE,
) -> Result<()> {
    unsafe {
        if adjust_privilege(ntseapi::SE_DEBUG_PRIVILEGE).is_err() {
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

pub fn get_process_handles(pid: u32) -> Result<Vec<HANDLE>> {
    unsafe {
        let data_size: ULONG = 0;
        let mut data = Vec::<u8>::new();

        loop {
            let status = NTSTATUS(api_ctx::ntdll().NtQuerySystemInformation.unwrap()(
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

            return Err(status);
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

pub fn get_handle_info(handle: HANDLE) -> Result<(String, String)> {
    unsafe {
        let data_size: ULONG = 0;
        let mut data = Vec::<u8>::new();

        loop {
            let status = NTSTATUS(api_ctx::ntdll().NtQueryObject.unwrap()(
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

            return Err(status);
        }

        let info = data.as_ptr() as ntobapi::POBJECT_NAME_INFORMATION;
        let name = (*info).Name.to_u16cstring();

        loop {
            let status = NTSTATUS(api_ctx::ntdll().NtQueryObject.unwrap()(
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

            return Err(status);
        }

        let info = data.as_ptr() as ntobapi::POBJECT_TYPE_INFORMATION;
        let type_name = (*info).TypeName.to_u16cstring();

        Ok((
            name.to_string_lossy().to_string(),
            type_name.to_string_lossy().to_string()
        ))
    }
}

pub fn process_open_alertable_thread(process_handle: HANDLE) -> Result<UniqueHandle> {
    unsafe {
        let mut thread_handle = open_next_thread(
            process_handle,
            ptr::null_mut(),
            THREAD_ALL_ACCESS,
        )?;

        let nt_set_event_addr =
            api_ctx::get_proc_address("ntdll.dll", "NtSetEvent").map_err(|_| {
                log::error!("unable to find NtSetEvent address");
                NTSTATUS(ntstatus::STATUS_PROCEDURE_NOT_FOUND)
            })?;

        while !thread_handle.is_null() {

            let local_event = create_event()?;

            let remote_event =
                match duplicate_handle(process_handle, *local_event, NT_CURRENT_PROCESS) {
                    Ok(event) => event,
                    Err(_) => {
                        thread_handle = open_next_thread(
                            process_handle,
                            *thread_handle,
                            THREAD_ALL_ACCESS,
                        )?;
                        continue;
                    }
                };

            if suspend_thread(*thread_handle).is_err() {
                thread_handle = open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            if queue_apc_thread(
                *thread_handle,
                nt_set_event_addr as _,
                *remote_event,
                ptr::null_mut(),
                ptr::null_mut(),
            )
                .is_err()
            {
                thread_handle = open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            if resume_thread(*thread_handle).is_err() {
                thread_handle = open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            let mut timeout = ntwin::LARGE_INTEGER {
                bindgen_union_field: (-10_000_000i64) as u64,
                ..Default::default()
            };

            let status = NTSTATUS(ntobapi::NtWaitForSingleObject(
                *local_event,
                FALSE as _,
                &mut timeout,
            ));
            if status.is_err() {
                log::error!("unable to wait for event, {}", status.0);
                thread_handle = open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            if status.0 == ntstatus::STATUS_TIMEOUT {
                log::debug!(
                    "probably not an alertable thread (HANDLE = 0x{:x})",
                    *thread_handle as usize
                );
                thread_handle = open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            log::debug!(
                "alertable thread found, HANDLE = 0x{:x}",
                *thread_handle as usize
            );
            return Ok(thread_handle);
        }

        log::error!(
            "unable to find alertable thread, process (HANDLE = 0x{:x})",
            *thread_handle as usize
        );

        Err(NTSTATUS(ntstatus::STATUS_NOT_FOUND))
    }
}

pub fn process_enumerate_threads<F>(process_handle: HANDLE, f: F) -> Result<()>
where
    F: Fn(HANDLE)-> bool,
{
    let mut thread_handle = open_next_thread(
        process_handle,
        ptr::null_mut(),
        THREAD_ALL_ACCESS,
    )?;

    while !thread_handle.is_null() {

        if !f(*thread_handle.get()) {
            break;
        }

        thread_handle = open_next_thread(
            process_handle,
            *thread_handle,
            THREAD_ALL_ACCESS,
        )?;
    }

    Ok(())
}
