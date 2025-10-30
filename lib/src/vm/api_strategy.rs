use crate::prelude::*;
use crate::fs;
use crate::pdb;
use crate::kdump;
use crate::sysapi;
use crate::sysapi_ctx::SysApiCtx as api_ctx;

use path::PathBuf;
use sync::Arc;
use exe::PtrPE;

use windef::{winbase, ntstatus, ntwin, ntobapi};
use winbase::{ACCESS_MASK, NT_CURRENT_PROCESS};

use windows::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::{FALSE, HANDLE, HWND, TRUE};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    PAGE_EXECUTE_READWRITE
};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId};
use windows_sys::Win32::System::Threading::{
    PROCESS_DUP_HANDLE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_ALL_ACCESS,
};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

use sysapi::UniqueHandle;

#[repr(u32)]
#[derive(Debug, Clone, VariantArray, FromRepr, IntoStaticStr)]
pub enum ProcessVmStrategy {
    AllocateInAddr,
    CreateSectionMap,
    CreateSectionMapLocalMap,
    LiveDumpParse,
}

impl fmt::Display for ProcessVmStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub enum ProcessMemory {
    AllocateInAddr {
        handle: HANDLE,
        base_addr_remote: PVOID,
    },
    CreateSectionMap {
        handle: HANDLE,
        section: HANDLE,
        base_addr_remote: PVOID,
    },
    CreateSectionMapLocalMap {
        handle: HANDLE,
        section: HANDLE,
        base_addr_remote: PVOID,
        base_addr_local: PVOID,
    },
    LiveDumpParse { // RO
        base_addr_remote: PVOID,
        kdump: Arc<kdump::KernelDump>,
        kdump_process: kdump::Process,
    },
}

impl ProcessMemory {
    pub fn init_allocate_in_addr(handle: HANDLE) -> Result<Self, ()> {
        Ok(ProcessMemory::AllocateInAddr {
            handle,
            base_addr_remote: ptr::null_mut(),
        })
    }

    pub fn init_create_section_map(handle: HANDLE) -> Result<Self, ()> {
        Ok(ProcessMemory::CreateSectionMap {
            handle,
            section: ptr::null_mut(),
            base_addr_remote: ptr::null_mut(),
        })
    }

    pub fn init_create_section_map_local_map(handle: HANDLE) -> Result<Self, ()> {
        Ok(ProcessMemory::CreateSectionMapLocalMap {
            handle,
            section: ptr::null_mut(),
            base_addr_remote: ptr::null_mut(),
            base_addr_local: ptr::null_mut(),
        })
    }

    pub fn init_live_dump_parse(pid: u32) -> Result<Self, ()> {

        let dump_filepath = PathBuf::from(fs::get_temp_folder()).join("system.dmp");
        let dump_filepath = dump_filepath.to_str().unwrap();

        {
            let file_mode = fs::FsFileMode::Write;
            let dump_file = sysapi::create_file(
                dump_filepath,
                file_mode.access_rights(),
                file_mode.share_mode(),
                0
            ).map_err(|e| {
                log::error!("Failed to create dump file: {}", sysapi::ntstatus_decode(e));
            });

            sysapi::dump_live_system(*dump_file.unwrap()).map_err(|e| {
                log::error!("Failed to dump live system: {}", sysapi::ntstatus_decode(e));
            })?;
        }

        let (_, _, src_data) = fs::map_file(
            "c:\\windows\\system32\\ntoskrnl.exe"
        )
            .map_err(|e| {
                log::error!("Failed to map dump file: {}", sysapi::ntstatus_decode(e));
            })?;

        let kernel_pe = PtrPE::new_memory(src_data.as_ptr(), src_data.len());

        let pdb_path = pdb::download_pdb(&kernel_pe, fs::get_temp_folder().as_str())
            .map_err(|e| {
                log::error!("Failed to download PDB: {e}");
            })?;

        let mut pdb = pdb::Pdb::init(pdb_path.as_str())
            .map_err(|e| {
                log::error!("Failed to initialize PDB: {e}");
            })?;

        let kdump = kdump::KernelDump::new(dump_filepath, &mut pdb)
            .map_err(|e| {
                log::error!("Failed to parse kernel dump: {e}");
            })?;

        let processes = kdump.get_processes()
            .map_err(|e| {
                log::error!("Failed to get processes from kernel dump: {e}");
            })?;

        let process = processes.iter().find(|p| p.pid == pid);
        if process.is_none() {
            log::error!("Failed to find process with pid: {pid}");
            return Err(());
        }

        Ok(ProcessMemory::LiveDumpParse {
            base_addr_remote: ptr::null_mut(),
            kdump: Arc::new(kdump),
            kdump_process: process.unwrap().clone(),
        })
    }

    pub fn create_memory(&mut self, size: usize) -> Result<(), NTSTATUS> {
        match self {
            ProcessMemory::AllocateInAddr {
                handle,
                base_addr_remote,
            } => {
                *base_addr_remote = sysapi::allocate_virtual_memory(
                    size,
                    PAGE_EXECUTE_READWRITE,
                    *handle,
                    *base_addr_remote,
                    MEM_COMMIT | MEM_RESERVE,
                )?;

                Ok(())
            }
            ProcessMemory::CreateSectionMap {
                handle,
                section,
                base_addr_remote,
            } => {
                *section = sysapi::create_section(size)?.release();
                *base_addr_remote = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    *handle,
                    *base_addr_remote,
                )?;

                Ok(())
            }
            ProcessMemory::CreateSectionMapLocalMap {
                handle,
                section,
                base_addr_remote,
                base_addr_local,
            } => {
                *section = sysapi::create_section(size)?.release();
                *base_addr_remote = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    *handle,
                    *base_addr_remote,
                )?;
                *base_addr_local = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_READWRITE,
                    NT_CURRENT_PROCESS,
                    ptr::null_mut(),
                )?;

                Ok(())
            }
            ProcessMemory::LiveDumpParse {
                ..
            } => panic!("LiveDumpParse is RO memory strategy")
        }
    }

    pub fn read_memory(
        &self,
        offset: usize,
        data: PVOID,
        size: usize,
    ) -> Result<(), NTSTATUS> {
        unsafe {
            match self {
                ProcessMemory::AllocateInAddr {
                    handle,
                    base_addr_remote,
                } => {
                    let buffer = slice::from_raw_parts_mut(data as *mut u8, size);
                    sysapi::read_virtual_memory(
                        buffer,
                        base_addr_remote.wrapping_add(offset),
                        *handle,
                    )?;

                    Ok(())
                }
                ProcessMemory::CreateSectionMap {
                    handle,
                    base_addr_remote,
                    ..
                } => {
                    let buffer = slice::from_raw_parts_mut(data as *mut u8, size);
                    sysapi::read_virtual_memory(
                        buffer,
                        base_addr_remote.wrapping_add(offset),
                        *handle,
                    )?;

                    Ok(())
                }
                ProcessMemory::CreateSectionMapLocalMap {
                    base_addr_local,
                    ..
                } => {
                    ptr::copy_nonoverlapping(
                        base_addr_local.wrapping_add(offset),
                        data,
                        size,
                    );

                    Ok(())
                }
                ProcessMemory::LiveDumpParse {
                    base_addr_remote,
                    kdump,
                    kdump_process,
                    ..
                } => {
                    let dst = slice::from_raw_parts_mut(data as *mut u8, size);
                    kdump.read_memory(dst, kdump_process, base_addr_remote.add(offset) as _)
                        .map_err(
                            |e| {
                                log::error!("Failed to read memory from kernel dump: {e}");
                                NTSTATUS(ntstatus::STATUS_INVALID_ADDRESS)
                            }
                        )?;

                    Ok(())
                }
            }
        }
    }

    pub fn write_memory(
        &self,
        offset: usize,
        data: PVOID,
        size: usize,
    ) -> Result<(), NTSTATUS> {
        match self {
            ProcessMemory::AllocateInAddr {
                handle,
                base_addr_remote,
            } => {
                unsafe {
                    let buffer = slice::from_raw_parts(data as *const u8, size);

                    sysapi::write_virtual_memory(
                        buffer,
                        base_addr_remote.wrapping_add(offset),
                        *handle,
                    )?;

                    Ok(())
                }
            }
            ProcessMemory::CreateSectionMap {
                handle,
                base_addr_remote,
                ..
            } => {
                unsafe {
                    let buffer = slice::from_raw_parts(data as *const u8, size);

                    sysapi::write_virtual_memory(
                        buffer,
                        base_addr_remote.wrapping_add(offset),
                        *handle,
                    )?;

                    Ok(())
                }
            }
            ProcessMemory::CreateSectionMapLocalMap {
                base_addr_local,
                ..
            } => {
                unsafe {
                    ptr::copy_nonoverlapping(
                        data,
                        base_addr_local.wrapping_add(offset),
                        size,
                    );
                }

                Ok(())
            }
            ProcessMemory::LiveDumpParse {
                ..
            } => {
                panic!("LiveDumpParse is RO memory strategy");
            }
        }
    }

    pub fn create_write_memory_fixup_addr(
        &mut self,
        data: PVOID,
        size: usize,
        fixup_addr_memory: Self,
        fixup_addr_offset: usize,
    ) -> Result<(), NTSTATUS> {
        self.create_memory(size)?;
        self.write_memory(0, data, size)?;

        let remote_base_addr = self.get_remote_base_addr();

        fixup_addr_memory.write_memory(
            fixup_addr_offset,
            addr_of!(remote_base_addr) as _,
            size_of::<PVOID>(),
        )?;

        Ok(())
    }

    pub fn get_remote_base_addr(&self) -> PVOID {
        match self {
            ProcessMemory::AllocateInAddr {
                base_addr_remote, ..
            } => *base_addr_remote,
            ProcessMemory::CreateSectionMap {
                base_addr_remote, ..
            } => *base_addr_remote,
            ProcessMemory::CreateSectionMapLocalMap {
                base_addr_remote, ..
            } => *base_addr_remote,
            ProcessMemory::LiveDumpParse {
                base_addr_remote, ..
            } => *base_addr_remote,
        }
    }

    pub fn set_remote_base_addr(&mut self, addr: PVOID) {
        match self {
            ProcessMemory::AllocateInAddr {
                base_addr_remote, ..
            } => {
                *base_addr_remote = addr;
            }
            ProcessMemory::CreateSectionMap {
                base_addr_remote, ..
            } => {
                *base_addr_remote = addr;
            }
            ProcessMemory::CreateSectionMapLocalMap {
                base_addr_remote, ..
            } => {
                *base_addr_remote = addr;
            }
            ProcessMemory::LiveDumpParse {
                base_addr_remote, ..
            } => {
                *base_addr_remote = addr;
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, VariantArray, FromRepr, IntoStaticStr)]
pub enum ProcessOpenStrategy {
    OpenProcess,
    OpenProcessByHwnd,
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Default)]
struct EnumWindowsProcOpts {
    pub pid: u32,   // in
    pub tid: u32,   // in
    pub hWnd: HWND, // out
}

#[allow(non_snake_case)]
extern "system" fn EnumWindowsProc(hWnd: HWND, lParam: isize) -> i32 {
    unsafe {
        let opts = &mut *(lParam as *mut EnumWindowsProcOpts);
        let mut pid: u32 = 0;

        let tid = GetWindowThreadProcessId(hWnd, &mut pid);

        if pid == opts.pid {
            opts.tid = tid;
            opts.hWnd = hWnd;
            return FALSE;
        }

        TRUE
    }
}

impl ProcessOpenStrategy {
    pub fn open(&self, pid: u32, access_mask: ACCESS_MASK) -> Result<UniqueHandle, NTSTATUS> {
        match self {
            ProcessOpenStrategy::OpenProcess => sysapi::open_process(pid, access_mask),
            ProcessOpenStrategy::OpenProcessByHwnd => {

                let mut opts = EnumWindowsProcOpts {
                    pid,
                    ..Default::default()
                };

                unsafe {
                    EnumWindows(Some(EnumWindowsProc), &mut opts as *mut _ as _);
                }

                if opts.hWnd.is_null() {
                    log::error!("Unable to find any windows for the process with PID {pid}");
                    return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL));
                }

                log::debug!("Window found, HWND = 0x{:x}", opts.hWnd as usize);

                // sysapi::ProcessOpenByHwnd(opts.hWnd, access_mask); // TODO: research access restrictions
                sysapi::open_process_by_hwnd(
                    opts.hWnd,
                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE,
                )
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, VariantArray, FromRepr, IntoStaticStr)]
pub enum ThreadOpenStrategy {
    ThreadOpenByTid,
    ThreadOpenAnyNext,
    ThreadOpenAnyByHwnd, // maybe only shell hwnd will be valid for the current process
}

#[derive(Default)]
pub struct ThreadOpenArgs {
    pub process_handle: Option<HANDLE>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
}

impl ThreadOpenStrategy {
    pub fn open(&self, args: ThreadOpenArgs, access_mask: ACCESS_MASK) -> Result<UniqueHandle, NTSTATUS> {
        match self {
            ThreadOpenStrategy::ThreadOpenByTid =>
                sysapi::open_thread(args.pid.unwrap(), args.tid.unwrap(), access_mask),
            ThreadOpenStrategy::ThreadOpenAnyNext =>
                sysapi::open_next_thread(args.process_handle.unwrap(), ptr::null_mut(), THREAD_ALL_ACCESS),
            ThreadOpenStrategy::ThreadOpenAnyByHwnd => {
                
                let pid = args.pid.unwrap();

                let mut opts = EnumWindowsProcOpts {
                    pid,
                    ..Default::default()
                };

                unsafe {
                    EnumWindows(Some(EnumWindowsProc), &mut opts as *mut _ as _);
                }

                if opts.hWnd.is_null() {
                    log::error!("Unable to find any windows for the process with PID {pid}");
                    return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL));
                }

                log::debug!("Window found, HWND = 0x{:x}", opts.hWnd as usize);
                sysapi::open_thread(opts.pid, opts.tid, access_mask)
            }
        }
    }
}

fn thread_set_ep<const IS_NEW_THREAD: bool, const IS_64: bool>(
    thread_handle: HANDLE,
    exec_address: PVOID,
) -> Result<(), NTSTATUS> {
    if IS_64 {
        let mut context = sysapi::get_thread_context(thread_handle)?;

        if IS_NEW_THREAD {
            context.Rcx = exec_address as u64;
        } else {
            context.Rip = exec_address as u64;
        }

        sysapi::set_thread_context(thread_handle, &context)?;
    } else {
        let mut context = sysapi::get_thread_wow64_context(thread_handle)?;

        if IS_NEW_THREAD {
            context.Eax = exec_address as u32;
        } else {
            context.Eip = exec_address as u32;
        }

        sysapi::set_thread_wow64_context(thread_handle, &context)?;
    }

    Ok(())
}

pub fn new_thread_set_ep_x64(
    thread_handle: HANDLE,
    exec_address: PVOID,
) -> Result<(), NTSTATUS> {
    thread_set_ep::<true, true>(thread_handle, exec_address)
}

pub fn new_thread_set_ep_x86(
    thread_handle: HANDLE,
    exec_address: PVOID,
) -> Result<(), NTSTATUS> {
    thread_set_ep::<true, false>(thread_handle, exec_address)
}

pub fn thread_set_ep_x64(
    thread_handle: HANDLE,
    exec_address: PVOID,
) -> Result<(), NTSTATUS> {
    thread_set_ep::<false, true>(thread_handle, exec_address)
}

pub fn thread_set_ep_x86(
    thread_handle: HANDLE,
    exec_address: PVOID,
) -> Result<(), NTSTATUS> {
    thread_set_ep::<false, false>(thread_handle, exec_address)
}

pub fn process_open_alertable_thread(process_handle: HANDLE) -> Result<UniqueHandle, NTSTATUS> {
    unsafe {
        let mut thread_handle = sysapi::open_next_thread(
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
            let local_event = sysapi::create_event()?;

            let remote_event =
                match sysapi::duplicate_handle(process_handle, *local_event, NT_CURRENT_PROCESS) {
                    Ok(event) => event,
                    Err(_) => {
                        thread_handle = sysapi::open_next_thread(
                            process_handle,
                            *thread_handle,
                            THREAD_ALL_ACCESS,
                        )?;
                        continue;
                    }
                };

            if sysapi::suspend_thread(*thread_handle).is_err() {
                thread_handle = sysapi::open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            if sysapi::queue_apc_thread(
                *thread_handle,
                nt_set_event_addr as _,
                *remote_event,
                ptr::null_mut(),
                ptr::null_mut(),
            )
                .is_err()
            {
                thread_handle = sysapi::open_next_thread(
                    process_handle,
                    *thread_handle,
                    THREAD_ALL_ACCESS,
                )?;
                continue;
            }

            if sysapi::resume_thread(*thread_handle).is_err() {
                thread_handle = sysapi::open_next_thread(
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
                thread_handle = sysapi::open_next_thread(
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
                thread_handle = sysapi::open_next_thread(
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
