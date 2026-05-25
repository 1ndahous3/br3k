use crate::prelude::*;

use crate::fs;
use crate::kdump;
use crate::pdb;
use crate::sysapi;

use std::fmt;
use std::path::PathBuf;
use std::result::Result;
use std::slice;
use std::sync::Arc;

use exe::PtrPE;

use winbase::{ACCESS_MASK, NT_CURRENT_PROCESS};
use windef::{ntioapi, ntstatus, winbase};

use windows::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Foundation::{FALSE, HANDLE, HWND, TRUE};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{
    PROCESS_DUP_HANDLE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_ALL_ACCESS,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray, EnumIter};
use scopeguard::ScopeGuard;

use sysapi::UniqueHandle;

#[derive(Debug, thiserror::Error)]
pub enum ProcessMemoryInitError {
    #[error("temporary dump path is not valid UTF-8")]
    TempPathNotUtf8,
    #[error(transparent)]
    NtStatus(#[from] sysapi::NtStatusError),
    #[error("failed to download PDB: {0}")]
    DownloadPdb(#[source] exe::Error),
    #[error("failed to initialize PDB: {0}")]
    InitPdb(#[source] pdb::PdbError),
    #[error("failed to parse kernel dump: {0}")]
    ParseKernelDump(#[source] kdmp_parser::error::Error),
    #[error("failed to get processes from kernel dump: {0}")]
    GetProcesses(#[source] kdmp_parser::error::Error),
    #[error("process with PID {pid} was not found in live kernel dump")]
    ProcessNotFound { pid: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessMemoryError {
    #[error(transparent)]
    NtStatus(#[from] sysapi::NtStatusError),
    #[error("{operation} requires initialized process VM read strategy")]
    MissingReadStrategy { operation: &'static str },
    #[error("{operation} requires initialized process VM write strategy")]
    MissingWriteStrategy { operation: &'static str },
    #[error("{operation} requires initialized local section map")]
    MissingLocalSectionMap { operation: &'static str },
    #[error("failed to read memory from kernel dump: {0}")]
    KernelDumpRead(#[source] kdmp_parser::error::Error),
}

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ProcessVmReadStrategy {
    ReadVirtualMemory,
    CreateSectionMap,
    CreateSectionMapLocalMap,
    LiveDumpParse,
}

impl fmt::Display for ProcessVmReadStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone)]
pub enum ProcessMemoryRead {
    ReadVirtualMemory {
        handle: HANDLE,
    },
    CreateSectionMap {
        handle: HANDLE,
    },
    CreateSectionMapLocalMap {
        base_addr_local: PVOID,
    },
    LiveDumpParse {
        kdump: Arc<kdump::KernelDump>,
        kdump_process: kdump::Process,
    },
}

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ProcessVmWriteStrategy {
    AllocateInAddr,
    CreateSectionMap,
    CreateSectionMapLocalMap,
}

impl fmt::Display for ProcessVmWriteStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum FileDeleteStrategy {
    NtDeleteFile,
    SetInformationFile,
    NtOpenFileDeleteOnClose,
    NtCreateFileDeleteOnClose,
}

impl fmt::Display for FileDeleteStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FileDeleteStrategy {
    pub fn delete_file(&self, path: &str) -> sysapi::NtResult<()> {
        match self {
            FileDeleteStrategy::NtDeleteFile => sysapi::delete_file_by_nt_delete_file(path),
            FileDeleteStrategy::SetInformationFile => sysapi::delete_file_by_set_information_file(path),
            FileDeleteStrategy::NtOpenFileDeleteOnClose => sysapi::delete_file_by_nt_open_file_delete_on_close(path),
            FileDeleteStrategy::NtCreateFileDeleteOnClose => sysapi::delete_file_by_nt_create_file_delete_on_close(path),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum FileOpenStrategy {
    NtOpenFile,
    NtCreateFile,
}

impl fmt::Display for FileOpenStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FileOpenStrategy {
    pub fn open_file(&self, path: &str, file_mode: &fs::FsFileMode) -> sysapi::NtResult<UniqueHandle> {
        let open_options = ntioapi::FILE_NON_DIRECTORY_FILE | ntioapi::FILE_SYNCHRONOUS_IO_NONALERT;

        match self {
            FileOpenStrategy::NtOpenFile => {
                sysapi::open_file_by_nt_open_file(path, file_mode.access_rights(), file_mode.share_mode(), open_options)
            }
            FileOpenStrategy::NtCreateFile => {
                sysapi::open_file_by_nt_create_file(path, file_mode.access_rights(), file_mode.share_mode(), open_options)
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum FileRenameStrategy {
    Rename,
    CopyDelete,
}

impl fmt::Display for FileRenameStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FileRenameStrategy {
    pub fn rename_file(&self, path: &str, new_path: &str) -> sysapi::NtResult<()> {
        match self {
            FileRenameStrategy::Rename => sysapi::rename_file_by_rename(path, new_path),
            FileRenameStrategy::CopyDelete => sysapi::rename_file_by_copy_delete(path, new_path),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum FileChangeStrategy {
    DeleteFile,
    OpenFile,
    CreateFileMapping,
}

impl fmt::Display for FileChangeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FileChangeStrategy {
    pub fn change_file(
        &self,
        path: &str,
        file_delete_strategy: &FileDeleteStrategy,
        file_open_strategy: &FileOpenStrategy,
    ) -> sysapi::NtResult<()> {
        match self {
            FileChangeStrategy::DeleteFile => file_delete_strategy.delete_file(path),
            FileChangeStrategy::OpenFile => sysapi::zero_file_by_open_file(
                path,
                |path| file_open_strategy.open_file(path, &fs::FsFileMode::Write)
            ),
            FileChangeStrategy::CreateFileMapping => sysapi::zero_file_by_file_mapping(path),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProcessMemoryWrite {
    AllocateInAddr {
        handle: HANDLE,
    },
    CreateSectionMap {
        handle: HANDLE,
        section: HANDLE,
    },
    CreateSectionMapLocalMap {
        handle: HANDLE,
        section: HANDLE,
        base_addr_local: PVOID,
    },
}

#[derive(Debug, Clone)]
pub struct ProcessMemory {
    base_addr_remote: PVOID,
    read: Option<ProcessMemoryRead>,
    write: Option<ProcessMemoryWrite>,
}

impl ProcessMemory {
    pub fn init(
        read_strategy: Option<&ProcessVmReadStrategy>,
        write_strategy: Option<&ProcessVmWriteStrategy>,
        handle: HANDLE,
        pid: u32,
    ) -> Result<Self, ProcessMemoryInitError> {
        let read = match read_strategy {
            Some(ProcessVmReadStrategy::ReadVirtualMemory) => Some(Self::init_read_virtual_memory(handle)),
            Some(ProcessVmReadStrategy::CreateSectionMap) => Some(Self::init_read_create_section_map(handle)),
            Some(ProcessVmReadStrategy::CreateSectionMapLocalMap) => Some(Self::init_read_create_section_map_local_map()),
            Some(ProcessVmReadStrategy::LiveDumpParse) => Some(Self::init_live_dump_parse(pid)?),
            None => None,
        };

        let write = match write_strategy {
            Some(ProcessVmWriteStrategy::AllocateInAddr) => Some(Self::init_allocate_in_addr(handle)),
            Some(ProcessVmWriteStrategy::CreateSectionMap) => Some(Self::init_create_section_map(handle)),
            Some(ProcessVmWriteStrategy::CreateSectionMapLocalMap) => Some(Self::init_create_section_map_local_map(handle)),
            None => None,
        };

        Ok(Self {
            base_addr_remote: ptr::null_mut(),
            read,
            write,
        })
    }

    fn init_read_virtual_memory(handle: HANDLE) -> ProcessMemoryRead {
        ProcessMemoryRead::ReadVirtualMemory { handle }
    }

    fn init_read_create_section_map(handle: HANDLE) -> ProcessMemoryRead {
        ProcessMemoryRead::CreateSectionMap { handle }
    }

    fn init_read_create_section_map_local_map() -> ProcessMemoryRead {
        ProcessMemoryRead::CreateSectionMapLocalMap {
            base_addr_local: ptr::null_mut(),
        }
    }

    fn init_allocate_in_addr(handle: HANDLE) -> ProcessMemoryWrite {
        ProcessMemoryWrite::AllocateInAddr { handle }
    }

    fn init_create_section_map(handle: HANDLE) -> ProcessMemoryWrite {
        ProcessMemoryWrite::CreateSectionMap {
            handle,
            section: ptr::null_mut(),
        }
    }

    fn init_create_section_map_local_map(handle: HANDLE) -> ProcessMemoryWrite {
        ProcessMemoryWrite::CreateSectionMapLocalMap {
            handle,
            section: ptr::null_mut(),
            base_addr_local: ptr::null_mut(),
        }
    }

    fn init_live_dump_parse(pid: u32) -> Result<ProcessMemoryRead, ProcessMemoryInitError> {
        let dump_filepath = PathBuf::from(fs::get_temp_folder()).join("system.dmp");
        let dump_filepath = dump_filepath.to_str()
            .ok_or(ProcessMemoryInitError::TempPathNotUtf8)?;

        {
            let file_mode = fs::FsFileMode::Write;
            let dump_file = sysapi::create_file(
                dump_filepath,
                file_mode.access_rights(),
                file_mode.share_mode(),
                0
            )?;

            sysapi::dump_live_system(*dump_file)?;
        }

        let (_, _, src_data) = fs::map_file("c:\\windows\\system32\\ntoskrnl.exe")?;

        let kernel_pe = PtrPE::new_memory(src_data.as_ptr(), src_data.len());

        let pdb_path = pdb::download_pdb(&kernel_pe, &fs::get_temp_folder())
            .map_err(ProcessMemoryInitError::DownloadPdb)?;

        let mut pdb = pdb::Pdb::init(&pdb_path)
            .map_err(ProcessMemoryInitError::InitPdb)?;

        let kdump = kdump::KernelDump::new(dump_filepath, &mut pdb)
            .map_err(ProcessMemoryInitError::ParseKernelDump)?;

        let processes = kdump.get_processes()
            .map_err(ProcessMemoryInitError::GetProcesses)?;

        let process = processes.iter().find(|p| p.pid == pid)
            .ok_or(ProcessMemoryInitError::ProcessNotFound { pid })?;

        Ok(ProcessMemoryRead::LiveDumpParse {
            kdump: Arc::new(kdump),
            kdump_process: process.clone()
        })
    }

    pub fn create_memory(&mut self, size: usize) -> Result<(), ProcessMemoryError> {
        let write = self.write.as_mut()
            .ok_or(ProcessMemoryError::MissingWriteStrategy { operation: "create memory" })?;

        match write {
            ProcessMemoryWrite::AllocateInAddr { handle } => {
                let allocation_type = MEM_COMMIT | MEM_RESERVE;
                let protect = PAGE_EXECUTE_READWRITE;
                let remote_base = self.base_addr_remote;
                let base_addr = sysapi::allocate_virtual_memory(
                    size,
                    protect,
                    *handle,
                    remote_base,
                    allocation_type
                )?;
                self.base_addr_remote = base_addr;

                Ok(())
            }
            ProcessMemoryWrite::CreateSectionMap { handle, section } => {
                *section = ScopeGuard::into_inner(sysapi::create_section(size)?);
                self.base_addr_remote = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    *handle,
                    self.base_addr_remote
                )?;

                Ok(())
            }
            ProcessMemoryWrite::CreateSectionMapLocalMap { handle, section, base_addr_local } => {
                *section = ScopeGuard::into_inner(sysapi::create_section(size)?);
                self.base_addr_remote = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    *handle,
                    self.base_addr_remote
                )?;
                *base_addr_local = sysapi::map_view_of_section(
                    *section,
                    size,
                    PAGE_READWRITE,
                    NT_CURRENT_PROCESS,
                    ptr::null_mut()
                )?;

                if let Some(ProcessMemoryRead::CreateSectionMapLocalMap { base_addr_local: read_base_addr_local }) = self.read.as_mut() {
                    *read_base_addr_local = *base_addr_local;
                }

                Ok(())
            }
        }
    }

    pub fn read_memory(&self, offset: usize, data: PVOID, size: usize) -> Result<(), ProcessMemoryError> {
        let read = self.read.as_ref()
            .ok_or(ProcessMemoryError::MissingReadStrategy { operation: "read memory" })?;

        unsafe {
            match read {
                ProcessMemoryRead::ReadVirtualMemory { handle }
                | ProcessMemoryRead::CreateSectionMap { handle } => {
                    let buffer = slice::from_raw_parts_mut(data as *mut u8, size);
                    sysapi::read_virtual_memory(
                        buffer,
                        self.base_addr_remote.wrapping_add(offset),
                        *handle
                    )?;

                    Ok(())
                }
                ProcessMemoryRead::CreateSectionMapLocalMap { base_addr_local } => {
                    if base_addr_local.is_null() {
                        return Err(ProcessMemoryError::MissingLocalSectionMap { operation: "read memory" });
                    }

                    ptr::copy_nonoverlapping(base_addr_local.wrapping_add(offset), data, size);

                    Ok(())
                }
                ProcessMemoryRead::LiveDumpParse { kdump, kdump_process } => {
                    let dst = slice::from_raw_parts_mut(data as *mut u8, size);
                    kdump.read_memory(
                        dst,
                        kdump_process,
                        self.base_addr_remote.add(offset) as _
                    ).map_err(ProcessMemoryError::KernelDumpRead)?;

                    Ok(())
                }
            }
        }
    }

    pub fn write_memory(&self, offset: usize, data: PVOID, size: usize) -> Result<(), ProcessMemoryError> {
        let write = self.write.as_ref()
            .ok_or(ProcessMemoryError::MissingWriteStrategy { operation: "write memory" })?;

        match write {
            ProcessMemoryWrite::AllocateInAddr { handle } => unsafe {
                let buffer = slice::from_raw_parts(data as *const u8, size);

                sysapi::write_virtual_memory(
                    buffer,
                    self.base_addr_remote.wrapping_add(offset),
                    *handle
                )?;

                Ok(())
            },
            ProcessMemoryWrite::CreateSectionMap { handle, .. } => unsafe {
                let buffer = slice::from_raw_parts(data as *const u8, size);

                sysapi::write_virtual_memory(
                    buffer,
                    self.base_addr_remote.wrapping_add(offset),
                    *handle
                )?;

                Ok(())
            },
            ProcessMemoryWrite::CreateSectionMapLocalMap { base_addr_local, .. } => {
                unsafe {
                    ptr::copy_nonoverlapping(data, base_addr_local.wrapping_add(offset), size);
                }

                Ok(())
            }
        }
    }

    pub fn create_write_memory_fixup_addr(
        &mut self,
        data: PVOID,
        size: usize,
        fixup_addr_memory: Self,
        fixup_addr_offset: usize,
    ) -> Result<(), ProcessMemoryError> {
        self.create_memory(size)?;
        self.write_memory(0, data, size)?;

        let remote_base_addr = self.get_remote_base_addr();

        fixup_addr_memory.write_memory(
            fixup_addr_offset,
            addr_of!(remote_base_addr) as _,
            size_of::<PVOID>()
        )?;

        Ok(())
    }

    pub fn get_remote_base_addr(&self) -> PVOID {
        self.base_addr_remote
    }

    pub fn set_remote_base_addr(&mut self, addr: PVOID) {
        self.base_addr_remote = addr;
    }
}

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
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
    pub fn open(&self, pid: u32, access_mask: ACCESS_MASK) -> sysapi::NtResult<UniqueHandle> {
        match self {
            ProcessOpenStrategy::OpenProcess => sysapi::open_process(pid, access_mask),
            ProcessOpenStrategy::OpenProcessByHwnd => {
                let mut opts = EnumWindowsProcOpts { pid, ..Default::default() };

                unsafe {
                    EnumWindows(Some(EnumWindowsProc), &mut opts as *mut _ as _);
                }

                if opts.hWnd.is_null() {
                    log::error!("Unable to find any windows for the process with PID {pid}");
                    return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL).into());
                }

                log::debug!("Window found, HWND = 0x{:x}", opts.hWnd as usize);

                // sysapi::ProcessOpenByHwnd(opts.hWnd, access_mask); // TODO: research access restrictions
                sysapi::open_process_by_hwnd(
                    opts.hWnd,
                    PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE
                )
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
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
    pub fn open(&self, args: ThreadOpenArgs, access_mask: ACCESS_MASK) -> sysapi::NtResult<UniqueHandle> {
        match self {
            ThreadOpenStrategy::ThreadOpenByTid => match (args.pid, args.tid) {
                (Some(pid), Some(tid)) => sysapi::open_thread(pid, tid, access_mask),
                _ => Err(NTSTATUS(ntstatus::STATUS_INVALID_PARAMETER).into()),
            },
            ThreadOpenStrategy::ThreadOpenAnyNext => match args.process_handle {
                Some(process_handle) => sysapi::open_next_thread(process_handle, ptr::null_mut(), THREAD_ALL_ACCESS),
                None => Err(NTSTATUS(ntstatus::STATUS_INVALID_PARAMETER).into()),
            },
            ThreadOpenStrategy::ThreadOpenAnyByHwnd => {
                let pid = args.pid
                    .ok_or(NTSTATUS(ntstatus::STATUS_INVALID_PARAMETER))?;

                let mut opts = EnumWindowsProcOpts { pid, ..Default::default() };

                unsafe {
                    EnumWindows(Some(EnumWindowsProc), &mut opts as *mut _ as _);
                }

                if opts.hWnd.is_null() {
                    log::error!("Unable to find any windows for the process with PID {pid}");
                    return Err(NTSTATUS(ntstatus::STATUS_UNSUCCESSFUL).into());
                }

                log::debug!("Window found, HWND = 0x{:x}", opts.hWnd as usize);
                sysapi::open_thread(opts.pid, opts.tid, access_mask)
            }
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ProcessSuspendStrategy {
    NtSuspendProcess,
    NtChangeProcessState,
}

impl fmt::Display for ProcessSuspendStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ProcessSuspendStrategy {
    pub fn suspend(&self, process_handle: HANDLE) -> sysapi::NtResult<()> {
        match self {
            ProcessSuspendStrategy::NtSuspendProcess => sysapi::suspend_process_by_nt_suspend_process(process_handle),
            ProcessSuspendStrategy::NtChangeProcessState => sysapi::suspend_process_by_state_change(process_handle),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ProcessResumeStrategy {
    NtResumeProcess,
    NtChangeProcessState,
}

impl fmt::Display for ProcessResumeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ProcessResumeStrategy {
    pub fn resume(&self, process_handle: HANDLE) -> sysapi::NtResult<()> {
        match self {
            ProcessResumeStrategy::NtResumeProcess => sysapi::resume_process_by_nt_resume_process(process_handle),
            ProcessResumeStrategy::NtChangeProcessState => sysapi::resume_process_by_state_change(process_handle),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ThreadSuspendStrategy {
    NtSuspendThread,
    NtChangeThreadState,
}

impl fmt::Display for ThreadSuspendStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ThreadSuspendStrategy {
    pub fn suspend(&self, thread_handle: HANDLE) -> sysapi::NtResult<()> {
        match self {
            ThreadSuspendStrategy::NtSuspendThread => sysapi::suspend_thread_by_nt_suspend_thread(thread_handle),
            ThreadSuspendStrategy::NtChangeThreadState => sysapi::suspend_thread_by_state_change(thread_handle),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, VariantArray, FromRepr, IntoStaticStr, EnumIter)]
pub enum ThreadResumeStrategy {
    NtResumeThread,
    NtChangeThreadState,
}

impl fmt::Display for ThreadResumeStrategy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl ThreadResumeStrategy {
    pub fn resume(&self, thread_handle: HANDLE) -> sysapi::NtResult<()> {
        match self {
            ThreadResumeStrategy::NtResumeThread => sysapi::resume_thread_by_nt_resume_thread(thread_handle),
            ThreadResumeStrategy::NtChangeThreadState => sysapi::resume_thread_by_state_change(thread_handle),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn thread_set_ep<const IS_NEW_THREAD: bool, const IS_64: bool>(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    if IS_64 {
        let mut context = sysapi::get_thread_context(thread_handle)?;

        if IS_NEW_THREAD {
            context.Rcx = exec_address as _;
        } else {
            context.Rip = exec_address as _;
        }

        sysapi::set_thread_context(thread_handle, &context)?;
    } else {
        let mut context = sysapi::get_thread_wow64_context(thread_handle)?;

        if IS_NEW_THREAD {
            context.Eax = exec_address as _;
        } else {
            context.Eip = exec_address as _;
        }

        sysapi::set_thread_wow64_context(thread_handle, &context)?;
    }

    Ok(())
}

#[cfg(target_arch = "x86")]
fn thread_set_ep<const IS_NEW_THREAD: bool, const IS_64: bool>(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    if IS_64 {
        return Err(NTSTATUS(ntstatus::STATUS_NOT_IMPLEMENTED).into());
    }

    let mut context = sysapi::get_thread_context(thread_handle)?;

    if IS_NEW_THREAD {
        context.Eax = exec_address as _;
    } else {
        context.Eip = exec_address as _;
    }

    sysapi::set_thread_context(thread_handle, &context)?;

    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn thread_set_ep<const IS_NEW_THREAD: bool, const IS_64: bool>(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    if !IS_64 {
        return Err(NTSTATUS(ntstatus::STATUS_NOT_IMPLEMENTED).into());
    }

    let mut context = sysapi::get_thread_context(thread_handle)?;

    if IS_NEW_THREAD {
        context.Anonymous.Anonymous.X0 = exec_address as _;
    } else {
        context.Pc = exec_address as _;
    }

    sysapi::set_thread_context(thread_handle, &context)?;

    Ok(())
}

pub fn new_thread_set_ep_x64(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    thread_set_ep::<true, true>(thread_handle, exec_address)
}

pub fn new_thread_set_ep_x86(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    thread_set_ep::<true, false>(thread_handle, exec_address)
}

pub fn thread_set_ep_x64(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    thread_set_ep::<false, true>(thread_handle, exec_address)
}

pub fn thread_set_ep_x86(thread_handle: HANDLE, exec_address: PVOID) -> sysapi::NtResult<()> {
    thread_set_ep::<false, false>(thread_handle, exec_address)
}
