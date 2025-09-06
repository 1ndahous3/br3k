use crate::prelude::*;
use crate::sysapi;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

use windows::Win32::Foundation::NTSTATUS;

use windef::winbase::NT_CURRENT_PROCESS;

use windows_sys::Win32::System::Memory::{
    PAGE_READONLY, SECTION_FLAGS,
    SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ACCESS_RIGHTS, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use crate::sysapi::UniqueHandle;

#[repr(u32)]
#[derive(Debug, Clone, VariantArray, FromRepr, IntoStaticStr)]
pub enum FsFileMode {
    Read,
    Write,
    ReadWrite,
}

impl fmt::Display for FsFileMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FsFileMode {
    pub fn access_rights(&self) -> FILE_ACCESS_RIGHTS {
        match self {
            FsFileMode::Read => FILE_GENERIC_READ,
            FsFileMode::Write => FILE_GENERIC_WRITE,
            FsFileMode::ReadWrite => FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        }
    }

    pub fn share_mode(&self) -> FILE_SHARE_MODE {
        match self {
            FsFileMode::Read => FILE_SHARE_READ,
            FsFileMode::Write => FILE_SHARE_WRITE,
            FsFileMode::ReadWrite => FILE_SHARE_READ | FILE_SHARE_WRITE,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, VariantArray, FromRepr, IntoStaticStr)]
pub enum FsSectionMode {
    Read,
    Write,
    Execute,
    ReadWrite,
    WriteExecute,
}

impl fmt::Display for FsSectionMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FsSectionMode {
    pub fn access_rights(&self) -> SECTION_FLAGS {
        match self {
            FsSectionMode::Read => SECTION_MAP_READ,
            FsSectionMode::Write => SECTION_MAP_WRITE,
            FsSectionMode::Execute => SECTION_MAP_EXECUTE,
            FsSectionMode::ReadWrite => SECTION_MAP_READ | SECTION_MAP_WRITE,
            FsSectionMode::WriteExecute => SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        }
    }
}

pub fn get_temp_folder() -> String {
    match std::env::temp_dir().to_str() {
        Some(path) => path.to_string(),
        None => panic!("Failed to get temporary directory path"),
    }
}

pub fn map_file(path: &str) -> Result<(UniqueHandle, UniqueHandle, &[u8]), NTSTATUS> {
    unsafe {
        let handle = sysapi::open_file(path)?;
        let size = sysapi::get_file_size(*handle)?;

        let section_handle = sysapi::create_file_section(
            *handle,
            SECTION_MAP_READ,
            PAGE_READONLY,
            false,
            None,
        )?;
        let data = sysapi::map_view_of_section(
            *section_handle,
            size,
            PAGE_READONLY,
            NT_CURRENT_PROCESS,
            ptr::null_mut(),
        )?;

        Ok((handle, section_handle,
            slice::from_raw_parts(data as *const u8, size)
        ))
    }
}
