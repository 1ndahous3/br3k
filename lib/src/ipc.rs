use crate::prelude::*;

use crate::sysapi;
use sysapi::UniqueHandle;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::NTSTATUS;

use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SDDL_REVISION_1
};

use windef::ntstatus;

static PIPE_NAME_PROC_PREFIX: &str = "br3k_ipc_";

pub fn create_pipe(pid: u32) -> Result<UniqueHandle, NTSTATUS> {
    unsafe {
        let pipe_name = format!("{PIPE_NAME_PROC_PREFIX}{pid}");

        // SDDL: SYSTEM + Administrators => Generic All; Everyone => Generic Read/Write
        // Minimal rights for any process to connect and exchange data.
        const PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)";

        // For low integrity client support:
        // const PIPE_SDDL: &str = "O:SYD:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)S:(ML;;NW;;;LW)";

        let mut sd_ptr = PSECURITY_DESCRIPTOR::default();

        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            U16CString::from_str(PIPE_SDDL).unwrap().as_ptr(),
            SDDL_REVISION_1,
            addr_of_mut!(sd_ptr),
            ptr::null_mut(),
        );

        if ok == 0 {
            return Err(NTSTATUS(ntstatus::STATUS_INVALID_PARAMETER));
        }

        let _guard = scopeguard::guard((), |_| {
            LocalFree(sd_ptr);
        });

        let pipe_handle = sysapi::create_named_pipe(pipe_name.as_str(), sd_ptr)?;

        Ok(pipe_handle)
    }
}

pub fn open_pipe(pid: u32) -> Result<UniqueHandle, NTSTATUS> {

    let pipe_name = format!("{PIPE_NAME_PROC_PREFIX}{pid}");
    let pipe_handle = sysapi::open_named_pipe(pipe_name.as_str())?;

    Ok(pipe_handle)
}

pub fn send_data(pipe_handle: HANDLE, data: &[u8]) -> Result<(), NTSTATUS> {

    let data_size = data.len() as u32;

    sysapi::write_file(pipe_handle, addr_of!(data_size) as _, size_of::<u32>())?;
    sysapi::write_file(pipe_handle, data.as_ptr() as _, data.len())?;

    Ok(())
}

pub fn receive_data(pipe_handle: HANDLE) -> Result<Vec<u8>, NTSTATUS> {

    let data_size = 0u32;
    let mut data: Vec<u8> = Vec::new();

    sysapi::read_file(pipe_handle, addr_of!(data_size) as _, size_of::<u32>())?;

    data.resize(data_size as _, 0);
    sysapi::read_file(pipe_handle, data.as_ptr() as _, data.len())?;

    Ok(data)
}
