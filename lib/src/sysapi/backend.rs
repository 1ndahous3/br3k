use crate::prelude::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::slice;

use strum_macros::EnumString;

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

#[derive(Debug, thiserror::Error)]
pub enum DirectSyscallError {
    #[error("direct system calls are not supported on this architecture")]
    Unsupported,
    #[error("unable to resolve direct system call id for {proc_name}")]
    SyscallIdNotFound { proc_name: &'static str },
    #[error("unable to allocate direct system call stub for {proc_name}")]
    StubAllocationFailed { proc_name: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, EnumString)]
pub enum SysApiBackend {
    #[default]
    Dll,
    DllCopy,
    DirectSyscall,
}

impl SysApiBackend {
    pub(crate) fn uses_dll_copy(self) -> bool {
        matches!(self, Self::DllCopy)
    }
}

pub(crate) struct DirectSyscallStubs {
    stubs: RefCell<HashMap<&'static str, PVOID>>,
}

impl DirectSyscallStubs {
    pub(crate) fn new() -> Self {
        Self { stubs: RefCell::new(HashMap::new()) }
    }

    pub(crate) fn get<T: Copy>(&self, proc_name: &'static str, api: T) -> Result<T, DirectSyscallError> {
        let mut stubs = self.stubs.borrow_mut();

        if let Some(stub) = stubs.get(proc_name) {
            return Ok(unsafe { mem::transmute_copy(stub) });
        }

        let stub = Self::create_stub(proc_name, api)?;
        stubs.insert(proc_name, stub);
        Ok(unsafe { mem::transmute_copy(&stub) })
    }

    #[cfg(target_arch = "x86_64")]
    fn create_stub<T: Copy>(proc_name: &'static str, api: T) -> Result<PVOID, DirectSyscallError> {
        let api: PVOID = unsafe { mem::transmute_copy(&api) };
        let syscall_id = Self::syscall_id_from_stub(api)
            .ok_or(DirectSyscallError::SyscallIdNotFound { proc_name })?;

        let mut stub = [
            0x4c, 0x8b, 0xd1,             // mov r10, rcx
            0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_id
            0x0f, 0x05,                   // syscall
            0xc3,                         // ret
        ];
        stub[4..8].copy_from_slice(&syscall_id.to_le_bytes());

        let allocation = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                stub.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if allocation.is_null() {
            return Err(DirectSyscallError::StubAllocationFailed { proc_name });
        }

        unsafe {
            ptr::copy_nonoverlapping(stub.as_ptr(), allocation as *mut u8, stub.len());
        }

        Ok(allocation as _)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn create_stub<T: Copy>(_proc_name: &'static str, _api: T) -> Result<PVOID, DirectSyscallError> {
        Err(DirectSyscallError::Unsupported)
    }

    #[cfg(target_arch = "x86_64")]
    fn syscall_id_from_stub(api: PVOID) -> Option<u32> {
        unsafe {
            let stub = slice::from_raw_parts(api as *const u8, 32);

            for offset in 0..=(stub.len().saturating_sub(8)) {
                if stub[offset..offset + 4] == [0x4c, 0x8b, 0xd1, 0xb8] {
                    return Some(u32::from_le_bytes([
                        stub[offset + 4],
                        stub[offset + 5],
                        stub[offset + 6],
                        stub[offset + 7],
                    ]));
                }
            }

            for offset in 0..=(stub.len().saturating_sub(7)) {
                if stub[offset] != 0xb8 {
                    continue;
                }

                let has_syscall = stub[offset + 5..]
                    .windows(2)
                    .take(16)
                    .any(|bytes| bytes == [0x0f, 0x05]);

                if has_syscall {
                    return Some(u32::from_le_bytes([
                        stub[offset + 1],
                        stub[offset + 2],
                        stub[offset + 3],
                        stub[offset + 4],
                    ]));
                }
            }

            None
        }
    }
}
