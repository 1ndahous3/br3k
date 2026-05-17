use crate::prelude::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::slice;

use strum_macros::EnumString;

use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
};

use windef::winbase::NT_CURRENT_PROCESS;

#[derive(Debug, thiserror::Error)]
pub enum DirectSyscallError {
    #[error("unable to resolve direct system call id for {proc_name}")]
    SyscallIdNotFound { proc_name: &'static str },
    #[error("direct system call stub is not prepared for {proc_name}")]
    StubNotPrepared { proc_name: &'static str },
    #[error("unable to allocate direct system call stub for {proc_name}")]
    StubAllocationFailed { proc_name: &'static str },
    #[error("unable to flush direct system call stub instruction cache for {proc_name}")]
    StubInstructionCacheFlushFailed { proc_name: &'static str },
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

#[cfg(target_arch = "x86")]
enum X86SyscallGateway {
    CallEdx(u32),
    CallDwordPtrEdx(u32),
    Sysenter,
}

#[cfg(target_arch = "x86")]
struct X86SyscallDescriptor {
    syscall_id: u32,
    stack_cleanup: u16,
    gateway: X86SyscallGateway,
}

#[cfg(target_arch = "aarch64")]
const ARM64_RET: u32 = 0xd65f03c0;
#[cfg(target_arch = "aarch64")]
const ARM64_SVC_BASE: u32 = 0xd4000001;
#[cfg(target_arch = "aarch64")]
const ARM64_SVC_MASK: u32 = 0xffe0001f;

impl DirectSyscallStubs {
    pub(crate) fn new() -> Self {
        Self { stubs: RefCell::new(HashMap::new()) }
    }

    pub(crate) fn get<T: Copy>(&self, proc_name: &'static str, _api: T) -> Result<T, DirectSyscallError> {
        let stubs = self.stubs.borrow();
        let stub = stubs
            .get(proc_name)
            .ok_or(DirectSyscallError::StubNotPrepared { proc_name })?;

        Ok(unsafe { mem::transmute_copy(stub) })
    }

    pub(crate) fn prepare<T: Copy>(&self, proc_name: &'static str, api: T) -> Result<(), DirectSyscallError> {
        let mut stubs = self.stubs.borrow_mut();

        let stub = Self::create_stub(proc_name, api)?;
        stubs.insert(proc_name, stub);
        Ok(())
    }

    fn allocate_stub(proc_name: &'static str, stub: &[u8]) -> Result<PVOID, DirectSyscallError> {
        let allocation = super::allocate_virtual_memory(
            stub.len(),
            PAGE_EXECUTE_READWRITE,
            NT_CURRENT_PROCESS,
            ptr::null_mut(),
            MEM_COMMIT | MEM_RESERVE,
        )
            .map_err(|_| DirectSyscallError::StubAllocationFailed { proc_name })?;

        unsafe {
            ptr::copy_nonoverlapping(stub.as_ptr(), allocation as *mut u8, stub.len());
        }

        #[cfg(target_arch = "aarch64")]
        {
            if super::flush_instruction_cache(NT_CURRENT_PROCESS, allocation as _, stub.len()).is_err() {
                return Err(DirectSyscallError::StubInstructionCacheFlushFailed { proc_name });
            }
        }

        Ok(allocation as _)
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

        Self::allocate_stub(proc_name, &stub)
    }

    #[cfg(target_arch = "x86")]
    fn create_stub<T: Copy>(proc_name: &'static str, api: T) -> Result<PVOID, DirectSyscallError> {
        let api: PVOID = unsafe { mem::transmute_copy(&api) };
        let descriptor = Self::x86_syscall_from_stub(api)
            .ok_or(DirectSyscallError::SyscallIdNotFound { proc_name })?;

        let mut stub = Vec::<u8>::with_capacity(18);
        stub.push(0xb8); // mov eax, syscall_id
        stub.extend_from_slice(&descriptor.syscall_id.to_le_bytes());

        match descriptor.gateway {
            X86SyscallGateway::CallEdx(address) => {
                stub.push(0xba); // mov edx, address
                stub.extend_from_slice(&address.to_le_bytes());
                stub.extend_from_slice(&[0xff, 0xd2]); // call edx
            }
            X86SyscallGateway::CallDwordPtrEdx(address) => {
                stub.push(0xba); // mov edx, address
                stub.extend_from_slice(&address.to_le_bytes());
                stub.extend_from_slice(&[0xff, 0x12]); // call dword ptr [edx]
            }
            X86SyscallGateway::Sysenter => {
                stub.extend_from_slice(&[0x8b, 0xd4, 0x0f, 0x34]); // mov edx, esp; sysenter
            }
        }

        if descriptor.stack_cleanup == 0 {
            stub.push(0xc3); // ret
        } else {
            stub.push(0xc2); // ret stack_cleanup
            stub.extend_from_slice(&descriptor.stack_cleanup.to_le_bytes());
        }

        Self::allocate_stub(proc_name, &stub)
    }

    #[cfg(target_arch = "aarch64")]
    fn create_stub<T: Copy>(proc_name: &'static str, api: T) -> Result<PVOID, DirectSyscallError> {
        let api: PVOID = unsafe { mem::transmute_copy(&api) };
        let syscall_id = Self::arm64_syscall_id_from_stub(api)
            .ok_or(DirectSyscallError::SyscallIdNotFound { proc_name })?;

        let svc = ARM64_SVC_BASE | ((syscall_id & 0xffff) << 5);
        let mut stub = [0u8; 8];
        stub[0..4].copy_from_slice(&svc.to_le_bytes());
        stub[4..8].copy_from_slice(&ARM64_RET.to_le_bytes());

        Self::allocate_stub(proc_name, &stub)
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

    #[cfg(target_arch = "x86")]
    fn x86_syscall_from_stub(api: PVOID) -> Option<X86SyscallDescriptor> {
        unsafe {
            let stub = slice::from_raw_parts(api as *const u8, 48);
            let syscall_id = Self::x86_syscall_id_from_stub(stub)?;
            let stack_cleanup = Self::x86_stack_cleanup_from_stub(stub)?;
            let gateway = Self::x86_gateway_from_stub(stub)?;

            Some(X86SyscallDescriptor { syscall_id, stack_cleanup, gateway })
        }
    }

    #[cfg(target_arch = "x86")]
    fn x86_syscall_id_from_stub(stub: &[u8]) -> Option<u32> {
        for offset in 0..=(stub.len().saturating_sub(5)) {
            if stub[offset] == 0xb8 {
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

    #[cfg(target_arch = "x86")]
    fn x86_stack_cleanup_from_stub(stub: &[u8]) -> Option<u16> {
        for offset in 0..stub.len() {
            match stub[offset] {
                0xc3 => return Some(0),
                0xc2 if offset + 2 < stub.len() => {
                    return Some(u16::from_le_bytes([stub[offset + 1], stub[offset + 2]]));
                }
                _ => {}
            }
        }

        None
    }

    #[cfg(target_arch = "x86")]
    fn x86_gateway_from_stub(stub: &[u8]) -> Option<X86SyscallGateway> {
        for offset in 0..=(stub.len().saturating_sub(7)) {
            if stub[offset] != 0xba {
                continue;
            }

            let address = u32::from_le_bytes([
                stub[offset + 1],
                stub[offset + 2],
                stub[offset + 3],
                stub[offset + 4],
            ]);

            match &stub[offset + 5..offset + 7] {
                [0xff, 0xd2] => return Some(X86SyscallGateway::CallEdx(address)),
                [0xff, 0x12] => return Some(X86SyscallGateway::CallDwordPtrEdx(address)),
                _ => {}
            }
        }

        for offset in 0..=(stub.len().saturating_sub(4)) {
            if stub[offset..offset + 4] == [0x8b, 0xd4, 0x0f, 0x34] {
                return Some(X86SyscallGateway::Sysenter);
            }
        }

        None
    }

    #[cfg(target_arch = "aarch64")]
    fn arm64_syscall_id_from_stub(api: PVOID) -> Option<u32> {
        unsafe {
            let stub = slice::from_raw_parts(api as *const u8, 32);

            for offset in (0..=(stub.len().saturating_sub(8))).step_by(4) {
                let instruction = u32::from_le_bytes([
                    stub[offset],
                    stub[offset + 1],
                    stub[offset + 2],
                    stub[offset + 3],
                ]);
                let next_instruction = u32::from_le_bytes([
                    stub[offset + 4],
                    stub[offset + 5],
                    stub[offset + 6],
                    stub[offset + 7],
                ]);

                if instruction & ARM64_SVC_MASK == ARM64_SVC_BASE && next_instruction == ARM64_RET {
                    return Some((instruction >> 5) & 0xffff);
                }
            }

            None
        }
    }
}
