pub mod lhiuct;
pub mod rop;
pub mod ntdll;

use crate::prelude::*;
use crate::pe_module;

#[macro_export]
macro_rules! cast_pfn {
    ($address:expr, $t:ty) => {
        mem::transmute::<*const (), $t>($address as _)
    };
}

static SYSTEM_DLLS: [&str; 5] = [
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "user32.dll",
    "ucrtbase.dll"
];

pub fn is_aligned(value: usize, bits: u32) -> bool {
    value & ((1 << bits) - 1) == 0
}

pub fn messageboxw() -> Vec<u8> {
    let shellcode = include_bytes!("MessageBoxA.bin");
    let mut data = Vec::with_capacity(shellcode.len());
    data.extend_from_slice(shellcode);
    data
}
