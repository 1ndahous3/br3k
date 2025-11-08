#![allow(non_snake_case)]

use crate::pe_module;

pub fn gadget_KiUserCallForwarder() -> Option<&'static [u8]> {
        pe_module::find_code_in_module("ntdll.dll", &[
            0x48, 0x83, 0xEC, 0x48,                   // sub     rsp, 48h
            0x48, 0x89, 0x4C, 0x24, 0x20,             // mov     [rsp+48h+var_28], rcx
            0x48, 0x89, 0x54, 0x24, 0x28,             // mov     [rsp+48h+var_20], rdx
            0x4C, 0x89, 0x44, 0x24, 0x30,             // mov     [rsp+48h+var_18], r8
            0x4C, 0x89, 0x4C, 0x24, 0x38,             // mov     [rsp+48h+var_10], r9
            0x48, 0x8B, 0xC8,                         // mov     rcx, rax
            0x48, 0x8B, 0x05, 0xA6, 0x16, 0x08, 0x00, // mov     rax, cs:__guard_check_icall_fptr
            0xFF, 0xD0,                               // call    rax ; RtlEndStrongEnumerationHashTable
            0x48, 0x8B, 0xC1,                         // mov     rax, rcx
            0x48, 0x8B, 0x4C, 0x24, 0x20,             // mov     rcx, [rsp+48h+var_28]
            0x48, 0x8B, 0x54, 0x24, 0x28,             // mov     rdx, [rsp+48h+var_20]
            0x4C, 0x8B, 0x44, 0x24, 0x30,             // mov     r8, [rsp+48h+var_18]
            0x4C, 0x8B, 0x4C, 0x24, 0x38,             // mov     r9, [rsp+48h+var_10]
            0x48, 0x83, 0xC4, 0x48,                   // add     rsp, 48h
            0x48, 0xFF, 0xE0,                         // jmp     rax
        ])
}
