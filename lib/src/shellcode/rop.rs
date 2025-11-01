use crate::prelude::*;
use crate::pe_module;

use super::SYSTEM_DLLS;

use std::ffi::CString;

pub fn gadget_inf_loop() -> Option<&'static[u8]> {
    pe_module::find_code_in_module(
        "ntdll.dll",
        &[
            0xEB, 0xFE // JMP -2
        ]
    )
}

pub fn gadget_ret() -> Option<&'static[u8]> {
    pe_module::find_code_in_module(
        "ntdll.dll",
        &[
            0xC3
        ]
    )
}

pub fn gadget_pop_value_and_ret() -> Option<&'static[u8]> {
    pe_module::find_code_in_module(
        "ntdll.dll",
        &[
            0x58, // pop rax
            0xC3  // ret
        ]
    )
}

pub fn gadget_pop_values_and_ret(count: usize) -> Option<&'static[u8]> {
    unsafe {
        static POP8: [u8; 3] = [
            0x58, // pop rax
            0x5A, // pop rdx
            0x59, // pop rcx
            // 0x5B, // pop rbx
            // 0x5E, // pop rsi
            // 0x5F, // pop rdi
            // 0x5D, // pop rbp
        ];

        static POP16: [u16; 8] = [
            0x5941, // pop r9
            0x5841, // pop r8
            0x5A41, // pop r10
            0x5B41, // pop r11
            0x5C41, // pop r12
            0x5D41, // pop r13
            0x5E41, // pop r14
            0x5F41, // pop r15
        ];

        let find_ret = |code: &[u8]| {
            code
                .windows(1)
                .position(|window| window == [0xC3].as_slice())
                .map(|index| code.as_ptr().add(index))
        };

        for dll_name in SYSTEM_DLLS {
            let dll_name = CString::new(dll_name).unwrap();
            let handle = pe_module::get_module_handle(dll_name.as_ref()).unwrap();

            let code_section = pe_module::get_module_text_section(handle);

            let mut ret = find_ret(code_section);

            while ret.is_some() {

                let it = ret.unwrap();
                let mut it_back = it;

                let mut pop_count: usize = 0;

                'find_pop: while pop_count < count {

                    it_back = it_back.sub(2); // first check 2-bytes instructions
                    for pop in POP16 {
                        if (it_back as *const u16).read_unaligned() == pop {
                            pop_count += 1;
                            continue 'find_pop;
                        }
                    }

                    it_back = it_back.add(1); // then check 1-bytes instructions
                    for pop in POP8 {
                        if it_back.read_unaligned() == pop {
                            pop_count += 1;
                            continue 'find_pop;
                        }
                    }

                    it_back = it_back.sub(3); // then check 4-bytes "add rsp, X"

                    if pop_count != 0 {
                        let pops_left = (count - pop_count) as u32;
                        let instr = 0xC48348 | ((pops_left * 8u32) << 24); // 48 83 C4 XX

                        if (it_back as *const u32).read_unaligned() == instr {
                            return Some(slice::from_raw_parts(
                                it_back,
                                it.offset_from(it_back) as usize)
                            );
                        }
                    }

                    break;
                }

                if pop_count == count {
                    return Some(slice::from_raw_parts(
                        it_back,
                        it.offset_from(it_back) as usize)
                    );
                }

                let offset = it.offset_from(code_section.as_ptr()) as usize;
                ret = find_ret(&code_section[offset + 1..]);
            }
        }

        None
    }
}
