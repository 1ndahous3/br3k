use crate::prelude::*;
use exe::{PtrPE, PE};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

pub fn get_module_handle(module_name: &CStr) -> Option<HMODULE> {
    unsafe {
        let module_handle = GetModuleHandleA(module_name.as_ptr() as _);

        if module_handle.is_null() {
            None
        } else {
            Some(module_handle)
        }
    }
}

pub fn get_module_text_section(module_data: PVOID) -> &'static[u8] {
    unsafe {
        let pe = PtrPE::from_memory(module_data as _).unwrap();

        let section = pe.get_section_by_name(".text").unwrap();

        let section_ptr = module_data.add(section.virtual_address.0 as usize) as *const u8;
        let section_size = section.size_of_raw_data as usize;

        slice::from_raw_parts(section_ptr, section_size)
    }
}

pub fn get_module_data_section(module_data: PVOID) -> &'static[u8] {
    unsafe {
        let pe = PtrPE::from_memory(module_data as _).unwrap();

        let section = pe.get_section_by_name(".data").unwrap();

        let section_ptr = module_data.add(section.virtual_address.0 as usize) as *const u8;
        let section_size = section.size_of_raw_data as usize;

        slice::from_raw_parts(section_ptr, section_size)
    }
}

pub fn find_code_in_module_data(module_data: PVOID, code: &[u8]) -> Option<&'static[u8]> {
    let section_data = get_module_text_section(module_data);
    section_data
        .windows(code.len())
        .position(|window| window == code)
        .map(|index| &section_data[index..index + code.len()])
}

pub fn find_code_in_module(module_name: &str, code: &[u8]) -> Option<&'static[u8]> {
    let module_name = CString::new(module_name).unwrap();
    let handle = get_module_handle(module_name.as_ref()).unwrap();

    find_code_in_module_data(handle as _, code)
}
