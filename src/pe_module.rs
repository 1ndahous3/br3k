use crate::prelude::*;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

pub fn get_module_handle(module_name: &CStr) -> Option<HANDLE> {
    unsafe {
        let module_handle = GetModuleHandleA(module_name.as_ptr() as _);

        if module_handle.is_null() {
            None
        } else {
            Some(module_handle)
        }
    }
}
