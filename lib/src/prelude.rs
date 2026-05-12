#![allow(unused_imports)]

pub use std::mem::{self, offset_of, size_of};
pub use std::ptr::{self, addr_of, addr_of_mut};

pub use std::ffi::{CStr, CString};
pub use widestring::U16CString;

pub use windef::winbase::PVOID;
