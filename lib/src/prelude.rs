#![allow(unused_imports)]

pub use std::*;

pub use mem::offset_of;
pub use ptr::{addr_of, addr_of_mut};

pub use std::sync::OnceLock;
pub use std::cell::{Cell, RefCell};

pub use std::ffi::{CString, CStr};
pub use widestring::U16CString;

pub use windef::winbase::PVOID;
