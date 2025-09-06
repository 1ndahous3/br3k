use crate::prelude::*;

use windows_sys::Win32::Foundation::UNICODE_STRING;

pub trait ToUnicodeString {
    fn to_unicode_string(&self) -> UNICODE_STRING;
}

impl ToUnicodeString for U16CString {
    fn to_unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: (self.len() * 2) as u16,
            MaximumLength: (self.len() * 2) as u16,
            Buffer: self.as_ptr() as *mut u16,
        }
    }
}

impl<const N: usize> ToUnicodeString for [u16; N] {
    fn to_unicode_string(&self) -> UNICODE_STRING {
        UNICODE_STRING {
            Length: N as u16,
            MaximumLength: N as u16,
            Buffer: self.as_ptr() as *mut u16,
        }
    }
}

pub fn to_unicode_string<T: ToUnicodeString>(s: &T) -> UNICODE_STRING {
    s.to_unicode_string()
}

pub trait ToU16CString {
    fn to_u16cstring(&self) -> U16CString;
}

impl ToU16CString for UNICODE_STRING {
    fn to_u16cstring(&self) -> U16CString {
        unsafe {
            U16CString::from_ptr_unchecked(self.Buffer, (self.Length / 2) as usize)
        }
    }
}

pub fn to_u16cstring<T: ToU16CString>(s: &T) -> U16CString {
    s.to_u16cstring()
}
