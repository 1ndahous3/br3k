use windef::winbase::AlignedContext;
use std::mem::{align_of, offset_of, size_of};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

#[test]
fn aligned_context_preserves_native_storage() {
    assert_eq!(align_of::<AlignedContext>(), 16);
    assert_eq!(offset_of!(AlignedContext, ctx), 0);
    assert_eq!(size_of::<AlignedContext>(), size_of::<CONTEXT>().next_multiple_of(16));
}

#[test]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn embedded_context_is_aligned() {
    assert_eq!(offset_of!(windef::ntpsapi::RTL_UMS_CONTEXT, Context), 16);
}
