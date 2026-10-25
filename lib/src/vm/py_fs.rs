use crate::vm::prelude::*;

use crate::fs;
use crate::sysapi;

use std::slice;

/// A read-only file section mapped into the current process.
///
/// Construction opens and maps the file. Native handles are owned by the object;
/// `data` is a local address, not an offset or a remote address. Prefer `bytes()`
/// when an independent copy is needed.
#[pyclass(module = false, name = "FileMapping")]
#[derive(Debug, PyPayload)]
pub struct FileMapping {
    pub handle: sysapi::UniqueHandle,
    pub section_handle: sysapi::UniqueHandle,
    pub data: usize,
    pub size: usize,
}

#[pyclass(with(Constructor))]
impl FileMapping {
    /// Native file handle owned by this mapping. Do not close it separately.
    #[pygetset]
    fn handle(zelf: &Py<Self>) -> usize {
        *zelf.handle as usize
    }

    /// Native section handle owned by this mapping. Do not close it separately.
    #[pygetset]
    fn section_handle(zelf: &Py<Self>) -> usize {
        *zelf.section_handle as usize
    }

    /// Base virtual address of the local mapped view.
    #[pygetset]
    fn data(zelf: &Py<Self>) -> usize {
        zelf.data
    }

    /// Size of the local mapped view in bytes.
    #[pygetset]
    fn size(zelf: &Py<Self>) -> usize {
        zelf.size
    }

    /// Copy the mapped view into an independent Python `bytes` object.
    #[pymethod]
    fn bytes(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        unsafe {
            let bytes = vm.ctx.new_bytes(slice::from_raw_parts(zelf.data as *const u8, zelf.size).to_vec());
            Ok(bytes)
        }
    }
}

impl Constructor for FileMapping {
    type Args = String;

    /// Open `path` and create a read-only mapping. Native failures raise `SystemError`.
    fn py_new(_cls: &Py<PyType>, path: String, vm: &VirtualMachine) -> PyResult<Self> {
        match fs::map_file(&path) {
            Ok((handle, section_handle, data)) => Ok(Self {
                handle,
                section_handle,
                data: data.as_ptr() as usize,
                size: data.len()
            }),
            Err(e) => Err(to_py_system_error(vm, "Unable to map file", e)),
        }
    }
}
