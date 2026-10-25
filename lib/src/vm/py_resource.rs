use crate::vm::prelude::*;

use crate::sysapi;

/// An owning native handle returned by br3k operations.
///
/// The handle closes when its last owning reference is released. Obtain instances
/// from APIs such as `br3k.fs.open_file`; this class has no Python constructor.
#[pyclass(module = false, name = "Handle")]
#[derive(Debug, PyPayload)]
pub struct Handle {
    pub handle: sysapi::UniqueHandle,
}

#[pyclass]
impl Handle {}

/// A non-owning view of Python bytes as a local address and byte length.
///
/// Keep the original bytes object alive for every use of the view. The view does
/// not retain its owner, copy the data, or make the storage writable.
#[pyclass(module = false, name = "BufferView")]
#[derive(Debug, PyPayload)]
pub struct BufferView {
    /// Local virtual address of the first byte. Valid only while the backing storage remains alive.
    #[pymember]
    pub ptr: u64,
    /// Length of the borrowed storage in bytes.
    #[pymember]
    pub size: u64,
}

#[py_api]
impl Constructor for BufferView {
    type Args = PyObjectRef;

    /// Borrow the storage of a `bytes` object; other objects raise `TypeError`.
    #[pyi(params(obj_ref = "bytes"))]
    fn py_new(_cls: &Py<PyType>, obj_ref: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        if let Ok(b) = &obj_ref.downcast::<PyBytes>() {
            return Ok(Self {
                ptr: b.as_ptr() as _,
                size: b.len() as _
            });
        }

        Err(vm.new_type_error("Cannot convert an object to a buffer view".to_string()))
    }
}

// because Python does not have a class for non-owning flat buffers (PyMemoryView is too abstract)
#[pyclass(with(Constructor))]
impl BufferView {
}

impl From<PyRef<PyBytes>> for BufferView {
    fn from(bytes: PyRef<PyBytes>) -> Self {
        Self {
            ptr: bytes.as_ptr() as _,
            size: bytes.as_bytes().len() as _
        }
    }
}
