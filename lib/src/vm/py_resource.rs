use crate::prelude::*;
use crate::vm::prelude::*;

use crate::sysapi;

#[pyclass(module = false, name = "Handle")]
#[derive(Debug, PyPayload)]
pub struct Handle {
    pub handle: sysapi::UniqueHandle,
}

#[pyclass]
impl Handle {}

#[pyclass(module = false, name = "BufferView")]
#[derive(Debug, PyPayload)]
pub struct BufferView {
    pub ptr: u64,
    pub size: u64,
}

impl Constructor for BufferView {
    type Args = PyObjectRef;

    fn py_new(cls: PyTypeRef, obj_ref: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {

        if let Ok(b) = &obj_ref.downcast::<PyBytes>() {
            return Self {
                ptr: b.as_ptr() as _,
                size: b.len() as _,
            }
            .into_ref_with_type(vm, cls)
            .map(Into::into)
        }

        Err(vm.new_type_error("Cannot convert an object to a buffer view".to_string()))
    }
}


// because Python does not have a class for non-owning flat buffers (PyMemoryView is too abstract)
#[pyclass(with(Constructor))]
impl BufferView {

    #[pygetset]
    fn ptr(&self) -> u64 {
        self.ptr
    }

    #[pygetset]
    fn size(&self) -> u64 {
        self.size
    }
}

impl From<PyRef<PyBytes>> for BufferView {
    fn from(bytes: PyRef<PyBytes>) -> Self {
        Self {
            ptr: bytes.as_ptr() as _,
            size: bytes.as_bytes().len() as _,
        }
    }
}
