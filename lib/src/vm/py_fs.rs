use crate::vm::prelude::*;
use crate::prelude::*;
use crate::sysapi;
use crate::fs;

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
    #[pygetset]
    fn handle(&self) -> usize {
        *self.handle.get() as usize
    }

    #[pygetset]
    fn section_handle(&self) -> usize {
        *self.section_handle.get() as usize
    }

    #[pygetset]
    fn data(&self) -> usize {
        self.data
    }

    #[pygetset]
    fn size(&self) -> usize {
        self.size
    }

    #[pymethod]
    fn bytes(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        unsafe {
            let bytes = vm.ctx.new_bytes(slice::from_raw_parts(self.data as *const u8, self.size).to_vec());
            Ok(bytes.into())
        }
    }
}

impl Constructor for FileMapping {
    type Args = String;

    fn py_new(cls: PyTypeRef, path: String, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        match fs::map_file(&path) {
            Ok((handle, section_handle, data)) => Self {
                handle,
                section_handle,
                data: data.as_ptr() as usize,
                size: data.len(),
            }
            .into_ref_with_type(vm, cls)
            .map(Into::into),
            Err(e) => Err(vm.new_system_error(format!(
                "Unable to map file: {}",
                sysapi::ntstatus_decode(e)
            ))),
        }
    }
}
