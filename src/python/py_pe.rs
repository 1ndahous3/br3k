use rustpython_vm::{
    VirtualMachine,
    pyclass,
    FromArgs,
    PyPayload, PyObjectRef, PyResult,
    builtins::PyTypeRef,
    types::Constructor,
};

use exe::{PtrPE, types, NTHeaders, PE, PEType};
use rustpython_vm::function::OptionalArg;

#[derive(FromArgs)]
pub struct PeNewArgs {
    #[pyarg(any)]
    data: usize,
    #[pyarg(any, optional)]
    size: OptionalArg<usize>,
    #[pyarg(any)]
    is_file: bool
}

#[pyclass(module = false, name = "Pe")]
#[derive(Debug, PyPayload)]
pub struct Pe {
    pub pe: PtrPE
}

impl Constructor for Pe {
    type Args = PeNewArgs;

    fn py_new(cls: PyTypeRef, args: Self::Args, vm: &VirtualMachine) -> PyResult<PyObjectRef> {

        let pe = if args.is_file {
            if args.size.is_missing() {
                return Err(vm.new_type_error("'size' must be specified for file type".to_string()));
            }

            PtrPE::new_disk(args.data as _, args.size.unwrap())
        } else {
            if let OptionalArg::Present(size) = args.size {
                PtrPE::new_memory(args.data as _, size)
            } else {
                unsafe {
                    PtrPE::from_memory(args.data as _)
                        .map_err(|e| vm.new_system_error(format!(
                            "Unable to load PE: {}", e)))?
                }
            }
        };

        Self {
            pe
        }
        .into_ref_with_type(vm, cls)
        .map(Into::into)
    }
}

#[pyclass(with(Constructor))]
impl Pe {
    #[pymethod]
    pub fn is_x64(&self) -> bool {
        self.pe.get_arch().unwrap() == types::Arch::X64
    }

    #[pymethod]
    fn image_size(&self) -> u32 {
        match self.pe.get_valid_nt_headers().unwrap() {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image,
        }
    }

    #[pymethod]
    fn ep_address(&self) -> u32 {
        self.pe.get_entrypoint().unwrap().0
    }

    #[pymethod]
    fn build_mem_image(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let data = self.pe.recreate_image(PEType::Memory).unwrap();
        let bytes = vm.ctx.new_bytes(data.to_vec());
        Ok(bytes.into())}
}
