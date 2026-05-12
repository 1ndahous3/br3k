use crate::vm::prelude::*;

use exe::{NTHeaders, PE, PEType, PtrPE, types};

#[derive(FromArgs)]
pub struct PeNewArgs {
    #[pyarg(any)]
    data: usize,
    #[pyarg(any, optional)]
    size: OptionalArg<usize>,
    #[pyarg(any)]
    is_file: bool,
}

#[pyclass(module = false, name = "Pe")]
#[derive(Debug, PyPayload)]
pub struct Pe {
    pub pe: PtrPE,
}

impl Constructor for Pe {
    type Args = PeNewArgs;

    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let pe = if args.is_file {
            let size = args.size.present()
                .ok_or_else(|| vm.new_type_error("'size' must be specified for file type".to_string()))?;

            PtrPE::new_disk(args.data as _, size)
        } else if let Some(size) = args.size.present() {
            PtrPE::new_memory(args.data as _, size)
        } else {
            unsafe { PtrPE::from_memory(args.data as _)
                .map_err(map_to_py_system_error(vm, "Unable to load PE"))? }
        };

        Ok(Self { pe })
    }
}

#[pyclass(with(Constructor))]
impl Pe {
    #[pymethod]
    pub fn is_x64(&self, vm: &VirtualMachine) -> PyResult<bool> {
        let arch = self.pe.get_arch()
            .map_err(map_to_py_system_error(vm, "Unable to read PE architecture"))?;

        Ok(arch == types::Arch::X64)
    }

    #[pymethod]
    fn image_size(&self, vm: &VirtualMachine) -> PyResult<u32> {
        let image_size = match self.pe.get_valid_nt_headers()
            .map_err(map_to_py_system_error(vm, "Unable to read PE NT headers"))? {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image,
        };

        Ok(image_size)
    }

    #[pymethod]
    fn ep_address(&self, vm: &VirtualMachine) -> PyResult<u32> {
        let ep = self.pe.get_entrypoint()
            .map_err(map_to_py_system_error(vm, "Unable to read PE entry point"))?;

        Ok(ep.0)
    }

    #[pymethod]
    fn build_mem_image(&self, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let data = self.pe.recreate_image(PEType::Memory)
            .map_err(map_to_py_system_error(vm, "Unable to build memory image"))?;
        let bytes = vm.ctx.new_bytes(data.to_vec());

        Ok(bytes.into())
    }
}
