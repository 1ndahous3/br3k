use crate::vm::prelude::*;

pub use crate::vm::py_pe::code_refs::{PeImportCodeReference, PeImportCodeTrace};
pub(crate) use crate::vm::py_pe::code_refs::import_code_reference_to_py;
use crate::vm::py_pe::delay_imports::PeDelayImportDescriptor;
pub use crate::vm::py_pe::image_resources::{
    PeDataDirectory, PeOverlayRange, PeResourceDataEntry, PeResourceDirectoryInfo,
    PeResourcePathEntry,
};
pub(crate) use crate::vm::py_pe::image_resources::{
    resource_data_entry_to_py, resource_directory_info_to_py,
};
pub(crate) use crate::vm::py_pe::sections::section_info_to_py;
pub use crate::vm::py_pe::sections::PeSection;

use exe::{NTHeaders, PE, PEType, PtrPE, types};

#[derive(FromArgs)]
pub struct DataDirectoryArgs {
    #[pyarg(any)]
    pub(crate) index: usize,
}

#[derive(FromArgs)]
pub struct ReadRvaArgs {
    #[pyarg(any)]
    pub(crate) rva: u32,
    #[pyarg(any)]
    pub(crate) size: usize,
}

#[derive(FromArgs)]
pub struct BuildRelocationTableArgs {
    #[pyarg(any)]
    pub(crate) rvas: Vec<u32>,
}

#[derive(FromArgs)]
pub struct AddRelocationsArgs {
    #[pyarg(any)]
    pub(crate) rvas: Vec<u32>,
    #[pyarg(named, optional)]
    pub(crate) section_name: OptionalArg<String>,
}

#[derive(FromArgs)]
pub struct RebuildDelayImportsArgs {
    #[pyarg(any)]
    pub(crate) descriptors: Vec<PyRef<PeDelayImportDescriptor>>,
    #[pyarg(named, optional)]
    pub(crate) section_name: OptionalArg<String>,
}

#[derive(FromArgs)]
pub struct SanitizeHeadersArgs {
    #[pyarg(named, optional)]
    pub(crate) clear_checksum: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) clear_security_directory: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) clear_bound_import_directory: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) clear_delay_import_directory: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) raw_sections_from_virtual: OptionalArg<bool>,
}

#[derive(FromArgs)]
pub struct CopyHeadersFromArgs {
    #[pyarg(any)]
    pub(crate) source: PyRef<PeImage>,
    #[pyarg(named, optional)]
    pub(crate) keep_image_base: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) keep_image_size: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) keep_entry_point: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) keep_section_raw_layout: OptionalArg<bool>,
    #[pyarg(named, optional)]
    pub(crate) raw_sections_from_virtual: OptionalArg<bool>,
}

pub use super::owned::PeImage;

#[derive(FromArgs)]
pub struct PeNewArgs {
    #[pyarg(any)]
    pub(crate) data: usize,
    #[pyarg(any, optional)]
    pub(crate) size: OptionalArg<usize>,
    #[pyarg(any)]
    pub(crate) is_file: bool,
}

/// Non-owning PE view over a local native address.
///
/// The caller must keep the backing allocation readable and alive for every access. Invalid pointers can crash the host. Prefer br3k.pe.Image for owned bytes and checked analysis; this low-level wrapper uses the native PE parser.
#[pyclass(module = "br3k.pe.native", name = "PtrImage")]
#[derive(Debug, PyPayload)]
pub struct Pe {
    pub pe: PtrPE,
}

impl Constructor for Pe {
    type Args = PeNewArgs;

    /// Wrap a local address as file or mapped PE data. File layout requires size; mapped layout can infer size from headers when omitted.
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
    /// Return whether the native parser identifies the image as X64. This is not a general machine-enum query.
    #[pymethod]
    pub fn is_x64(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<bool> {
        let arch = zelf.pe.get_arch()
            .map_err(map_to_py_system_error(vm, "Unable to read PE architecture"))?;

        Ok(arch == types::Arch::X64)
    }

    /// Return SizeOfImage from the optional header, in bytes.
    #[pymethod]
    fn image_size(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<u32> {
        let image_size = match zelf.pe.get_valid_nt_headers()
            .map_err(map_to_py_system_error(vm, "Unable to read PE NT headers"))? {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.size_of_image,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.size_of_image,
        };

        Ok(image_size)
    }

    /// Return AddressOfEntryPoint as an RVA, despite the historical method name.
    #[pymethod]
    fn ep_address(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<u32> {
        let ep = zelf.pe.get_entrypoint()
            .map_err(map_to_py_system_error(vm, "Unable to read PE entry point"))?;

        Ok(ep.0)
    }

    /// Recreate mapped-layout bytes from the wrapped image. Does not resolve imports or execute the image.
    #[pymethod]
    fn build_mem_image(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let data = zelf.pe.recreate_image(PEType::Memory)
            .map_err(map_to_py_system_error(vm, "Unable to build memory image"))?;
        let bytes = vm.ctx.new_bytes(data.to_vec());

        Ok(bytes)
    }
}
