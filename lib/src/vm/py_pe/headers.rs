use crate::vm::prelude::*;

use crate::pe::headers::{self, DirectoryRecovery};
use crate::vm::py_pe::format::synthetic_image_to_py;
use crate::vm::py_pe::image_resources::data_directory_to_py;
use crate::vm::py_proc::CProcessMemoryRegion;

#[derive(FromArgs)]
pub struct SynthesizeFromRegionsArgs {
    #[pyarg(any)]
    raw_data: PyRef<PyBytes>,
    #[pyarg(any)]
    allocation_base: u64,
    #[pyarg(any)]
    regions: Vec<PyRef<CProcessMemoryRegion>>,
    #[pyarg(named)]
    machine: String,
    #[pyarg(named, optional)]
    is_dll: OptionalArg<bool>,
    #[pyarg(named, optional)]
    entry_point_rva: OptionalArg<u32>,
}

/// Outcome of attempting to salvage one data-directory entry from surviving header evidence.
#[pyclass(module = "br3k.pe.headers", name = "DirectoryRecovery")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDirectoryRecovery {
    data: DirectoryRecovery,
}

#[pyclass]
impl PeDirectoryRecovery {
    /// PE data-directory index.
    #[pygetset]
    fn index(zelf: &Py<Self>) -> usize { zelf.data.index }

    /// Directory address and size associated with this salvage attempt.
    #[pygetset]
    fn directory(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<super::image_resources::PeDataDirectory> { data_directory_to_py(zelf.data.directory, vm) }

    /// Typed restoration outcome, including unsupported, invalid, file-only, and overlapping data.
    #[pygetset]
    fn status(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::headers::DirectoryRecoveryStatus>> {
        PyEnumValue::new(zelf.data.status, vm)
    }

    /// Explanation of an unsuccessful restoration, or None when no error was recorded.
    #[pygetset]
    fn error(zelf: &Py<Self>) -> Option<String> { zelf.data.error.clone() }
}

pub fn synthesize_from_regions(args: SynthesizeFromRegionsArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::format::PeSyntheticImage>> {
    let regions = args.regions.iter().map(|region| region.data.clone()).collect::<Vec<_>>();
    let image = headers::synthesize_from_regions(
        args.raw_data.as_bytes(), args.allocation_base, &regions, &args.machine, args.is_dll.unwrap_or(true), args.entry_point_rva.present(),
    ).map_err(map_to_py_value_error(vm, "Unable to synthesize PE image from regions"))?;
    Ok(synthetic_image_to_py(image, vm))
}

pub(crate) fn directory_recovery_to_py(records: &[DirectoryRecovery], vm: &VirtualMachine) -> PyListOf<PyRef<PeDirectoryRecovery>> {
    PyListOf::new(records.iter().cloned().map(|data| PeDirectoryRecovery { data }.into_ref(&vm.ctx)).collect(), vm)
}
