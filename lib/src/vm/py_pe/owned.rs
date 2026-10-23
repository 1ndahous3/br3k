use crate::vm::prelude::*;

use crate::pe::image::Image;
use crate::pe::format;
use super::{views, image::ReadRvaArgs};

/// Immutable parsed PE bytes. File offsets and mapped RVAs are never guessed.
///
/// Construct with file bytes, or use from_mapped(data, load_base) for an acquired
/// memory image. Feature views share the backing bytes and retain layout and
/// address context. Parsing headers does not validate every directory or prove
/// that the image can be loaded. edit() creates independent transactional state.
#[pyclass(module = "br3k.pe", name = "Image")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImage { pub(crate) image: Image }

impl PeImage {
    pub(crate) fn from_image(image: Image) -> Self { Self { image } }
    pub(crate) fn from_data(data: Vec<u8>, vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self::from_image(Image::parse(data).map_err(map_to_py_value_error(vm, "Invalid PE image"))?))
    }
}

impl Constructor for PeImage {
    type Args = (PyRef<PyBytes>,);
    /// Parse immutable file-layout PE bytes. Invalid headers raise ValueError.
    fn py_new(_cls: &Py<PyType>, (data,): Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        Self::from_data(data.as_bytes().to_vec(), vm)
    }
}

#[pyclass(with(Constructor))]
impl PeImage {
    /// Parse a file-layout byte buffer; no filesystem access is performed.
    ///
    /// data is PE file content, not a path. Raises ValueError for invalid headers.
    #[pyclassmethod]
    fn from_file(_cls: &Py<PyType>, data: PyRef<PyBytes>, vm: &VirtualMachine) -> PyResult<Self> {
        Self::from_data(data.as_bytes().to_vec(), vm)
    }

    /// Parse mapped bytes at their actual captured load address.
    ///
    /// Use Capture.image() for br3k-acquired memory so missing-range evidence is
    /// retained. This constructor assumes all supplied bytes were acquired.
    #[pyclassmethod]
    fn from_mapped(_cls: &Py<PyType>, data: PyRef<PyBytes>, load_base: u64, vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self::from_image(Image::from_mapped(data.as_bytes().to_vec(), load_base, Vec::new())
            .map_err(map_to_py_value_error(vm, "Invalid mapped PE image"))?))
    }

    /// A copy of the stored bytes in this image's declared layout.
    #[pygetset]
    fn data(&self, vm: &VirtualMachine) -> PyRef<PyBytes> { vm.ctx.new_bytes(self.image.data().to_vec()) }
    /// File or Mapped storage layout; independent of preferred and actual bases.
    #[pygetset]
    fn layout(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::image::Layout>> { PyEnumValue::new(self.image.layout(), vm) }
    /// Actual load address for mapped images, or None for file-layout images.
    #[pygetset]
    fn load_base(&self) -> Option<u64> { self.image.load_base() }
    /// Read-only COFF, optional-header, and data-directory view.
    #[pygetset]
    fn headers(&self) -> views::Headers { views::Headers { image: self.image.clone() } }
    /// Read-only normal, delay, and bound-import views.
    #[pygetset]
    fn imports(&self) -> views::Imports { views::Imports { image: self.image.clone() } }
    /// Read-only resource-tree view.
    #[pygetset]
    fn resources(&self) -> views::Resources { views::Resources { image: self.image.clone() } }
    /// Read-only base-relocation view and candidate discovery.
    #[pygetset]
    fn relocations(&self) -> views::Relocations { views::Relocations { image: self.image.clone() } }
    /// Read-only TLS directory and callback view.
    #[pygetset]
    fn tls(&self) -> views::Tls { views::Tls { image: self.image.clone() } }
    /// Bounded static API-reference analysis over mapped executable bytes.
    #[pygetset]
    fn code(&self) -> views::Code { views::Code { image: self.image.clone() } }
    /// Load-configuration directory view and structural checks.
    #[pygetset]
    fn load_config(&self) -> views::Directory { self.directory_view(format::PE_DIRECTORY_ENTRY_LOAD_CONFIG) }
    /// Exception-directory view and architecture-specific structural checks.
    #[pygetset]
    fn exceptions(&self) -> views::Directory { self.directory_view(format::PE_DIRECTORY_ENTRY_EXCEPTION) }
    /// CLR header directory view and structural checks.
    #[pygetset]
    fn clr(&self) -> views::Directory { self.directory_view(format::PE_DIRECTORY_ENTRY_COM_DESCRIPTOR) }
    /// Debug-directory view and structural checks.
    #[pygetset]
    fn debug(&self) -> views::Directory { self.directory_view(format::PE_DIRECTORY_ENTRY_DEBUG) }
    /// File-only certificate and overlay metadata view.
    #[pygetset]
    fn security(&self) -> views::Security { views::Security { image: self.image.clone() } }
    /// Parse this image's export table. A missing or malformed export directory raises ValueError.
    #[pygetset]
    fn exports(&self, vm: &VirtualMachine) -> PyResult<super::PeExportResolver> {
        Ok(super::PeExportResolver::from_table(self.image.exports().map_err(map_to_py_value_error(vm, "Unable to parse exports"))?))
    }

    /// Section records in section-table order.
    #[pygetset]
    fn sections(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::sections::PeSection>>> {
        let sections = self.image.sections().map_err(map_to_py_value_error(vm, "Unable to read sections"))?;
        Ok(PyListOf::new(sections.into_iter().map(|section| super::sections::section_info_to_py(section, vm)).collect(), vm))
    }

    /// Read a checked RVA range in the image's explicit layout.
    ///
    /// Raises ValueError for an unmapped RVA, a virtual-only file tail, an
    /// ambiguous section range, or bytes missing from the capture. A failed
    /// acquisition is never presented as successfully read zeroes.
    #[pymethod]
    fn read(&self, args: ReadRvaArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let bytes = self.image.read_rva(args.rva, args.size).map_err(map_to_py_value_error(vm, "Unable to read RVA"))?;
        Ok(vm.ctx.new_bytes(bytes.to_vec()))
    }

    /// Convert captured section contents to file layout without modifying this image.
    /// Missing section data raises ValueError. This conversion does not rebuild
    /// imports or certify loader compatibility; use a recovery Plan for repairs.
    #[pymethod]
    fn to_file(&self, vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self::from_image(self.image.to_file().map_err(map_to_py_value_error(vm, "Unable to convert layout"))?))
    }

    /// Map file sections at the preferred base, including loader-zero-filled virtual tails.
    #[pymethod]
    fn to_mapped(&self, vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self::from_image(self.image.to_mapped().map_err(map_to_py_value_error(vm, "Unable to map image"))?))
    }

    /// Find PE-shaped images embedded in this image's bytes, retaining layout and resource context.
    #[pymethod]
    fn embedded_images(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::embedded::PeEmbeddedImage>>> {
        let images = self.image.find_embedded().map_err(map_to_py_value_error(vm, "Unable to find embedded images"))?;
        Ok(super::embedded::embedded_images_to_py(images, vm))
    }

    /// Return cached metadata and structural anomalies for this immutable image.
    #[pymethod]
    fn inspect(&self, vm: &VirtualMachine) -> PyResult<super::PeMetadataSummary> {
        let summary = self.image.inspect()
            .map_err(map_to_py_value_error(vm, "Unable to inspect PE metadata"))?;
        Ok(super::diagnostics::PeMetadataSummary::from_summary(summary.clone()))
    }

    /// Create an independent editor; successful edits never modify this Image.
    #[pymethod]
    fn edit(&self) -> super::editor::Editor { super::editor::Editor::new(self.image.clone()) }

    /// Add the actual mapped load base or preferred file base to an RVA, checking overflow but not image-range membership.
    #[pymethod]
    fn rva_to_va(&self, rva: u32, vm: &VirtualMachine) -> PyResult<u64> {
        self.image.rva_to_va(rva).map_err(map_to_py_value_error(vm, "Invalid RVA"))
    }
    /// Subtract this image's address base from a VA, checking that the result fits a 32-bit RVA. Does not check section membership.
    #[pymethod]
    fn va_to_rva(&self, va: u64, vm: &VirtualMachine) -> PyResult<u32> {
        self.image.va_to_rva(va).map_err(map_to_py_value_error(vm, "Invalid VA"))
    }
}

impl PeImage {
    fn directory_view(&self, index: usize) -> views::Directory { views::Directory { image: self.image.clone(), index } }
}
