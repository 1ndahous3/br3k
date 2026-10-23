use crate::vm::prelude::*;

use crate::pe::image::SectionInfo;

#[derive(FromArgs)]
pub struct PeSectionNewArgs {
    #[pyarg(named)]
    name: PyStrRef,
    #[pyarg(named)]
    virtual_address: u32,
    #[pyarg(named)]
    virtual_size: u32,
    #[pyarg(named)]
    raw_offset: u32,
    #[pyarg(named)]
    raw_size: u32,
    #[pyarg(named)]
    characteristics: u32,
}

#[derive(FromArgs)]
pub struct PeSectionContainsRvaArgs {
    #[pyarg(any)]
    rva: u32,
}

/// PE section-header record with explicit virtual and file ranges. Constructing a record does not add a section to an image.
#[pyclass(module = "br3k.pe.headers", name = "Section")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSection {
    pub(super) name: String,
    pub(super) virtual_address: u32,
    pub(super) virtual_size: u32,
    pub(super) raw_offset: u32,
    pub(super) raw_size: u32,
    pub(super) characteristics: u32,
}

impl Constructor for PeSection {
    type Args = PeSectionNewArgs;

    /// Create a section record from named header fields. Values are stored without validating a complete image layout.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, _vm: &VirtualMachine) -> PyResult<Self> {
        Ok(Self {
            name: args.name.to_string(),
            virtual_address: args.virtual_address,
            virtual_size: args.virtual_size,
            raw_offset: args.raw_offset,
            raw_size: args.raw_size,
            characteristics: args.characteristics,
        })
    }
}

#[pyclass(with(Constructor))]
impl PeSection {
    /// Decoded section name.
    #[pygetset]
    fn name(&self) -> String {
        self.name.clone()
    }

    /// Section start RVA.
    #[pygetset]
    fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    /// VirtualSize from the section header, in bytes.
    #[pygetset]
    fn virtual_size(&self) -> u32 {
        self.virtual_size
    }

    /// PointerToRawData file offset.
    #[pygetset]
    fn raw_offset(&self) -> u32 {
        self.raw_offset
    }

    /// SizeOfRawData from the section header, in bytes.
    #[pygetset]
    fn raw_size(&self) -> u32 {
        self.raw_size
    }

    /// Raw IMAGE_SCN_* section characteristics.
    #[pygetset]
    fn characteristics(&self) -> u32 {
        self.characteristics
    }

    /// Return the larger of virtual_size and raw_size, in bytes.
    #[pymethod]
    fn size(&self) -> u32 {
        crate::pe::format::section_size(&self.to_section_info())
    }

    /// Return whether IMAGE_SCN_MEM_EXECUTE is set. This does not query runtime page protection.
    #[pymethod]
    fn is_executable(&self) -> bool {
        crate::pe::format::section_is_executable(&self.to_section_info())
    }

    /// Return whether the RVA lies in the section's size() span, excluding its end.
    #[pymethod]
    fn contains_rva(&self, args: PeSectionContainsRvaArgs) -> bool {
        let size = crate::pe::format::section_size(&self.to_section_info());
        args.rva >= self.virtual_address && args.rva < self.virtual_address.saturating_add(size)
    }

    /// Return a compact human-readable section summary.
    #[pymethod]
    fn summary(&self) -> String {
        crate::pe::format::section_summary(&self.to_section_info())
    }
}

impl PeSection {
    pub(crate) fn to_section_info(&self) -> SectionInfo {
        SectionInfo {
            name: self.name.clone(),
            virtual_address: self.virtual_address,
            virtual_size: self.virtual_size,
            raw_offset: self.raw_offset,
            raw_size: self.raw_size,
            characteristics: self.characteristics,
        }
    }
}

pub(crate) fn section_info_to_py(section: SectionInfo, vm: &VirtualMachine) -> PyRef<PeSection> {
    PeSection {
        name: section.name,
        virtual_address: section.virtual_address,
        virtual_size: section.virtual_size,
        raw_offset: section.raw_offset,
        raw_size: section.raw_size,
        characteristics: section.characteristics,
    }
    .into_ref(&vm.ctx)
}
