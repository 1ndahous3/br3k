use super::{Error, Image, Layout, MappedToFileImageOptions};
use crate::pe::{bound_imports, delay_imports, embedded, exports, imports, relocations, tls};

impl Image {
    pub fn validate_reference(&self, reference: &Image) -> Result<(), Error> {
        reference.require_layout(Layout::File)?;
        if self.machine() != reference.machine() { return Err(Error::ReferenceIdentity("machine")); }
        if self.time_date_stamp()? != reference.time_date_stamp()? { return Err(Error::ReferenceIdentity("timestamp")); }
        if self.image_size()? != reference.image_size()? { return Err(Error::ReferenceIdentity("SizeOfImage")); }
        Ok(())
    }

    pub fn validate_contents(&self) -> Result<(), Error> {
        for section in self.section_view()? {
            let size = match self.layout() {
                Layout::File => section.raw_size,
                Layout::Mapped => if section.virtual_size == 0 { section.raw_size } else { section.virtual_size },
            };
            if size != 0 { self.read_rva(section.virtual_address, size as usize)?; }
        }
        Ok(())
    }
    pub fn inspect(&self) -> Result<&crate::pe::diagnostics::MetadataSummary, crate::pe::diagnostics::DiagnosticsError> {
        self.metadata.get_or_init(|| crate::pe::diagnostics::inspect_image(self)).as_ref().map_err(Clone::clone)
    }

    /// Map file bytes at their preferred base. Virtual-only section tails are loader zero-fill.
    pub fn to_mapped(&self) -> Result<Self, Error> {
        if self.layout() == Layout::Mapped { return Ok(self.clone()); }
        let size = self.image_size()? as usize;
        let mut data = Vec::new();
        data.try_reserve_exact(size).map_err(|_| Error::TooSmall("mapped image allocation"))?;
        data.resize(size, 0);
        let headers = self.size_of_headers() as usize;
        let destination = data.get_mut(..headers).ok_or(Error::OutOfBounds { offset: 0, size: headers })?;
        destination.copy_from_slice(self.read_file_rva(0, headers)?);
        for section in self.section_view()? {
            let size = section.raw_size as usize;
            if size == 0 { continue; }
            let offset = section.virtual_address as usize;
            let end = offset.checked_add(size).ok_or(Error::Overflow("mapping file section"))?;
            let destination = data.get_mut(offset..end).ok_or(Error::OutOfBounds { offset, size })?;
            destination.copy_from_slice(self.read_file_rva(section.virtual_address, size)?);
        }
        Self::from_mapped(data, self.image_base()?, Vec::new())
    }
    pub fn to_file(&self) -> Result<Self, Error> {
        if self.layout() == Layout::File { return Ok(self.clone()); }
        self.validate_contents()?;
        Self::parse(self.mapped_to_file_image_with_options(MappedToFileImageOptions {
            image_base: self.load_base(), ..Default::default()
        })?)
    }

    pub fn import_entries(&self) -> Result<Vec<imports::ImportDescriptor>, imports::ImportError> {
        match self.layout() { Layout::File => self.imports(), Layout::Mapped => self.mapped_imports() }
    }

    pub fn delay_entries(&self) -> Result<Vec<delay_imports::DelayImportDescriptor>, delay_imports::DelayImportError> {
        match self.layout() { Layout::File => self.delay_imports(), Layout::Mapped => self.mapped_delay_imports() }
    }

    pub fn bound_entries(&self) -> Result<Vec<bound_imports::BoundImportDescriptor>, bound_imports::BoundImportError> {
        match self.layout() { Layout::File => self.bound_imports(), Layout::Mapped => self.mapped_bound_imports() }
    }

    pub fn check_bound_entries(&self, symbols: &crate::pe::export_map::ExportMap) -> Result<Vec<bound_imports::BoundImportCheck>, bound_imports::BoundImportError> {
        match self.layout() { Layout::File => self.bound_import_checks(symbols), Layout::Mapped => self.mapped_bound_import_checks(symbols) }
    }

    pub fn discover_delay(&self) -> Result<delay_imports::DelayImportRecovery, delay_imports::DelayImportError> {
        match self.layout() { Layout::File => self.recover_delay_imports(), Layout::Mapped => self.recover_mapped_delay_imports() }
    }

    pub fn discover_delay_from(&self, source: &Image) -> Result<delay_imports::DelayImportRecovery, delay_imports::DelayImportError> {
        match self.layout() { Layout::File => self.recover_delay_imports_from(source), Layout::Mapped => self.recover_mapped_delay_imports_from(source) }
    }

    pub fn relocation_entries(&self) -> Result<Vec<relocations::BaseRelocationBlock>, relocations::RelocationError> {
        match self.layout() { Layout::File => self.base_relocations(), Layout::Mapped => self.mapped_base_relocations() }
    }

    pub fn discover_relocations(&self) -> Result<relocations::RelocationDiscovery, relocations::RelocationError> {
        match self.layout() { Layout::File => self.relocation_candidates(), Layout::Mapped => self.mapped_relocation_candidates() }
    }

    pub fn tls(&self) -> Result<Option<tls::TlsDirectory>, tls::TlsError> {
        match self.layout() { Layout::File => self.tls_directory(), Layout::Mapped => self.mapped_tls_directory() }
    }

    pub fn resources(&self) -> Result<Vec<super::ResourceDataEntry>, Error> {
        match self.layout() { Layout::File => self.resource_data_entries(), Layout::Mapped => self.mapped_resource_data_entries() }
    }

    pub fn resource_info(&self) -> Result<super::ResourceDirectoryInfo, Error> {
        match self.layout() { Layout::File => self.resource_directory_info(), Layout::Mapped => self.mapped_resource_directory_info() }
    }

    pub fn exports(&self) -> Result<exports::ExportTable, exports::ExportError> {
        exports::ExportTable::from_image(self, None)
    }

    pub fn find_embedded(&self) -> Result<Vec<embedded::EmbeddedImage>, Error> {
        match self.layout() { Layout::File => self.embedded_images(), Layout::Mapped => self.mapped_embedded_images() }
    }
}
