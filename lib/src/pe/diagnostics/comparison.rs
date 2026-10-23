use super::{compare, DiagnosticsError, ImageComparison};
use crate::pe::{image::{Image, Layout}, exports::ExportError, format};
use std::collections::BTreeMap;
use crate::pe::diagnostic::{Diagnostic, Stage};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)] Image(#[from] crate::pe::image::Error),
    #[error(transparent)] Diagnostics(#[from] DiagnosticsError),
    #[error(transparent)] Exports(#[from] ExportError),
    #[error(transparent)] Relocations(#[from] crate::pe::relocations::RelocationError),
}

#[derive(Clone, Debug)]
pub struct ExportChange {
    pub names: Vec<String>,
    pub rva: u32,
    pub section: String,
    pub before: Vec<u8>,
    pub raw_before: Vec<u8>,
    pub after: Vec<u8>,
}

/// Two immutable images and one normalization policy shared by all comparison components.
#[derive(Clone, Debug)]
pub struct Comparison {
    pub captured: Image,
    pub reference: Image,
    pub normalized_reference: Image,
    pub sections: ImageComparison,
    pub diagnostics: Vec<Diagnostic>,
}

impl Comparison {
    pub fn new(captured: Image, reference: Image) -> Result<Self, Error> {
        captured.require_layout(Layout::Mapped)?;
        captured.validate_reference(&reference)?;
        let mut diagnostics = Vec::new();
        let base = captured.address_base()?;
        let normalized_reference = if base == reference.image_base()? { reference.clone() } else {
            match reference.rebase(base) {
                Ok(report) => Image::parse(report.image)?,
                Err(error) => {
                    diagnostics.push(Diagnostic::warning(Stage::Normalization, format!("Relocation normalization unavailable; raw reference retained: {error}")));
                    reference.clone()
                }
            }
        };
        let sections = compare::compare_images(&captured, &normalized_reference, Default::default())?;
        for section in &sections.sections {
            if let Some(error) = &section.mapped_error { diagnostics.push(Diagnostic::warning(Stage::Capture, format!("{}: {error}", section.name))); }
            if let Some(error) = &section.disk_error { diagnostics.push(Diagnostic::warning(Stage::Reference, format!("{}: {error}", section.name))); }
        }
        for section in reference.section_view()? {
            if !sections.sections.iter().any(|result| result.rva == section.virtual_address) {
                diagnostics.push(Diagnostic::warning(Stage::Comparison, format!("Reference-only section {} at 0x{:x}", section.name, section.virtual_address)));
            }
        }
        Ok(Self { captured, reference, normalized_reference, sections, diagnostics })
    }

    pub fn complete(&self) -> bool { self.diagnostics.is_empty() }

    pub fn byte_changes(&self, options: compare::ByteChangeOptions) -> Result<compare::ImageByteChanges, Error> {
        Ok(compare::byte_changes_images(&self.captured, &self.normalized_reference, options)?)
    }

    pub fn import_changes(&self, symbols: &crate::pe::export_map::ExportMap) -> Result<super::ImportComparison, Error> {
        Ok(super::iat_hooks::compare_imports(&self.captured, &self.reference, symbols)?)
    }

    pub fn export_changes(&self, size: usize) -> Result<Vec<ExportChange>, Error> {
        let exports = match self.reference.exports() {
            Err(ExportError::MissingExportDirectory) => return Ok(Vec::new()),
            result => result?,
        };
        let sections = self.captured.sections()?;
        let mut changes = BTreeMap::<u32, ExportChange>::new();
        for export in exports.symbols.iter().filter(|export| export.forwarder.is_none()) {
            let Some(section) = sections.iter().find(|section| {
                export.rva >= section.virtual_address && (export.rva as u64) < section.virtual_address as u64 + format::section_size(section) as u64
            }) else { continue };
            if !format::section_is_executable(section) { continue; }
            let section_result = self.sections.sections.iter().find(|result| result.rva == section.virtual_address);
            if section_result.is_some_and(|result| result.mapped_error.is_none() && result.disk_error.is_none() && !result.changed) { continue; }
            let before = self.normalized_reference.read_rva(export.rva, size)?.to_vec();
            let raw_before = self.reference.read_rva(export.rva, size)?.to_vec();
            let after = self.captured.read_rva(export.rva, size)?.to_vec();
            if before == after { continue; }
            let change = changes.entry(export.rva).or_insert_with(|| ExportChange {
                names: Vec::new(), rva: export.rva, section: section.name.clone(), before, raw_before, after,
            });
            let names = if export.names.is_empty() { vec![format!("#{}", export.ordinal)] } else { export.names.clone() };
            for name in names { if !change.names.contains(&name) { change.names.push(name); } }
        }
        Ok(changes.into_values().collect())
    }
}
