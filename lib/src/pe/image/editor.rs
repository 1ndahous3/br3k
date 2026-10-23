use super::{Error, Image, Layout, SanitizeHeadersOptions};
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Completeness of a local image build, not a guarantee of loader compatibility or correct execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum BuildStatus {
    /// Build has no retained incompleteness under the applied policy.
    Complete,
    /// Build retained unresolved evidence, diagnostics, or heuristic reconstruction.
    Partial,
}

/// Kind of operation recorded in an image editor's change history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ChangeKind {
    /// Header sanitization, copying, or salvage.
    Headers,
    /// Normal import reconstruction or replacement.
    Imports,
    /// Delay-import restoration or replacement.
    DelayImports,
    /// Resource copying or merging.
    Resources,
    /// Relocation-table construction or rebasing.
    Relocations,
    /// TLS field sanitization.
    Tls,
    /// Direct local byte edits.
    Bytes,
}

#[derive(Clone, Debug)]
pub struct Change {
    pub kind: ChangeKind,
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub struct BuildResult {
    pub image: Image,
    pub status: BuildStatus,
    pub changes: Vec<Change>,
    pub diagnostics: Vec<crate::pe::diagnostic::Diagnostic>,
}

/// Transactional local edits. A failed operation leaves both bytes and revision unchanged.
#[derive(Clone, Debug)]
pub struct Editor {
    image: Image,
    changes: Vec<Change>,
    revision: u64,
}

impl Editor {
    pub fn new(image: Image) -> Self { Self { image, changes: Vec::new(), revision: 0 } }
    pub fn image(&self) -> &Image { &self.image }
    pub fn revision(&self) -> u64 { self.revision }

    pub fn apply_report<R, E: From<Error>>(&mut self, kind: ChangeKind, operation: impl FnOnce(&Image) -> Result<R, E>, bytes: impl FnOnce(&R) -> &[u8]) -> Result<R, E> {
        let report = operation(&self.image)?;
        let data = bytes(&report).to_vec();
        self.apply(kind, |_| Ok::<_, E>(data))?;
        Ok(report)
    }

    pub fn apply<E: From<Error>>(&mut self, kind: ChangeKind, operation: impl FnOnce(&Image) -> Result<Vec<u8>, E>) -> Result<(), E> {
        let data = operation(&self.image)?;
        let image = match self.image.layout() {
            Layout::File => Image::parse(data)?,
            Layout::Mapped => Image::from_mapped(data, self.image.address_base()?, self.image.missing_ranges().to_vec())?,
        };
        self.revision = self.revision.checked_add(1).ok_or(Error::Overflow("incrementing edit revision"))?;
        self.image = image;
        self.changes.push(Change { kind, revision: self.revision });
        Ok(())
    }

    pub fn sanitize_headers(&mut self, options: SanitizeHeadersOptions) -> Result<(), Error> {
        self.apply(ChangeKind::Headers, |image| image.sanitize_headers_with_options(options))
    }

    pub fn build(&self) -> Result<BuildResult, Error> {
        // Byte ownership and section backing must still agree after the last edit.
        self.image.validate_contents()?;
        Ok(BuildResult {
            image: self.image.clone(), changes: self.changes.clone(),
            diagnostics: Vec::new(),
            status: if self.image.missing_ranges().is_empty() { BuildStatus::Complete } else { BuildStatus::Partial },
        })
    }

    pub fn rebase(&mut self, base: u64) -> Result<crate::pe::relocations::RebaseResult, crate::pe::relocations::RelocationError> {
        let report = match self.image.layout() { Layout::File => self.image.rebase(base), Layout::Mapped => self.image.rebase_mapped(base) }?;
        self.apply(ChangeKind::Relocations, |_| Ok::<_, crate::pe::relocations::RelocationError>(report.image.clone()))?;
        if self.image.layout() == Layout::Mapped { self.image.load_base = Some(base); }
        Ok(report)
    }
}
