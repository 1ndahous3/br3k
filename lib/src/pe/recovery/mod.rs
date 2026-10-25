pub mod imports;
pub mod headers;

#[cfg(test)]
#[path = "../tests/recovery.rs"]
mod tests;

use crate::pe::image::{Image, SanitizeHeadersOptions};
use crate::pe::image::editor::{BuildResult, BuildStatus, Change, ChangeKind, Editor};
use crate::pe::imports::{ImportModel, ImportIssueSeverity, RebuildImportsOptions};

#[derive(Clone, Copy, Debug)]
pub struct BuildPolicy {
    pub allow_partial: bool,
    pub sanitize_headers: bool,
    pub preserve_resources: bool,
    pub discover_relocations: bool,
}

impl Default for BuildPolicy {
    fn default() -> Self {
        Self { allow_partial: false, sanitize_headers: true, preserve_resources: true, discover_relocations: false }
    }
}

impl imports::Plan {
    /// Build the current model against its original capture, then apply independent repair policies.
    pub fn build(&self, model: &ImportModel, policy: BuildPolicy) -> Result<BuildResult, imports::Error> {
        let issues = self.validate(model)?;
        let synthetic_headers = self.header_recovery.as_ref().is_some_and(|recovery| recovery.synthetic);
        let mut partial = issues.iter().any(|issue| issue.severity == ImportIssueSeverity::Error) || !self.diagnostics.is_empty() || synthetic_headers;
        if partial && !policy.allow_partial { return Err(imports::Error::PartialOutput); }
        let mut diagnostics = self.diagnostics.clone();
        if synthetic_headers { diagnostics.push(crate::pe::diagnostic::Diagnostic::warning(crate::pe::diagnostic::Stage::Headers, "Headers were reconstructed heuristically")); }
        let has_imports = model.modules().iter().any(|module| module.valid_function_count != 0) || !self.direct_references.is_empty();
        let image = if has_imports {
            let report = self.rebuild(model, RebuildImportsOptions::default())?;
            if report.patchable_code_references != report.patched_code_references {
                partial = true;
                diagnostics.push(crate::pe::diagnostic::Diagnostic::warning(crate::pe::diagnostic::Stage::Build, "Some direct code references were not patched"));
            }
            Image::parse(report.image)?
        } else {
            // No discovered imports is not proof that the original image needed none.
            partial = true;
            diagnostics.push(crate::pe::diagnostic::Diagnostic::warning(crate::pe::diagnostic::Stage::Imports, "No imports recovered; preserving captured import data without claiming reconstruction"));
            self.input.file.clone()
        };
        if partial && !policy.allow_partial { return Err(imports::Error::PartialOutput); }
        let mut editor = Editor::new(image);
        if policy.preserve_resources {
            match editor.image().resource_info() {
                Ok(_) => (),
                Err(crate::pe::image::Error::DataDirectoryEmpty { .. } | crate::pe::image::Error::DataDirectoryMissing { .. }) => {
                    if let Some(source) = &self.reference {
                        match source.resource_info() {
                            Ok(_) => editor.apply(ChangeKind::Resources, |image| image.copy_resource_directory_from_file(source.data(), ".rsrc"))?,
                            Err(crate::pe::image::Error::DataDirectoryEmpty { .. } | crate::pe::image::Error::DataDirectoryMissing { .. }) => (),
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        if policy.discover_relocations && editor.image().base_relocations()?.is_empty() {
            let discovery = editor.image().discover_relocations()?;
            if !discovery.candidates.is_empty() {
                partial = true;
                diagnostics.push(crate::pe::diagnostic::Diagnostic::warning(crate::pe::diagnostic::Stage::Build, "Relocations were inferred from pointer-shaped values, not proven relocation records"));
                editor.apply(ChangeKind::Relocations, |image| image.add_relocations(&discovery.rvas(), ".reloc").map(|result| result.image))?;
            }
        }
        if policy.sanitize_headers {
            editor.sanitize_headers(SanitizeHeadersOptions { clear_checksum: true, clear_security_directory: true, clear_bound_import_directory: true, ..Default::default() })?;
        }
        let mut result = editor.build()?;
        if partial && !policy.allow_partial { return Err(imports::Error::PartialOutput); }
        if has_imports { result.changes.insert(0, Change { kind: ChangeKind::Imports, revision: 0 }); }
        result.diagnostics = diagnostics;
        result.status = if partial { BuildStatus::Partial } else { BuildStatus::Complete };
        Ok(result)
    }
}
