use crate::vm::prelude::*;

use crate::pe::image::{Image, Layout, SanitizeHeadersOptions, TrustedHeadersOptions};
use crate::pe::image::editor::{self as raw, ChangeKind};
use super::owned::PeImage;
use std::cell::RefCell;
use std::rc::Rc;

#[py_api]
#[derive(FromArgs)]
pub struct MergeResourcesArgs {
    #[pyarg(any)] reference: PyRef<PeImage>,
    #[pyarg(any)] captured: PyRef<PeImage>,
    #[pyi(ty = "br3k.pe.resources.MergePreference")]
    #[pyarg(named, optional)] prefer: OptionalArg<PyObjectRef>,
    #[pyarg(named, optional)] section_name: OptionalArg<String>,
}

#[py_api]
#[derive(FromArgs)]
pub struct ReplaceImportsArgs {
    #[pyarg(any)] model: PyRef<super::PeImportBuilder>,
    #[pyi(ty = "br3k.pe.imports.WriteMode")]
    #[pyarg(named, optional)] mode: OptionalArg<PyObjectRef>,
    #[pyarg(named, optional)] section_name: OptionalArg<String>,
    #[pyarg(named, optional)] clear_bound_imports: OptionalArg<bool>,
    #[pyarg(named, optional)] clear_delay_imports: OptionalArg<bool>,
    #[pyarg(named, optional)] import_by_ordinal: OptionalArg<bool>,
    #[pyarg(named, optional)] references: OptionalArg<Vec<PyRef<super::PeImportCodeReference>>>,
    #[pyarg(named, optional)] stub_section_name: OptionalArg<String>,
}

/// Local transactional editor. Feature editors share one revision; the source Image stays unchanged.
/// Obtain with Image.edit(). A failed operation leaves bytes and revision unchanged.
/// File-structure rebuilds require file layout; TLS clearing and rebasing support
/// both layouts. No operation writes to the source process.
#[pyclass(module = "br3k.pe", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct Editor { state: Rc<RefCell<raw::Editor>> }

impl Editor {
    pub(crate) fn new(image: Image) -> Self { Self { state: Rc::new(RefCell::new(raw::Editor::new(image))) } }
}

#[pyclass]
impl Editor {
    /// Revision of the local editor state after successful edits.
    #[pygetset]
    fn revision(&self) -> u64 { self.state.borrow().revision() }
    /// Header editor sharing this editor's image and revision.
    #[pygetset]
    fn headers(&self) -> HeaderEditor { HeaderEditor { state: self.state.clone() } }
    /// Import editor sharing this editor's image and revision.
    #[pygetset]
    fn imports(&self) -> ImportEditor { ImportEditor { state: self.state.clone() } }
    /// Resource editor sharing this editor's image and revision.
    #[pygetset]
    fn resources(&self) -> ResourceEditor { ResourceEditor { state: self.state.clone() } }
    /// Relocation editor sharing this editor's image and revision.
    #[pygetset]
    fn relocations(&self) -> RelocationEditor { RelocationEditor { state: self.state.clone() } }
    /// TLS editor sharing this editor's image and revision.
    #[pygetset]
    fn tls(&self) -> TlsEditor { TlsEditor { state: self.state.clone() } }
    /// Validate the current revision and return owned output plus applied changes.
    /// Output retains the editor's layout. Convert result.image.to_file() explicitly
    /// before writing mapped output as a PE file. Does not certify loader compatibility.
    #[pymethod]
    fn build(&self, vm: &VirtualMachine) -> PyResult<BuildResult> {
        Ok(BuildResult { result: self.state.borrow().build().map_err(map_to_py_value_error(vm, "Unable to build edited image"))? })
    }
}

/// A serialized image and its build outcome. Complete does not promise loader/execution compatibility.
#[pyclass(module = "br3k.pe", name = "BuildResult")]
#[derive(Clone, Debug, PyPayload)]
pub struct BuildResult { pub(crate) result: raw::BuildResult }

#[pyclass]
impl BuildResult {
    /// Diagnostics produced while validating and building this result.
    #[pygetset]
    fn diagnostics(&self, vm: &VirtualMachine) -> PyListOf<PyRef<super::diagnostic::Diagnostic>> { super::diagnostic::to_py(&self.result.diagnostics, vm) }
    /// Immutable image snapshot containing the resulting local bytes.
    #[pygetset]
    fn image(&self) -> PeImage { PeImage::from_image(self.result.image.clone()) }
    /// Complete or Partial under the selected checks; never a loadability guarantee.
    #[pygetset]
    fn status(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::image::editor::BuildStatus>> {
        PyEnumValue::new(self.result.status, vm)
    }
    /// Successful edits included in this build, in operation order.
    #[pygetset]
    fn changes(&self, vm: &VirtualMachine) -> PyListOf<PyRef<Change>> {
        PyListOf::new(self.result.changes.iter().cloned().map(|change| Change { change }.into_ref(&vm.ctx)).collect(), vm)
    }
}

/// One successful local edit, identified by its operation kind and resulting revision.
#[pyclass(module = "br3k.pe.recovery", name = "Change")]
#[derive(Clone, Debug, PyPayload)]
pub struct Change { change: raw::Change }
#[pyclass]
impl Change {
    /// Kind of edit performed.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::image::editor::ChangeKind>> { PyEnumValue::new(self.change.kind, vm) }
    /// Revision of the local editor state after successful edits.
    #[pygetset]
    fn revision(&self) -> u64 { self.change.revision }
}

/// Header operations on the owning Editor's local image. All feature editors share that editor's state.
#[pyclass(module = "br3k.pe.headers", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct HeaderEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl HeaderEditor {
    /// Clear selected stale header fields without changing the source Image.
    #[pymethod]
    fn sanitize(&self, args: super::image::SanitizeHeadersArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.state.borrow_mut().sanitize_headers(SanitizeHeadersOptions {
            clear_checksum: args.clear_checksum.unwrap_or(true),
            clear_security_directory: args.clear_security_directory.unwrap_or(true),
            clear_bound_import_directory: args.clear_bound_import_directory.unwrap_or(true),
            clear_delay_import_directory: args.clear_delay_import_directory.unwrap_or(false),
            raw_sections_from_virtual: args.raw_sections_from_virtual.unwrap_or(false),
        }).map_err(map_to_py_value_error(vm, "Unable to sanitize headers"))
    }

    /// Copy trusted headers with explicit preservation of live address/layout fields.
    /// Incompatible headers raise ValueError and do not advance the edit revision.
    #[pymethod]
    fn copy_from(&self, args: super::image::CopyHeadersFromArgs, vm: &VirtualMachine) -> PyResult<()> {
        self.state.borrow_mut().apply(ChangeKind::Headers, |image| image.copy_headers_from_trusted(args.source.image.data(), TrustedHeadersOptions {
            keep_image_base: args.keep_image_base.unwrap_or(true), keep_image_size: args.keep_image_size.unwrap_or(true),
            keep_entry_point: args.keep_entry_point.unwrap_or(true), keep_section_raw_layout: args.keep_section_raw_layout.unwrap_or(true),
            raw_sections_from_virtual: args.raw_sections_from_virtual.unwrap_or(false),
        }))
            .map_err(map_to_py_value_error(vm, "Unable to copy trusted headers"))
    }

    /// Validate and restore supported directories independently from surviving header
    /// bytes. Returned records preserve invalid, unsupported, and file-only outcomes.
    #[pymethod]
    fn salvage(&self, source: PyRef<PyBytes>, file_header_offset: usize, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::headers::PeDirectoryRecovery>>> {
        let mut records = Vec::new();
        self.state.borrow_mut().apply(ChangeKind::Headers, |image| {
            let mut image = image.clone();
            records = image.salvage_directories(source.as_bytes(), file_header_offset)?;
            Ok::<_, crate::pe::headers::HeaderError>(image.into_data())
        }).map_err(map_to_py_value_error(vm, "Unable to salvage directories"))?;
        Ok(super::headers::directory_recovery_to_py(&records, vm))
    }
}

/// TLS sanitization operations on the owning Editor's local image. These never invoke callbacks.
#[pyclass(module = "br3k.pe.tls", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct TlsEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl TlsEditor {
    /// Clear the TLS callback pointer in the local image and return the changed bytes and TLS edit details.
    #[pymethod]
    fn clear_callbacks(&self, vm: &VirtualMachine) -> PyResult<PyRef<super::tls::PeTlsSanitizeResult>> {
        let report = self.state.borrow_mut().apply_report(ChangeKind::Tls, |image| {
            match image.layout() { Layout::File => image.clear_tls_callbacks(), Layout::Mapped => image.clear_mapped_tls_callbacks() }
        }, |report| &report.image).map_err(map_to_py_value_error(vm, "Unable to clear TLS callbacks"))?;
        Ok(super::tls::tls_sanitize_result_to_py(report, vm))
    }
    /// Clear the TLS data-directory entry in the local image and return the changed bytes and TLS edit details.
    #[pymethod]
    fn clear(&self, vm: &VirtualMachine) -> PyResult<PyRef<super::tls::PeTlsSanitizeResult>> {
        let report = self.state.borrow_mut().apply_report(ChangeKind::Tls, |image| image.clear_tls_directory(), |report| &report.image)
            .map_err(map_to_py_value_error(vm, "Unable to clear TLS directory"))?;
        Ok(super::tls::tls_sanitize_result_to_py(report, vm))
    }
}

/// Normal and delay-import edits on the owning Editor's local file-layout image.
#[pyclass(module = "br3k.pe.imports", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct ImportEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl ImportEditor {
    /// Delay-import editor sharing the same local image.
    #[pygetset]
    fn delay(&self) -> DelayEditor { DelayEditor { state: self.state.clone() } }
    /// Rebuild imports on a file-layout image using a matching target pointer size.
    /// mode selects slot preservation or a new IAT. Returned evidence describes
    /// code-reference patching; a failed rebuild leaves the revision unchanged.
    #[pymethod]
    fn replace(&self, args: ReplaceImportsArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::import_records::PeImportRebuild>> {
        if args.model.pointer_size() != self.state.borrow().image().pointer_size() {
            return Err(vm.new_value_error("Import model pointer size differs from the edited image"));
        }
        let mode = args.mode.present().map(|value| super::namespaces::enum_value(value, "ImportWriteMode", vm)).transpose()?;
        let mode = mode.and_then(crate::pe::imports::ImportWriteMode::from_repr).unwrap_or(crate::pe::imports::ImportWriteMode::PreserveIatSlots);
        let options = crate::pe::imports::RebuildImportsOptions {
            write_mode: mode, section_name: args.section_name.unwrap_or(".idata".into()),
            clear_bound_imports: args.clear_bound_imports.unwrap_or(true), clear_delay_imports: args.clear_delay_imports.unwrap_or(false),
            import_by_ordinal: args.import_by_ordinal.unwrap_or(false),
            code_references: args.references.present().unwrap_or_default().iter().map(|reference| reference.to_import_code_reference()).collect(),
            code_stub_section_name: args.stub_section_name.unwrap_or(".br3kstb".into()),
        };
        let report = self.state.borrow_mut().apply_report(ChangeKind::Imports, |image| {
            image.require_layout(Layout::File)?;
            crate::pe::imports::rebuild_imports_with_report(image.data(), &args.model.model_clone(), options)
        }, |report| &report.image).map_err(map_to_py_value_error(vm, "Unable to replace import model"))?;
        Ok(super::import_records::import_rebuild_to_py(report, vm))
    }
}

/// Delay-import restoration and rebuilding on the owning Editor's local image.
#[pyclass(module = "br3k.pe.imports", name = "DelayEditor")]
#[derive(Clone, Debug, PyPayload)]
pub struct DelayEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl DelayEditor {
    /// Restore delay-import state from recovery evidence into the local image. Supports file and mapped layouts.
    #[pymethod]
    fn restore(&self, recovery: PyRef<super::delay_imports::PeDelayImportRecovery>, vm: &VirtualMachine) -> PyResult<()> {
        self.state.borrow_mut().apply(ChangeKind::DelayImports, |image| match image.layout() {
            Layout::File => image.restore_delay_imports(&recovery.recovery),
            Layout::Mapped => image.restore_mapped_delay_imports(&recovery.recovery),
        }).map_err(map_to_py_value_error(vm, "Unable to restore delay imports"))
    }
    /// Rebuild delay-import descriptors in a file-layout image, using .didat as the default new section name.
    #[pymethod]
    fn replace(&self, args: super::image::RebuildDelayImportsArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::delay_imports::PeDelayImportRebuild>> {
        let descriptors = args.descriptors.iter().map(|entry| entry.descriptor_clone()).collect::<Vec<_>>();
        let name = args.section_name.unwrap_or(".didat".to_string());
        let report = self.state.borrow_mut().apply_report(ChangeKind::DelayImports, |image| {
            image.require_layout(Layout::File)?;
            image.rebuild_delay_imports(&descriptors, &name)
        }, |report| &report.image).map_err(map_to_py_value_error(vm, "Unable to replace delay imports"))?;
        Ok(super::delay_imports::delay_import_rebuild_to_py(report, vm))
    }
}

/// Resource merging and copying on the owning Editor's local file-layout image.
#[pyclass(module = "br3k.pe.resources", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct ResourceEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl ResourceEditor {
    /// Merge typed resource paths, retaining explicit conflict preference.
    #[pymethod]
    fn merge(&self, args: MergeResourcesArgs, vm: &VirtualMachine) -> PyResult<()> {
        let preference = args.prefer.present().map(|value| super::namespaces::enum_value(value, "ResourceMergePreference", vm)).transpose()?;
        let preference = super::image_resources::resource_merge_preference(preference.unwrap_or(0), vm)?;
        args.reference.image.require_layout(Layout::File).map_err(map_to_py_value_error(vm, "Resource reference"))?;
        args.captured.image.require_layout(Layout::Mapped).map_err(map_to_py_value_error(vm, "Resource capture"))?;
        args.reference.image.validate_contents().map_err(map_to_py_value_error(vm, "Incomplete resource reference"))?;
        args.captured.image.validate_contents().map_err(map_to_py_value_error(vm, "Incomplete resource capture"))?;
        let section_name = args.section_name.unwrap_or(".rsrc".into());
        self.state.borrow_mut().apply(ChangeKind::Resources, |image| {
            image.require_layout(Layout::File)?;
            image.copy_merged_resource_directory_from_file_and_mapped_image(args.reference.image.data(), args.captured.image.data(), &section_name, preference)
        }).map_err(map_to_py_value_error(vm, "Unable to merge resources"))
    }
    /// Copy resource data from a file or mapped image with captured section contents.
    /// Missing data raises ValueError rather than becoming fabricated resource bytes.
    #[pymethod]
    fn copy_from(&self, source: PyRef<PeImage>, vm: &VirtualMachine) -> PyResult<()> {
        source.image.validate_contents().map_err(map_to_py_value_error(vm, "Incomplete resource source"))?;
        self.state.borrow_mut().apply(ChangeKind::Resources, |image| {
            image.require_layout(Layout::File)?;
            match source.image.layout() {
                Layout::File => image.copy_resource_directory_from_file(source.image.data(), ".rsrc"),
                Layout::Mapped => image.copy_resource_directory_from_mapped_image(source.image.data(), ".rsrc"),
            }
        }).map_err(map_to_py_value_error(vm, "Unable to copy resources"))
    }
}

/// Relocation-table construction and local image rebasing on the owning Editor's state.
#[pyclass(module = "br3k.pe.relocations", name = "Editor")]
#[derive(Clone, Debug, PyPayload)]
pub struct RelocationEditor { state: Rc<RefCell<raw::Editor>> }
#[pyclass]
impl RelocationEditor {
    /// Build a relocation table from the supplied RVAs in a file-layout image. The default section name is .reloc.
    #[pymethod]
    fn add(&self, args: super::image::AddRelocationsArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::relocations::PeRelocationBuild>> {
        let name = args.section_name.unwrap_or(".reloc".into());
        let report = self.state.borrow_mut().apply_report(ChangeKind::Relocations, |image| {
            image.require_layout(Layout::File)?;
            image.add_relocations(&args.rvas, &name)
        }, |report| &report.image).map_err(map_to_py_value_error(vm, "Unable to add relocations"))?;
        Ok(super::relocations::relocation_build_to_py(report, vm))
    }
    /// Apply the image's supported relocations to a new base in the local image. The target process is not modified.
    #[pymethod]
    fn rebase(&self, base: u64, vm: &VirtualMachine) -> PyResult<PyRef<super::relocations::PeRebaseResult>> {
        let report = self.state.borrow_mut().rebase(base).map_err(map_to_py_value_error(vm, "Unable to rebase image"))?;
        Ok(super::relocations::rebase_result_to_py(report, vm))
    }
}
