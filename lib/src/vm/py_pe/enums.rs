use crate::vm::prelude::*;

use crate::vm::adapters::PythonEnum;

macro_rules! python_enums {
    ($(($name:literal, $ty:path)),* $(,)?) => {
        $(impl PythonEnum for $ty {
            fn python_type(vm: &VirtualMachine) -> PyResult<PyObjectRef> { super::namespaces::lookup($name, vm) }
            fn value(self) -> u32 { self as u32 }
        })*

        pub(super) fn register(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            let int_enum = vm.import("enum", 0)?.get_attr("IntEnum", vm)?;
            $(
                let members = vm.ctx.new_dict();
                for item in <$ty as strum::VariantArray>::VARIANTS {
                    let name: &'static str = item.into();
                    members.set_item(name, vm.ctx.new_int(*item as u32).into(), vm)?;
                }
                module.set_attr($name, int_enum.call(($name, members), vm)?, vm)?;
            )*
            Ok(())
        }
    };
}

python_enums! {
    ("Layout", crate::pe::image::Layout),
    ("Stage", crate::pe::diagnostic::Stage),
    ("ExportTableSource", crate::pe::export_map::ExportTableSource),
    ("ResourceChangeKind", crate::pe::diagnostics::resources::ResourceChangeKind),
    ("CheckStatus", crate::pe::headers::CheckStatus),
    ("Severity", crate::pe::diagnostic::Severity),
    ("BuildStatus", crate::pe::image::editor::BuildStatus),
    ("ChangeKind", crate::pe::image::editor::ChangeKind),
    ("ImportWriteMode", crate::pe::imports::ImportWriteMode),
    ("ImportAddressResolveMode", crate::pe::imports::ImportAddressResolveMode),
    ("ImportEvidenceKind", crate::pe::imports::ImportEvidenceKind),
    ("ImportResolutionKind", crate::pe::imports::ImportResolutionKind),
    ("ImportCodeReferenceKind", crate::pe::imports::ImportCodeReferenceKind),
    ("ImportIssueKind", crate::pe::imports::ImportIssueKind),
    ("ImportIssueSeverity", crate::pe::imports::ImportIssueSeverity),
    ("ResourceMergePreference", crate::pe::image::ResourceMergePreference),
    ("SectionRawLayout", crate::pe::image::SectionRawLayout),
    ("EmbeddedImageLayout", crate::pe::embedded::EmbeddedImageLayout),
    ("BoundImportKind", crate::pe::bound_imports::BoundImportKind),
    ("BoundImportStatus", crate::pe::bound_imports::BoundImportStatus),
    ("DelayImportRecoveryStatus", crate::pe::delay_imports::DelayImportRecoveryStatus),
    ("ImportLookupKind", crate::pe::imports::ImportLookupKind),
    ("DirectoryRecoveryStatus", crate::pe::headers::DirectoryRecoveryStatus),
    ("SectionSource", crate::pe::headers::SectionSource),
    ("BaseRelocationKind", crate::pe::relocations::BaseRelocationKind),
    ("HeaderArtifactKind", crate::pe::format::HeaderArtifactKind),
    ("ImportRecoveryStrength", crate::vm::py_pe::types::ImportRecoveryStrength),
    ("ExportResolverSource", crate::vm::py_pe::types::ExportResolverSource),
    ("HiddenModuleReasonKind", crate::vm::py_pe::types::HiddenModuleReasonKind),
    ("FindingKind", crate::vm::py_pe::types::FindingKind),
    ("ThreadStartKind", crate::vm::py_pe::types::ThreadStartKind),
    ("ThreadStackRegionKind", crate::vm::py_pe::types::ThreadStackRegionKind),
    ("ImageAnomalyKind", crate::pe::diagnostics::ImageAnomalyKind),
    ("ImageAnomalySeverity", crate::pe::diagnostics::ImageAnomalySeverity),
}
