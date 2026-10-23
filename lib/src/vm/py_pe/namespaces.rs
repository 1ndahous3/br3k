use crate::vm::prelude::*;

// One registration map also drives internal enum lookup and stub/runtime verification.
pub(crate) const TYPES: &[(&str, &str, &str)] = &[
    ("PtrImage", "native", "PtrImage"),
    ("Image", "", "Image"),
    ("Diagnostic", "analysis", "Diagnostic"),
    ("Stage", "analysis", "Stage"),
    ("Severity", "analysis", "Severity"),
    ("Comparison", "analysis", "Comparison"),
    ("ResourceComparison", "analysis", "ResourceComparison"),
    ("ResourceChange", "resources", "Change"),
    ("ResourceChangeKind", "resources", "ChangeKind"),
    ("ByteComparison", "analysis", "ByteComparison"),
    ("ImportComparison", "analysis", "ImportComparison"),
    ("ImportChanges", "analysis", "ImportChanges"),
    ("ExportChanges", "analysis", "ExportChanges"),
    ("ExportChange", "analysis", "ExportChange"),
    ("ProcessView", "", "ProcessView"),
    ("Capture", "", "Capture"),
    ("Editor", "", "Editor"),
    ("BuildResult", "", "BuildResult"),
    ("Change", "recovery", "Change"),
    ("ReadFailure", "analysis", "ReadFailure"),
    ("SourceFailure", "exports", "SourceFailure"),
    ("Headers", "headers", "Headers"),
    ("Directory", "headers", "Directory"),
    ("DirectoryCheck", "headers", "DirectoryCheck"),
    ("CheckStatus", "headers", "CheckStatus"),
    ("Security", "security", "Security"),
    ("Imports", "imports", "Imports"),
    ("DelayImports", "imports", "DelayImports"),
    ("BoundImports", "imports", "BoundImports"),
    ("Resources", "resources", "Resources"),
    ("Relocations", "relocations", "Relocations"),
    ("Tls", "tls", "Tls"),
    ("Code", "code", "Code"),
    ("HeaderEditor", "headers", "Editor"),
    ("ImportEditor", "imports", "Editor"),
    ("DelayEditor", "imports", "DelayEditor"),
    ("ResourceEditor", "resources", "Editor"),
    ("RelocationEditor", "relocations", "Editor"),
    ("TlsEditor", "tls", "Editor"),
    ("DataDirectory", "headers", "DataDirectory"),
    ("OverlayRange", "security", "OverlayRange"),
    ("ResourceDirectoryInfo", "resources", "DirectoryInfo"),
    ("ResourcePathEntry", "resources", "PathEntry"),
    ("ResourceDataEntry", "resources", "DataEntry"),
    ("MemoryRange", "analysis", "MemoryRange"),
    ("ScanFinding", "analysis", "ScanFinding"),
    ("HiddenModuleReason", "analysis", "HiddenModuleReason"),
    ("HiddenModuleScanOptions", "analysis", "HiddenModuleScanOptions"),
    ("HiddenModuleArtifact", "analysis", "HiddenModuleArtifact"),
    ("HiddenModuleCandidate", "analysis", "HiddenModuleCandidate"),
    ("HiddenModuleScanResult", "analysis", "HiddenModuleScanResult"),
    ("ProcessScan", "analysis", "ProcessScan"),
    ("ThreadStartEvidence", "analysis", "ThreadStartEvidence"),
    ("ThreadStackRegion", "analysis", "ThreadStackRegion"),
    ("Section", "headers", "Section"),
    ("ImportCodeReference", "code", "Reference"),
    ("ImportCodeTrace", "code", "Trace"),
    ("ImportBuilder", "imports", "Model"),
    ("AddressSlot", "imports", "AddressSlot"),
    ("ImportAddressTableRange", "imports", "AddressTableRange"),
    ("ImportAddressTableRangeScore", "imports", "AddressTableRangeScore"),
    ("ImportDescriptor", "imports", "Descriptor"),
    ("ImportDescriptorFunction", "imports", "DescriptorFunction"),
    ("ImportModule", "imports", "Module"),
    ("ImportFunction", "imports", "Function"),
    ("ImportEvidence", "imports", "Evidence"),
    ("ImportIssue", "imports", "Issue"),
    ("ImportRebuild", "imports", "Rebuild"),
    ("ExportResolver", "exports", "Table"),
    ("ExportMap", "exports", "Symbols"),
    ("ExportMapRecord", "exports", "Record"),
    ("ExportTableSource", "exports", "SourceKind"),
    ("ApiSetEntry", "exports", "ApiSetEntry"),
    ("ApiSetMap", "exports", "ApiSetMap"),
    ("BoundImportDescriptor", "imports", "BoundDescriptor"),
    ("BoundImportCheck", "imports", "BoundCheck"),
    ("EmbeddedImage", "analysis", "EmbeddedImage"),
    ("DirectoryRecovery", "headers", "DirectoryRecovery"),
    ("BoundForwarderRef", "imports", "BoundForwarder"),
    ("DelayImportDescriptor", "imports", "DelayDescriptor"),
    ("DelayImportCandidate", "imports", "DelayCandidate"),
    ("DelayImportRecovery", "imports", "DelayRecovery"),
    ("DelayImportFunction", "imports", "DelayFunction"),
    ("DelayImportRebuild", "imports", "DelayRebuild"),
    ("BaseRelocationEntry", "relocations", "Entry"),
    ("BaseRelocationBlock", "relocations", "Block"),
    ("RelocationCandidate", "relocations", "Candidate"),
    ("RelocationDiscovery", "relocations", "Discovery"),
    ("RebaseResult", "relocations", "RebaseResult"),
    ("RelocationBuild", "relocations", "Build"),
    ("TlsCallback", "tls", "Callback"),
    ("TlsDirectory", "tls", "Directory"),
    ("TlsSanitizeResult", "tls", "SanitizeResult"),
    ("ExportSymbol", "exports", "Symbol"),
    ("SectionComparison", "analysis", "SectionComparison"),
    ("ImageComparison", "analysis", "SectionReport"),
    ("SectionByteChange", "analysis", "ByteChange"),
    ("ImageByteChanges", "analysis", "ByteChanges"),
    ("ExportPrologueHash", "exports", "PrologueHash"),
    ("ImportAddressChange", "imports", "AddressChange"),
    ("ImageAnomaly", "analysis", "ImageAnomaly"),
    ("SecurityDirectoryInfo", "security", "DirectoryInfo"),
    ("RichHeaderInfo", "analysis", "RichHeaderInfo"),
    ("LoadConfigInfo", "load_config", "Info"),
    ("LoadConfigCodeIntegrityInfo", "load_config", "CodeIntegrityInfo"),
    ("DirectoryInfo", "analysis", "DirectoryInfo"),
    ("TlsDirectoryInfo", "tls", "DirectoryInfo"),
    ("DotNetDirectoryInfo", "clr", "DirectoryInfo"),
    ("PackerHint", "analysis", "PackerHint"),
    ("MetadataSummary", "analysis", "MetadataSummary"),
    ("FileHeader", "headers", "FileHeader"),
    ("HeaderArtifact", "headers", "Artifact"),
    ("SyntheticImage", "headers", "SyntheticImage"),
    ("ImportRecoveryOptions", "recovery", "Options"),
    ("ImportRecoveryResult", "recovery", "Plan"),
    ("Layout", "", "Layout"),
    ("BuildStatus", "recovery", "BuildStatus"),
    ("ChangeKind", "recovery", "ChangeKind"),
    ("ImportWriteMode", "imports", "WriteMode"),
    ("ImportAddressResolveMode", "imports", "AddressResolveMode"),
    ("ImportEvidenceKind", "imports", "EvidenceKind"),
    ("ImportResolutionKind", "imports", "ResolutionKind"),
    ("ImportCodeReferenceKind", "code", "ReferenceKind"),
    ("ImportIssueKind", "imports", "IssueKind"),
    ("ImportIssueSeverity", "imports", "IssueSeverity"),
    ("ResourceMergePreference", "resources", "MergePreference"),
    ("SectionRawLayout", "headers", "SectionRawLayout"),
    ("EmbeddedImageLayout", "analysis", "EmbeddedImageLayout"),
    ("BoundImportKind", "imports", "BoundKind"),
    ("BoundImportStatus", "imports", "BoundStatus"),
    ("DelayImportRecoveryStatus", "imports", "DelayRecoveryStatus"),
    ("ImportLookupKind", "imports", "LookupKind"),
    ("DirectoryRecoveryStatus", "headers", "DirectoryRecoveryStatus"),
    ("SectionSource", "headers", "SectionSource"),
    ("BaseRelocationKind", "relocations", "Kind"),
    ("HeaderArtifactKind", "headers", "ArtifactKind"),
    ("ImportRecoveryStrength", "recovery", "Strength"),
    ("ExportResolverSource", "exports", "SourcePolicy"),
    ("HiddenModuleReasonKind", "analysis", "HiddenModuleReasonKind"),
    ("FindingKind", "analysis", "FindingKind"),
    ("ThreadStartKind", "analysis", "ThreadStartKind"),
    ("ThreadStackRegionKind", "analysis", "ThreadStackRegionKind"),
    ("ImageAnomalyKind", "analysis", "ImageAnomalyKind"),
    ("ImageAnomalySeverity", "analysis", "ImageAnomalySeverity"),
];

pub(crate) fn install(vm: &VirtualMachine, root: &Py<PyModule>) -> PyResult<()> {
    let modules = vm.sys_module.get_attr("modules", vm)?.try_into_value::<PyDictRef>(vm)?;
    for domain in ["native", "analysis", "recovery", "exports", "headers", "imports", "resources", "relocations", "tls", "code", "security", "load_config", "clr"] {
        let name = format!("br3k.pe.{domain}");
        let definition = match domain {
            "headers" => Some(super::api::headers_api::module_def(&vm.ctx)),
            "exports" => Some(super::api::exports_api::module_def(&vm.ctx)),
            "recovery" => Some(super::api::recovery_api::module_def(&vm.ctx)),
            "analysis" => Some(super::api::analysis_api::module_def(&vm.ctx)),
            _ => None,
        };
        let module = if let Some(definition) = definition {
            let module = definition.create_module(vm)?;
            definition.exec_module(vm, &module)?;
            module
        } else { vm.new_module(&name, vm.ctx.new_dict(), None) };
        modules.set_item(&name, module.clone().into(), vm)?;
        root.set_attr(domain, module, vm)?;
    }
    for &(old, domain, name) in TYPES {
        let value = root.get_attr(old, vm)?;
        if !domain.is_empty() {
            let module = root.get_attr(domain, vm)?;
            module.set_attr(name, value.clone(), vm)?;
            root.as_object().del_attr(old, vm)?;
        }
        if value.get_attr("__members__", vm).is_ok() {
            value.set_attr("__module__", vm.ctx.new_str(if domain.is_empty() { "br3k.pe".to_string() } else { format!("br3k.pe.{domain}") }), vm)?;
            value.set_attr("__name__", vm.ctx.new_str(name), vm)?;
            value.set_attr("__qualname__", vm.ctx.new_str(name), vm)?;
        }
    }
    Ok(())
}

pub(crate) fn lookup(old: &'static str, vm: &VirtualMachine) -> PyResult<PyObjectRef> {
    let root = vm.import("br3k", 0)?.get_attr("pe", vm)?;
    match TYPES.iter().find(|entry| entry.0 == old) {
        Some((_, domain, name)) if !domain.is_empty() => root.get_attr(*domain, vm)?.get_attr(*name, vm),
        _ => root.get_attr(old, vm),
    }
}

pub(crate) fn enum_value(value: PyObjectRef, name: &'static str, vm: &VirtualMachine) -> PyResult<u32> {
    let expected = lookup(name, vm)?;
    if !value.class().as_object().is(&expected) {
        return Err(vm.new_type_error(format!("Expected {name}, not {}", value.class().name())));
    }
    value.try_into_value(vm)
}
