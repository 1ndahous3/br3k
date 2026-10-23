use crate::vm::prelude::*;

#[pymodule(name = "br3k.pe")]
pub mod pe {

    use crate::vm::prelude::*;

    use crate::pe::format as raw_format;
    use crate::vm::py_pe;

    use rustpython_vm::extend_module;

    fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
        register_types(vm, module);
        register_constants(vm, module);
        py_pe::enums::register(vm, module)?;
        py_pe::namespaces::install(vm, module)
    }

    fn register_types(vm: &VirtualMachine, module: &Py<PyModule>) {
        extend_module!(vm, module, {
            "PtrImage" => py_pe::Pe::make_static_type(),
            "Image" => py_pe::PeImage::make_static_type(),
            "Diagnostic" => py_pe::diagnostic::Diagnostic::make_static_type(),
            "Comparison" => py_pe::comparison::Comparison::make_static_type(),
            "ResourceComparison" => py_pe::comparison::Resources::make_static_type(),
            "ResourceChange" => py_pe::comparison::ResourceChange::make_static_type(),
            "ByteComparison" => py_pe::comparison::Bytes::make_static_type(),
            "ImportComparison" => py_pe::comparison::Imports::make_static_type(),
            "ImportChanges" => py_pe::comparison::ImportChanges::make_static_type(),
            "ExportChanges" => py_pe::comparison::Exports::make_static_type(),
            "ExportChange" => py_pe::comparison::ExportChange::make_static_type(),
            "ProcessView" => py_pe::process::ProcessView::make_static_type(),
            "Capture" => py_pe::process::Capture::make_static_type(),
            "Editor" => py_pe::editor::Editor::make_static_type(),
            "BuildResult" => py_pe::editor::BuildResult::make_static_type(),
            "Change" => py_pe::editor::Change::make_static_type(),
            "ReadFailure" => py_pe::process::ReadFailure::make_static_type(),
            "SourceFailure" => py_pe::process::SourceFailure::make_static_type(),
            "Headers" => py_pe::views::Headers::make_static_type(),
            "Directory" => py_pe::views::Directory::make_static_type(),
            "DirectoryCheck" => py_pe::views::DirectoryCheck::make_static_type(),
            "Security" => py_pe::views::Security::make_static_type(),
            "Imports" => py_pe::views::Imports::make_static_type(),
            "DelayImports" => py_pe::views::DelayImports::make_static_type(),
            "BoundImports" => py_pe::views::BoundImports::make_static_type(),
            "Resources" => py_pe::views::Resources::make_static_type(),
            "Relocations" => py_pe::views::Relocations::make_static_type(),
            "Tls" => py_pe::views::Tls::make_static_type(),
            "Code" => py_pe::views::Code::make_static_type(),
            "HeaderEditor" => py_pe::editor::HeaderEditor::make_static_type(),
            "ImportEditor" => py_pe::editor::ImportEditor::make_static_type(),
            "DelayEditor" => py_pe::editor::DelayEditor::make_static_type(),
            "ResourceEditor" => py_pe::editor::ResourceEditor::make_static_type(),
            "RelocationEditor" => py_pe::editor::RelocationEditor::make_static_type(),
            "TlsEditor" => py_pe::editor::TlsEditor::make_static_type(),
            "DataDirectory" => py_pe::PeDataDirectory::make_static_type(),
            "OverlayRange" => py_pe::PeOverlayRange::make_static_type(),
            "ResourceDirectoryInfo" => py_pe::PeResourceDirectoryInfo::make_static_type(),
            "ResourcePathEntry" => py_pe::PeResourcePathEntry::make_static_type(),
            "ResourceDataEntry" => py_pe::PeResourceDataEntry::make_static_type(),
            "MemoryRange" => py_pe::PeMemoryRange::make_static_type(),
            "ScanFinding" => py_pe::PeScanFinding::make_static_type(),
            "HiddenModuleReason" => py_pe::PeHiddenModuleReason::make_static_type(),
            "HiddenModuleScanOptions" => py_pe::PeHiddenModuleScanOptions::make_static_type(),
            "HiddenModuleArtifact" => py_pe::PeHiddenModuleArtifact::make_static_type(),
            "HiddenModuleCandidate" => py_pe::PeHiddenModuleCandidate::make_static_type(),
            "HiddenModuleScanResult" => py_pe::PeHiddenModuleScanResult::make_static_type(),
            "ProcessScan" => py_pe::PeProcessScan::make_static_type(),
            "ThreadStartEvidence" => py_pe::PeThreadStartEvidence::make_static_type(),
            "ThreadStackRegion" => py_pe::PeThreadStackRegion::make_static_type(),
            "Section" => py_pe::PeSection::make_static_type(),
            "ImportCodeReference" => py_pe::PeImportCodeReference::make_static_type(),
            "ImportCodeTrace" => py_pe::PeImportCodeTrace::make_static_type(),
            "ImportBuilder" => py_pe::PeImportBuilder::make_static_type(),
            "AddressSlot" => py_pe::imports::AddressSlot::make_static_type(),
            "ImportAddressTableRange" => py_pe::PeImportAddressTableRange::make_static_type(),
            "ImportAddressTableRangeScore" => py_pe::PeImportAddressTableRangeScore::make_static_type(),
            "ImportDescriptor" => py_pe::PeImportDescriptor::make_static_type(),
            "ImportDescriptorFunction" => py_pe::PeImportDescriptorFunction::make_static_type(),
            "ImportModule" => py_pe::PeImportModule::make_static_type(),
            "ImportFunction" => py_pe::PeImportFunction::make_static_type(),
            "ImportEvidence" => py_pe::PeImportEvidence::make_static_type(),
            "ImportIssue" => py_pe::PeImportIssue::make_static_type(),
            "ImportRebuild" => py_pe::PeImportRebuild::make_static_type(),
            "ExportResolver" => py_pe::PeExportResolver::make_static_type(),
            "ExportMap" => py_pe::PeExportMap::make_static_type(),
            "ExportMapRecord" => py_pe::PeExportMapRecord::make_static_type(),
            "ApiSetEntry" => py_pe::PeApiSetEntry::make_static_type(),
            "ApiSetMap" => py_pe::PeApiSetMap::make_static_type(),
            "BoundImportDescriptor" => py_pe::PeBoundImportDescriptor::make_static_type(),
            "BoundImportCheck" => py_pe::PeBoundImportCheck::make_static_type(),
            "EmbeddedImage" => py_pe::PeEmbeddedImage::make_static_type(),
            "DirectoryRecovery" => py_pe::PeDirectoryRecovery::make_static_type(),
            "BoundForwarderRef" => py_pe::PeBoundForwarderRef::make_static_type(),
            "DelayImportDescriptor" => py_pe::PeDelayImportDescriptor::make_static_type(),
            "DelayImportCandidate" => py_pe::delay_imports::PeDelayImportCandidate::make_static_type(),
            "DelayImportRecovery" => py_pe::delay_imports::PeDelayImportRecovery::make_static_type(),
            "DelayImportFunction" => py_pe::PeDelayImportFunction::make_static_type(),
            "DelayImportRebuild" => py_pe::PeDelayImportRebuild::make_static_type(),
            "BaseRelocationEntry" => py_pe::PeBaseRelocationEntry::make_static_type(),
            "BaseRelocationBlock" => py_pe::PeBaseRelocationBlock::make_static_type(),
            "RelocationCandidate" => py_pe::PeRelocationCandidate::make_static_type(),
            "RelocationDiscovery" => py_pe::PeRelocationDiscovery::make_static_type(),
            "RebaseResult" => py_pe::PeRebaseResult::make_static_type(),
            "RelocationBuild" => py_pe::PeRelocationBuild::make_static_type(),
            "TlsCallback" => py_pe::PeTlsCallback::make_static_type(),
            "TlsDirectory" => py_pe::PeTlsDirectory::make_static_type(),
            "TlsSanitizeResult" => py_pe::PeTlsSanitizeResult::make_static_type(),
            "ExportSymbol" => py_pe::PeExportSymbol::make_static_type(),
            "SectionComparison" => py_pe::PeSectionComparison::make_static_type(),
            "ImageComparison" => py_pe::PeImageComparison::make_static_type(),
            "SectionByteChange" => py_pe::PeSectionByteChange::make_static_type(),
            "ImageByteChanges" => py_pe::PeImageByteChanges::make_static_type(),
            "ExportPrologueHash" => py_pe::PeExportPrologueHash::make_static_type(),
            "ImportAddressChange" => py_pe::PeImportAddressChange::make_static_type(),
            "ImageAnomaly" => py_pe::PeImageAnomaly::make_static_type(),
            "SecurityDirectoryInfo" => py_pe::PeSecurityDirectoryInfo::make_static_type(),
            "RichHeaderInfo" => py_pe::PeRichHeaderInfo::make_static_type(),
            "LoadConfigInfo" => py_pe::PeLoadConfigInfo::make_static_type(),
            "LoadConfigCodeIntegrityInfo" => py_pe::PeLoadConfigCodeIntegrityInfo::make_static_type(),
            "DirectoryInfo" => py_pe::PeDirectoryInfo::make_static_type(),
            "TlsDirectoryInfo" => py_pe::PeTlsDirectoryInfo::make_static_type(),
            "DotNetDirectoryInfo" => py_pe::PeDotNetDirectoryInfo::make_static_type(),
            "PackerHint" => py_pe::PePackerHint::make_static_type(),
            "MetadataSummary" => py_pe::PeMetadataSummary::make_static_type(),
            "FileHeader" => py_pe::PeFileHeader::make_static_type(),
            "HeaderArtifact" => py_pe::PeHeaderArtifact::make_static_type(),
            "SyntheticImage" => py_pe::PeSyntheticImage::make_static_type(),
            "ImportRecoveryOptions" => py_pe::PeImportRecoveryOptions::make_static_type(),
            "ImportRecoveryResult" => py_pe::PeImportRecoveryResult::make_static_type(),
        });
    }

    fn register_constants(vm: &VirtualMachine, module: &Py<PyModule>) {
        extend_module!(vm, module, {
            "PE_DIRECTORY_ENTRY_EXPORT" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_EXPORT),
            "PE_DIRECTORY_ENTRY_IMPORT" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_IMPORT),
            "PE_DIRECTORY_ENTRY_RESOURCE" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_RESOURCE),
            "PE_DIRECTORY_ENTRY_EXCEPTION" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_EXCEPTION),
            "PE_DIRECTORY_ENTRY_SECURITY" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_SECURITY),
            "PE_DIRECTORY_ENTRY_BASERELOC" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_BASERELOC),
            "PE_DIRECTORY_ENTRY_DEBUG" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_DEBUG),
            "PE_DIRECTORY_ENTRY_ARCHITECTURE" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_ARCHITECTURE),
            "PE_DIRECTORY_ENTRY_GLOBALPTR" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_GLOBALPTR),
            "PE_DIRECTORY_ENTRY_TLS" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_TLS),
            "PE_DIRECTORY_ENTRY_LOAD_CONFIG" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_LOAD_CONFIG),
            "PE_DIRECTORY_ENTRY_BOUND_IMPORT" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_BOUND_IMPORT),
            "PE_DIRECTORY_ENTRY_IAT" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_IAT),
            "PE_DIRECTORY_ENTRY_DELAY_IMPORT" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_DELAY_IMPORT),
            "PE_DIRECTORY_ENTRY_COM_DESCRIPTOR" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
            "PE_DIRECTORY_ENTRY_RESERVED" => vm.ctx.new_int(raw_format::PE_DIRECTORY_ENTRY_RESERVED),
            "PE_DATA_DIRECTORY_NAMES" => data_directory_names(vm),
            "IMAGE_DOS_SIGNATURE" => vm.ctx.new_int(raw_format::IMAGE_DOS_SIGNATURE),
            "IMAGE_NT_SIGNATURE" => vm.ctx.new_int(raw_format::IMAGE_NT_SIGNATURE),
            "IMAGE_FILE_EXECUTABLE_IMAGE" => vm.ctx.new_int(raw_format::IMAGE_FILE_EXECUTABLE_IMAGE),
            "IMAGE_FILE_LARGE_ADDRESS_AWARE" => vm.ctx.new_int(raw_format::IMAGE_FILE_LARGE_ADDRESS_AWARE),
            "IMAGE_FILE_32BIT_MACHINE" => vm.ctx.new_int(raw_format::IMAGE_FILE_32BIT_MACHINE),
            "IMAGE_FILE_DLL" => vm.ctx.new_int(raw_format::IMAGE_FILE_DLL),
            "IMAGE_FILE_MACHINE_I386" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_I386),
            "IMAGE_FILE_MACHINE_AMD64" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_AMD64),
            "IMAGE_FILE_MACHINE_ARM64" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_ARM64),
            "IMAGE_FILE_MACHINE_ARM64EC" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_ARM64EC),
            "IMAGE_FILE_MACHINE_ARM64X" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_ARM64X),
            "IMAGE_FILE_MACHINE_CHPE_X86" => vm.ctx.new_int(raw_format::IMAGE_FILE_MACHINE_CHPE_X86),
            "IMAGE_NT_OPTIONAL_HDR32_MAGIC" => vm.ctx.new_int(raw_format::IMAGE_NT_OPTIONAL_HDR32_MAGIC),
            "IMAGE_NT_OPTIONAL_HDR64_MAGIC" => vm.ctx.new_int(raw_format::IMAGE_NT_OPTIONAL_HDR64_MAGIC),
            "IMAGE_SCN_CNT_INITIALIZED_DATA" => vm.ctx.new_int(raw_format::IMAGE_SCN_CNT_INITIALIZED_DATA),
            "IMAGE_SCN_MEM_EXECUTE" => vm.ctx.new_int(raw_format::IMAGE_SCN_MEM_EXECUTE),
            "IMAGE_SCN_MEM_READ" => vm.ctx.new_int(raw_format::IMAGE_SCN_MEM_READ),
            "IMAGE_SCN_MEM_WRITE" => vm.ctx.new_int(raw_format::IMAGE_SCN_MEM_WRITE),
            "IMAGE_GUARD_CF_INSTRUMENTED" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_INSTRUMENTED),
            "IMAGE_GUARD_CFW_INSTRUMENTED" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CFW_INSTRUMENTED),
            "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT),
            "IMAGE_GUARD_SECURITY_COOKIE_UNUSED" => vm.ctx.new_int(raw_format::IMAGE_GUARD_SECURITY_COOKIE_UNUSED),
            "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_PROTECT_DELAYLOAD_IAT),
            "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION" => vm.ctx.new_int(raw_format::IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION),
            "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT),
            "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION),
            "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT),
            "IMAGE_GUARD_RF_INSTRUMENTED" => vm.ctx.new_int(raw_format::IMAGE_GUARD_RF_INSTRUMENTED),
            "IMAGE_GUARD_RF_ENABLE" => vm.ctx.new_int(raw_format::IMAGE_GUARD_RF_ENABLE),
            "IMAGE_GUARD_RF_STRICT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_RF_STRICT),
            "IMAGE_GUARD_RETPOLINE_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_RETPOLINE_PRESENT),
            "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT),
            "IMAGE_GUARD_XFG_ENABLED" => vm.ctx.new_int(raw_format::IMAGE_GUARD_XFG_ENABLED),
            "IMAGE_GUARD_CASTGUARD_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CASTGUARD_PRESENT),
            "IMAGE_GUARD_MEMCPY_PRESENT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_MEMCPY_PRESENT),
            "IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK),
            "IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT" => vm.ctx.new_int(raw_format::IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT),
            "MAX_SECTIONS" => vm.ctx.new_int(raw_format::MAX_SECTIONS),
            "SECTION_HEADER_SIZE" => vm.ctx.new_int(raw_format::SECTION_HEADER_SIZE),
        });
    }

    fn data_directory_names(vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        let names = raw_format::PE_DATA_DIRECTORY_NAMES
            .iter()
            .map(|name| vm.ctx.new_str(*name))
            .collect::<Vec<_>>();

        PyListOf::new(names, vm)
    }
}

#[pymodule(name = "br3k.pe.recovery")]
pub mod recovery_api {
    use crate::vm::prelude::*;
    use crate::vm::py_pe;

    /// Analyze a mapped image offline with explicit symbols and an optional matching
    /// file reference. Returns the same source-bound Plan used by ProcessView.recover().
    #[pyfunction]
    fn analyze(args: py_pe::recovery::AnalyzeArgs, vm: &VirtualMachine) -> PyResult<py_pe::PeImportRecoveryResult> {
        py_pe::recovery::analyze(args, vm)
    }

}

#[pymodule(name = "br3k.pe.exports")]
pub mod exports_api {
    use crate::vm::prelude::*;
    use crate::vm::py_pe;

    /// Hash executable export entries in file bytes, grouping aliases at one RVA.
    /// Hashes are baseline comparison evidence, not a security verdict.
    #[pyfunction]
    fn prologue_hashes(args: py_pe::diagnostics::ExportPrologueHashesArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<py_pe::diagnostics::PeExportPrologueHash>>> {
        py_pe::diagnostics::export_prologue_hashes(args, vm)
    }

}

#[pymodule(name = "br3k.pe.analysis")]
pub mod analysis_api {
    use crate::vm::prelude::*;
    use crate::vm::py_pe;

    /// Inspect an explicitly selected process-memory span as a candidate.
    /// This is an expert selection primitive, not confirmation of a hidden PE.
    #[pyfunction]
    fn candidate(args: py_pe::hidden::ManualHiddenModuleCandidateArgs, vm: &VirtualMachine) -> PyResult<py_pe::PeHiddenModuleCandidate> {
        py_pe::hidden::manual_hidden_module_candidate(args, vm)
    }

}

#[pymodule(name = "br3k.pe.headers")]
pub mod headers_api {
    use crate::vm::prelude::*;
    use crate::vm::py_pe;

    /// Return the known architecture label for a COFF machine value, or its hexadecimal representation when unknown.
    #[pyfunction]
    fn machine_name(machine: u16) -> String {
        py_pe::format::machine_name(machine)
    }

    /// Resolve a case-insensitive architecture label to its COFF machine value.
    ///
    /// Accepts x86/i386, x64/amd64, arm64/aarch64, arm64ec, arm64x, and chpe_x86/chpe-x86/chpe. Unknown labels raise ValueError.
    #[pyfunction]
    fn machine_value(machine: PyStrRef, vm: &VirtualMachine) -> PyResult<u16> {
        py_pe::format::machine_value(machine, vm)
    }

    /// Return the standard PE directory name for an index, or None when out of range.
    #[pyfunction]
    fn data_directory_name(index: usize) -> Option<&'static str> {
        py_pe::format::data_directory_name(index)
    }

    /// Decode the eight-byte section-name field at offset. Return None for truncated, empty, or non-printable names.
    #[pyfunction]
    fn section_name(args: py_pe::format::SectionNameArgs) -> Option<String> {
        py_pe::format::section_name(args)
    }

    /// Parse one candidate section header; return None when the bytes are unsuitable.
    #[pyfunction]
    fn parse_section_header(args: py_pe::format::ParseSectionHeaderArgs, vm: &VirtualMachine) -> Option<PyRef<py_pe::sections::PeSection>> {
        py_pe::format::parse_section_header(args, vm)
    }

    /// Parse a candidate section table without claiming that a complete PE exists.
    #[pyfunction]
    fn parse_section_table(args: py_pe::format::ParseSectionTableArgs, vm: &VirtualMachine) -> Option<PyListOf<PyRef<py_pe::sections::PeSection>>> {
        py_pe::format::parse_section_table(args, vm)
    }

    /// Parse surviving COFF/optional-header evidence, or return None.
    #[pyfunction]
    fn parse_file_header(args: py_pe::format::ParseFileHeaderArgs, vm: &VirtualMachine) -> Option<PyRef<py_pe::format::PeFileHeader>> {
        py_pe::format::parse_file_header(args, vm)
    }

    /// Scan supplied bytes for PE, COFF, and section-table artifacts.
    /// Scores are ranking evidence and can include false positives.
    #[pyfunction]
    fn scan_artifacts(args: py_pe::format::ScanHeaderArtifactsArgs, vm: &VirtualMachine) -> PyListOf<PyRef<py_pe::format::PeHeaderArtifact>> {
        py_pe::format::scan_header_artifacts(args, vm)
    }

    /// Calculate a page-aligned image extent from section ranges and the supplied minimum size. Arithmetic overflow raises ValueError.
    #[pyfunction]
    fn image_size_from_sections(args: py_pe::format::ImageSizeFromSectionsArgs, vm: &VirtualMachine) -> PyResult<u32> {
        py_pe::format::image_size_from_sections(args, vm)
    }

    /// Return the first executable section's RVA, falling back to the first section, or zero for an empty sequence.
    #[pyfunction]
    fn first_executable_section_rva(args: py_pe::format::FirstExecutableSectionRvaArgs) -> u32 {
        py_pe::format::first_executable_section_rva(args)
    }

    /// Construct mapped analysis headers from explicit section evidence.
    /// Synthetic output is not proof of a recovered, loadable executable.
    #[pyfunction]
    fn synthesize(args: py_pe::format::SynthesizeMappedImageArgs, vm: &VirtualMachine) -> PyResult<PyRef<py_pe::format::PeSyntheticImage>> {
        py_pe::format::synthesize_mapped_image(args, vm)
    }

    /// Construct analysis sections from memory-region layout and protections.
    /// The result may add a header prefix while preserving captured virtual addresses.
    #[pyfunction]
    fn synthesize_from_regions(args: py_pe::headers::SynthesizeFromRegionsArgs, vm: &VirtualMachine) -> PyResult<PyRef<py_pe::format::PeSyntheticImage>> {
        py_pe::headers::synthesize_from_regions(args, vm)
    }

    /// Return a normalized header fingerprint for file-layout PE bytes.
    ///
    /// Normalizes selected mutable header fields before hashing. This is comparison evidence, not a cryptographic integrity or authenticity check.
    #[pyfunction]
    fn normalized_hash(args: py_pe::diagnostics::NormalizedHeaderHashArgs, vm: &VirtualMachine) -> PyResult<u64> {
        py_pe::diagnostics::normalized_header_hash(args, vm)
    }

}
