use crate::vm::prelude::*;

use crate::pe::diagnostics as raw_diagnostics;
use crate::vm::py_pe::exports::export_table_source_to_py;


#[derive(FromArgs)]
pub struct NormalizedHeaderHashArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
}

#[derive(FromArgs)]
pub struct ExportPrologueHashesArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(named, optional)]
    image_base: OptionalArg<u64>,
    #[pyarg(named, optional)]
    module_name: OptionalArg<PyStrRef>,
    #[pyarg(named, optional)]
    prologue_size: OptionalArg<usize>,
}

/// Comparison of one normalized mapped section with its disk reference.
///
/// Missing hashes carry an error description; a mismatch is evidence of change,
/// not attribution to a hook, packer, or malicious component.
#[pyclass(module = "br3k.pe.analysis", name = "SectionComparison")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSectionComparison {
    comparison: raw_diagnostics::SectionComparison,
}

#[pyclass]
impl PeSectionComparison {
    /// Section name used for the comparison.
    #[pygetset]
    fn name(&self) -> String {
        self.comparison.name.clone()
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.comparison.rva
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.comparison.size
    }

    /// Whether the compared section has the executable characteristic.
    #[pygetset]
    fn executable(&self) -> bool {
        self.comparison.executable
    }

    /// Fingerprint of the mapped bytes; unavailable comparisons return None.
    #[pygetset]
    fn mapped_hash(&self) -> Option<u64> {
        self.comparison.mapped_hash
    }

    /// Fingerprint of the normalized disk-reference bytes; unavailable comparisons return None.
    #[pygetset]
    fn disk_hash(&self) -> Option<u64> {
        self.comparison.disk_hash
    }

    /// Reason mapped bytes could not be compared, or None.
    #[pygetset]
    fn mapped_error(&self) -> Option<String> {
        self.comparison.mapped_error.clone()
    }

    /// Reason reference bytes could not be compared, or None.
    #[pygetset]
    fn disk_error(&self) -> Option<String> {
        self.comparison.disk_error.clone()
    }

    /// Whether comparable section content differs.
    #[pygetset]
    fn changed(&self) -> bool {
        self.comparison.changed
    }
}

/// Section-level comparison results, including failed comparisons and changed-section filters.
#[pyclass(module = "br3k.pe.analysis", name = "SectionReport")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImageComparison {
    comparison: raw_diagnostics::ImageComparison,
}

impl PeImageComparison {
    pub(crate) fn from_comparison(comparison: raw_diagnostics::ImageComparison) -> Self { Self { comparison } }
}

#[pyclass]
impl PeImageComparison {
    /// Per-section comparison records, including errors.
    #[pygetset]
    fn sections(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeSectionComparison>> {
        section_comparisons_to_py(&self.comparison.sections, vm)
    }

    /// Number of sections reported as changed.
    #[pygetset]
    fn changed_count(&self) -> usize {
        self.comparison.changed_count()
    }

    /// Number of changed sections marked executable.
    #[pygetset]
    fn changed_executable_count(&self) -> usize {
        self.comparison.changed_executable_count()
    }

    /// Return names of all sections reported as changed.
    #[pymethod]
    fn changed_section_names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        string_list_to_py(&self.comparison.changed_section_names(), vm)
    }

    /// Return names of changed executable sections.
    #[pymethod]
    fn changed_executable_section_names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        string_list_to_py(&self.comparison.changed_executable_section_names(), vm)
    }
}

/// One differing byte range within a compared section, with bounded samples.
#[pyclass(module = "br3k.pe.analysis", name = "ByteChange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSectionByteChange {
    change: raw_diagnostics::SectionByteChange,
}

#[pyclass]
impl PeSectionByteChange {
    /// Name of the containing section.
    #[pygetset]
    fn section_name(&self) -> String {
        self.change.section_name.clone()
    }

    /// Image-relative start address of the containing section.
    #[pygetset]
    fn section_rva(&self) -> u32 {
        self.change.section_rva
    }

    /// Whether the compared section has the executable characteristic.
    #[pygetset]
    fn executable(&self) -> bool {
        self.change.executable
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.change.rva
    }

    /// Byte offset of the change from the containing section's start.
    #[pygetset]
    fn offset(&self) -> u32 {
        self.change.offset
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.change.size
    }

    /// Fingerprint of the mapped bytes.
    #[pygetset]
    fn mapped_hash(&self) -> u64 {
        self.change.mapped_hash
    }

    /// Fingerprint of the normalized disk-reference bytes.
    #[pygetset]
    fn disk_hash(&self) -> u64 {
        self.change.disk_hash
    }

    /// Bounded sample of mapped bytes from this change.
    #[pygetset]
    fn mapped_sample(&self, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(self.change.mapped_sample.clone())
    }

    /// Bounded sample of reference bytes from this change.
    #[pygetset]
    fn disk_sample(&self, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(self.change.disk_sample.clone())
    }

    /// Whether samples omit bytes from the full changed range.
    #[pygetset]
    fn sample_truncated(&self) -> bool {
        self.change.sample_truncated
    }

    /// Format the record's location, evidence, and comparison details for display.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{} rva=0x{:x} size=0x{:x} mapped_hash=0x{:x} disk_hash=0x{:x}",
            self.change.section_name,
            self.change.rva,
            self.change.size,
            self.change.mapped_hash,
            self.change.disk_hash,
        )
    }
}

/// Bounded collection of changed byte ranges and aggregate comparison counters.
#[pyclass(module = "br3k.pe.analysis", name = "ByteChanges")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImageByteChanges {
    pub(crate) changes: raw_diagnostics::ImageByteChanges,
}

#[pyclass]
impl PeImageByteChanges {
    /// Individual changed byte ranges retained within the reporting limit.
    #[pygetset]
    fn ranges(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeSectionByteChange>> {
        section_byte_changes_to_py(&self.changes.ranges, vm)
    }

    /// Number of sections compared.
    #[pygetset]
    fn compared_section_count(&self) -> usize {
        self.changes.compared_section_count
    }

    /// Number of sections containing changed bytes.
    #[pygetset]
    fn changed_section_count(&self) -> usize {
        self.changes.changed_section_count
    }

    /// Number of differing bytes counted by the comparison.
    #[pygetset]
    fn changed_byte_count(&self) -> usize {
        self.changes.changed_byte_count
    }

    /// Number of retained changed-range records.
    #[pygetset]
    fn range_count(&self) -> usize {
        self.changes.range_count()
    }

    /// Whether reporting limits prevented retaining every changed range.
    #[pygetset]
    fn truncated(&self) -> bool {
        self.changes.truncated
    }
}

/// Fingerprint of bytes at an export RVA, collapsing aliases that share that RVA.
#[pyclass(module = "br3k.pe.exports", name = "PrologueHash")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeExportPrologueHash {
    hash: raw_diagnostics::ExportPrologueHash,
}

#[pyclass]
impl PeExportPrologueHash {
    /// All export display names sharing the prologue RVA.
    #[pygetset]
    fn names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        string_list_to_py(&self.hash.names, vm)
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.hash.rva
    }

    /// Content fingerprint used for comparison, not a cryptographic authenticity check.
    #[pygetset]
    fn hash(&self) -> u64 {
        self.hash.hash
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> usize {
        self.hash.size
    }
}

/// An IAT slot whose actual target differs from the export-derived expected target.
#[pyclass(module = "br3k.pe.imports", name = "AddressChange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportAddressChange {
    pub(crate) change: raw_diagnostics::ImportAddressChange,
}

#[pyclass]
impl PeImportAddressChange {
    /// Module named by the import descriptor.
    #[pygetset]
    fn module_name(&self) -> String {
        self.change.module_name.clone()
    }

    /// Imported symbol name, or None for an ordinal import.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.change.name.clone()
    }

    /// Imported ordinal when the import is ordinal-based.
    #[pygetset]
    fn ordinal(&self) -> Option<u16> {
        self.change.ordinal
    }

    /// Image-relative address of the changed IAT slot.
    #[pygetset]
    fn iat_rva(&self) -> u32 {
        self.change.iat_rva
    }

    /// Expected target virtual address resolved from the reference exports.
    #[pygetset]
    fn expected_address(&self) -> u64 {
        self.change.expected_address
    }

    /// Module supplying the expected target, after forwarding resolution.
    #[pygetset]
    fn expected_module_name(&self) -> String {
        self.change.expected_module_name.clone()
    }

    /// Expected target's export name when available.
    #[pygetset]
    fn expected_name(&self) -> Option<String> {
        self.change.expected_name.clone()
    }

    /// Expected target's export ordinal.
    #[pygetset]
    fn expected_ordinal(&self) -> u32 {
        self.change.expected_ordinal
    }

    /// Source policy result used for the expected export.
    #[pygetset]
    fn expected_source(&self, vm: &VirtualMachine) -> PyResult<Option<PyEnumValue<crate::pe::export_map::ExportTableSource>>> {
        export_table_source_to_py(Some(self.change.expected_source), vm)
    }

    /// Pointer value observed in the mapped IAT slot.
    #[pygetset]
    fn actual_address(&self) -> u64 {
        self.change.actual_address
    }

    /// Resolved module for the observed pointer, or None if unresolved.
    #[pygetset]
    fn actual_module_name(&self) -> Option<String> {
        self.change.actual_module_name.clone()
    }

    /// Resolved export name for the observed pointer, or None.
    #[pygetset]
    fn actual_name(&self) -> Option<String> {
        self.change.actual_name.clone()
    }

    /// Resolved export ordinal for the observed pointer, or None.
    #[pygetset]
    fn actual_ordinal(&self) -> Option<u32> {
        self.change.actual_ordinal
    }

    /// Source of the observed target's export metadata, or None if unresolved.
    #[pygetset]
    fn actual_source(&self, vm: &VirtualMachine) -> PyResult<Option<PyEnumValue<crate::pe::export_map::ExportTableSource>>> {
        export_table_source_to_py(self.change.actual_source, vm)
    }

    /// Format the record's location, evidence, and comparison details for display.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{}!{} iat=0x{:x} expected={} actual={}",
            self.change.module_name,
            import_target_text(self.change.name.as_deref(), self.change.ordinal),
            self.change.iat_rva,
            export_target_text(
                &self.change.expected_module_name,
                self.change.expected_name.as_deref(),
                Some(self.change.expected_ordinal),
                self.change.expected_address,
            ),
            resolved_address_text(
                self.change.actual_module_name.as_deref(),
                self.change.actual_name.as_deref(),
                self.change.actual_ordinal,
                self.change.actual_address,
            ),
        )
    }
}

/// A typed structural or metadata anomaly, with optional image-relative location.
#[pyclass(module = "br3k.pe.analysis", name = "ImageAnomaly")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImageAnomaly {
    anomaly: raw_diagnostics::ImageAnomaly,
}

#[pyclass]
impl PeImageAnomaly {
    /// Typed anomaly category for programmatic filtering.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::diagnostics::ImageAnomalyKind>> {
        PyEnumValue::new(self.anomaly.kind, vm)
    }

    /// Typed severity assigned by the structural checks.
    #[pygetset]
    fn severity(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::diagnostics::ImageAnomalySeverity>> {
        PyEnumValue::new(self.anomaly.severity, vm)
    }

    /// Associated section name, or None for image-wide anomalies.
    #[pygetset]
    fn section_name(&self) -> Option<String> {
        self.anomaly.section_name.clone()
    }

    /// PE data-directory index involved in the anomaly, or None.
    #[pygetset]
    fn directory_index(&self) -> Option<usize> {
        self.anomaly.directory_index
    }

    /// Display name of the involved data directory, or None.
    #[pygetset]
    fn directory_name(&self) -> Option<String> {
        self.anomaly.directory_name.clone()
    }

    /// Image-relative virtual address of this item; None where no location is available.
    #[pygetset]
    fn rva(&self) -> Option<u32> {
        self.anomaly.rva
    }

    /// Extent in bytes, or None when the extent is unknown.
    #[pygetset]
    fn size(&self) -> Option<u32> {
        self.anomaly.size
    }

    /// Human-readable explanation of the anomaly.
    #[pygetset]
    fn message(&self) -> String {
        self.anomaly.message.clone()
    }

    /// Format the record's location, evidence, and comparison details for display.
    #[pymethod]
    fn summary(&self) -> String {
        let mut text = format!(
            "{} {}",
            self.anomaly.severity.as_str(),
            self.anomaly.kind.as_str(),
        );
        if let Some(section_name) = &self.anomaly.section_name {
            text.push_str(&format!(" section={section_name}"));
        }
        if let Some(directory_name) = &self.anomaly.directory_name {
            text.push_str(&format!(" directory={directory_name}"));
        }
        if let Some(rva) = self.anomaly.rva {
            text.push_str(&format!(" rva=0x{rva:x}"));
        }
        if let Some(size) = self.anomaly.size {
            text.push_str(&format!(" size=0x{size:x}"));
        }
        text.push_str(&format!(": {}", self.anomaly.message));

        text
    }
}

/// Certificate-table location. Its address is a file offset, unlike other PE directories.
///
/// Presence does not validate an Authenticode signature; certificate data is not
/// normally part of the mapped image.
#[pyclass(module = "br3k.pe.security", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSecurityDirectoryInfo {
    info: raw_diagnostics::SecurityDirectoryInfo,
}

#[pyclass]
impl PeSecurityDirectoryInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Certificate-table byte offset in file layout, not an RVA.
    #[pygetset]
    fn file_offset(&self) -> u32 {
        self.info.file_offset
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.info.size
    }
}

/// Detected Rich-header extent, XOR key, and content fingerprint; not a trust verdict.
#[pyclass(module = "br3k.pe.analysis", name = "RichHeaderInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeRichHeaderInfo {
    info: raw_diagnostics::RichHeaderInfo,
}

#[pyclass]
impl PeRichHeaderInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Byte offset of the Rich header from the start of the file.
    #[pygetset]
    fn offset(&self) -> usize {
        self.info.offset
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> usize {
        self.info.size
    }

    /// XOR key stored in the Rich header.
    #[pygetset]
    fn key(&self) -> u32 {
        self.info.key
    }

    /// Content fingerprint used for comparison, not a cryptographic authenticity check.
    #[pygetset]
    fn hash(&self) -> u64 {
        self.info.hash
    }
}

/// Parsed load-configuration fields and mitigation metadata.
///
/// Optional fields are None when absent from the available structure, not zero.
/// Pointer-valued fields retain PE virtual addresses; counts, flags, RVAs, and
/// section-relative offsets retain their native meanings. These describe image
/// metadata, not proof that the OS enabled a mitigation.
#[pyclass(module = "br3k.pe.load_config", name = "Info")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeLoadConfigInfo {
    info: raw_diagnostics::LoadConfigInfo,
}

#[pyclass]
impl PeLoadConfigInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.info.rva
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.info.size
    }

    /// Size declared inside the load-config structure, when readable.
    #[pygetset]
    fn structure_size(&self) -> Option<u32> {
        self.info.structure_size
    }

    /// Raw load-config TimeDateStamp value.
    #[pygetset]
    fn time_date_stamp(&self) -> Option<u32> {
        self.info.time_date_stamp
    }

    /// Declared load-config major version.
    #[pygetset]
    fn major_version(&self) -> Option<u16> {
        self.info.major_version
    }

    /// Declared load-config minor version.
    #[pygetset]
    fn minor_version(&self) -> Option<u16> {
        self.info.minor_version
    }

    /// Declared dependent-load flags.
    #[pygetset]
    fn dependent_load_flags(&self) -> Option<u16> {
        self.info.dependent_load_flags
    }

    /// Declared process-heap flags.
    #[pygetset]
    fn process_heap_flags(&self) -> Option<u32> {
        self.info.process_heap_flags
    }

    /// Virtual address of the security-cookie storage.
    #[pygetset]
    fn security_cookie(&self) -> Option<u64> {
        self.info.security_cookie
    }

    /// Virtual address of the SafeSEH handler table.
    #[pygetset]
    fn se_handler_table(&self) -> Option<u64> {
        self.info.se_handler_table
    }

    /// Number of SafeSEH handler entries.
    #[pygetset]
    fn se_handler_count(&self) -> Option<u64> {
        self.info.se_handler_count
    }

    /// Virtual address of the CFG check-function pointer slot.
    #[pygetset]
    fn guard_cf_check_function_pointer(&self) -> Option<u64> {
        self.info.guard_cf_check_function_pointer
    }

    /// Virtual address of the CFG dispatch-function pointer slot.
    #[pygetset]
    fn guard_cf_dispatch_function_pointer(&self) -> Option<u64> {
        self.info.guard_cf_dispatch_function_pointer
    }

    /// Virtual address of the CFG function table.
    #[pygetset]
    fn guard_cf_function_table(&self) -> Option<u64> {
        self.info.guard_cf_function_table
    }

    /// Number of CFG function-table entries.
    #[pygetset]
    fn guard_cf_function_count(&self) -> Option<u64> {
        self.info.guard_cf_function_count
    }

    /// Raw GuardFlags bitfield.
    #[pygetset]
    fn guard_flags(&self) -> Option<u32> {
        self.info.guard_flags
    }

    /// Recognized GuardFlags names for display.
    #[pygetset]
    fn guard_flag_names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        let names = self.info
            .guard_flag_names()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();

        string_list_to_py(&names, vm)
    }

    /// Compatibility spelling of guard_flag_names.
    #[pygetset]
    fn guard_flags_names(&self, vm: &VirtualMachine) -> PyListOf<PyStrRef> {
        self.guard_flag_names(vm)
    }

    /// CFG table-entry size in bytes derived from GuardFlags, or None.
    #[pygetset]
    fn guard_cf_function_table_entry_size(&self) -> Option<u32> {
        self.info.guard_cf_function_table_entry_size()
    }

    /// Parsed CodeIntegrity record when the load-config structure contains it.
    #[pygetset]
    fn code_integrity(&self, vm: &VirtualMachine) -> Option<PyRef<PeLoadConfigCodeIntegrityInfo>> {
        match self.info.code_integrity.clone() {
            Some(info) => Some(PeLoadConfigCodeIntegrityInfo { info }.into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Virtual address of the address-taken IAT-entry table.
    #[pygetset]
    fn guard_address_taken_iat_entry_table(&self) -> Option<u64> {
        self.info.guard_address_taken_iat_entry_table
    }

    /// Number of address-taken IAT entries.
    #[pygetset]
    fn guard_address_taken_iat_entry_count(&self) -> Option<u64> {
        self.info.guard_address_taken_iat_entry_count
    }

    /// Virtual address of the guarded long-jump target table.
    #[pygetset]
    fn guard_long_jump_target_table(&self) -> Option<u64> {
        self.info.guard_long_jump_target_table
    }

    /// Number of guarded long-jump targets.
    #[pygetset]
    fn guard_long_jump_target_count(&self) -> Option<u64> {
        self.info.guard_long_jump_target_count
    }

    /// Virtual address of the dynamic-value relocation table.
    #[pygetset]
    fn dynamic_value_reloc_table(&self) -> Option<u64> {
        self.info.dynamic_value_reloc_table
    }

    /// Virtual address of CHPE/hybrid-image metadata.
    #[pygetset]
    fn chpe_metadata_pointer(&self) -> Option<u64> {
        self.info.chpe_metadata_pointer
    }

    /// Virtual address of the return-flow-guard failure routine.
    #[pygetset]
    fn guard_rf_failure_routine(&self) -> Option<u64> {
        self.info.guard_rf_failure_routine
    }

    /// Virtual address of the return-flow-guard failure-function pointer slot.
    #[pygetset]
    fn guard_rf_failure_routine_function_pointer(&self) -> Option<u64> {
        self.info.guard_rf_failure_routine_function_pointer
    }

    /// Dynamic relocation table offset within the indicated section.
    #[pygetset]
    fn dynamic_value_reloc_table_offset(&self) -> Option<u32> {
        self.info.dynamic_value_reloc_table_offset
    }

    /// Section index associated with the dynamic relocation table offset.
    #[pygetset]
    fn dynamic_value_reloc_table_section(&self) -> Option<u16> {
        self.info.dynamic_value_reloc_table_section
    }

    /// Virtual address of the return-flow-guard stack-verification pointer slot.
    #[pygetset]
    fn guard_rf_verify_stack_pointer_function_pointer(&self) -> Option<u64> {
        self.info.guard_rf_verify_stack_pointer_function_pointer
    }

    /// Declared hotpatch table offset.
    #[pygetset]
    fn hot_patch_table_offset(&self) -> Option<u32> {
        self.info.hot_patch_table_offset
    }

    /// Virtual address of enclave configuration.
    #[pygetset]
    fn enclave_configuration_pointer(&self) -> Option<u64> {
        self.info.enclave_configuration_pointer
    }

    /// Virtual address of volatile metadata.
    #[pygetset]
    fn volatile_metadata_pointer(&self) -> Option<u64> {
        self.info.volatile_metadata_pointer
    }

    /// Virtual address of the guarded exception-continuation table.
    #[pygetset]
    fn guard_eh_continuation_table(&self) -> Option<u64> {
        self.info.guard_eh_continuation_table
    }

    /// Number of guarded exception-continuation targets.
    #[pygetset]
    fn guard_eh_continuation_count(&self) -> Option<u64> {
        self.info.guard_eh_continuation_count
    }

    /// Virtual address of the XFG check-function pointer slot.
    #[pygetset]
    fn guard_xfg_check_function_pointer(&self) -> Option<u64> {
        self.info.guard_xfg_check_function_pointer
    }

    /// Virtual address of the XFG dispatch-function pointer slot.
    #[pygetset]
    fn guard_xfg_dispatch_function_pointer(&self) -> Option<u64> {
        self.info.guard_xfg_dispatch_function_pointer
    }

    /// Virtual address of the XFG table-dispatch pointer slot.
    #[pygetset]
    fn guard_xfg_table_dispatch_function_pointer(&self) -> Option<u64> {
        self.info.guard_xfg_table_dispatch_function_pointer
    }

    /// Raw CastGuardOsDeterminedFailureMode load-config field.
    #[pygetset]
    fn cast_guard_os_determined_failure_mode(&self) -> Option<u64> {
        self.info.cast_guard_os_determined_failure_mode
    }

    /// Virtual address of the guarded memcpy pointer slot.
    #[pygetset]
    fn guard_memcpy_function_pointer(&self) -> Option<u64> {
        self.info.guard_memcpy_function_pointer
    }

    /// Whether GuardFlags declares CFG instrumentation.
    #[pygetset]
    fn guard_cf_instrumented(&self) -> bool {
        self.info.guard_cf_instrumented()
    }

    /// Whether GuardFlags declares a CFG function table.
    #[pygetset]
    fn guard_cf_function_table_present(&self) -> bool {
        self.info.guard_cf_function_table_present()
    }

    /// Whether load-config metadata declares return-flow guard.
    #[pygetset]
    fn guard_rf_enabled(&self) -> bool {
        self.info.guard_rf_enabled()
    }

    /// Whether XFG metadata is indicated by the parsed load config.
    #[pygetset]
    fn has_xfg(&self) -> bool {
        self.info.has_xfg()
    }

    /// Whether CastGuard metadata is indicated.
    #[pygetset]
    fn has_cast_guard(&self) -> bool {
        self.info.has_cast_guard()
    }

    /// Whether guarded-memcpy metadata is indicated.
    #[pygetset]
    fn has_guard_memcpy(&self) -> bool {
        self.info.has_guard_memcpy()
    }

    /// Whether a nonzero CHPE metadata pointer is present.
    #[pygetset]
    fn has_chpe_metadata(&self) -> bool {
        self.info.has_chpe_metadata()
    }

    /// Whether dynamic-value relocation metadata is indicated.
    #[pygetset]
    fn has_dynamic_value_relocations(&self) -> bool {
        self.info.has_dynamic_value_relocations()
    }

    /// Whether a hotpatch table offset is present and nonzero.
    #[pygetset]
    fn has_hotpatch_table(&self) -> bool {
        self.info.has_hotpatch_table()
    }

    /// Whether enclave configuration is indicated.
    #[pygetset]
    fn has_enclave_config(&self) -> bool {
        self.info.has_enclave_config()
    }

    /// Whether volatile metadata is indicated.
    #[pygetset]
    fn has_volatile_metadata(&self) -> bool {
        self.info.has_volatile_metadata()
    }

    /// Whether guarded exception-continuation metadata is indicated.
    #[pygetset]
    fn has_guard_eh_continuations(&self) -> bool {
        self.info.has_guard_eh_continuations()
    }
}

/// The load-config CodeIntegrity record as declared in the image.
#[pyclass(module = "br3k.pe.load_config", name = "CodeIntegrityInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeLoadConfigCodeIntegrityInfo {
    info: raw_diagnostics::LoadConfigCodeIntegrityInfo,
}

#[pyclass]
impl PeLoadConfigCodeIntegrityInfo {
    /// Raw CodeIntegrity flags.
    #[pygetset]
    fn flags(&self) -> u16 {
        self.info.flags
    }

    /// CodeIntegrity catalog identifier.
    #[pygetset]
    fn catalog(&self) -> u16 {
        self.info.catalog
    }

    /// Declared offset associated with the code-integrity catalog.
    #[pygetset]
    fn catalog_offset(&self) -> u32 {
        self.info.catalog_offset
    }

    /// Raw reserved CodeIntegrity field; retained for inspection.
    #[pygetset]
    fn reserved(&self) -> u32 {
        self.info.reserved
    }
}

/// Location of the CLR runtime header; presence alone does not validate managed metadata.
#[pyclass(module = "br3k.pe.clr", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDotNetDirectoryInfo {
    info: raw_diagnostics::DotNetDirectoryInfo,
}

#[pyclass]
impl PeDotNetDirectoryInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.info.rva
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.info.size
    }
}

/// Presence and image-relative extent of a PE data directory.
#[pyclass(module = "br3k.pe.analysis", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDirectoryInfo {
    info: raw_diagnostics::DataDirectoryInfo,
}

#[pyclass]
impl PeDirectoryInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.info.rva
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.info.size
    }
}

/// TLS-directory location and recovered callback virtual addresses.
#[pyclass(module = "br3k.pe.tls", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeTlsDirectoryInfo {
    info: raw_diagnostics::TlsDirectoryInfo,
}

#[pyclass]
impl PeTlsDirectoryInfo {
    /// Whether this metadata structure was detected.
    #[pygetset]
    fn present(&self) -> bool {
        self.info.present
    }

    /// Image-relative virtual address of this item.
    #[pygetset]
    fn rva(&self) -> u32 {
        self.info.rva
    }

    /// Extent in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.info.size
    }

    /// TLS callback virtual addresses recovered from the image.
    #[pygetset]
    fn callbacks(&self, vm: &VirtualMachine) -> PyListOf<PyRef<rustpython_vm::builtins::PyInt>> {
        let callbacks = self.info
            .callbacks
            .iter()
            .map(|callback| vm.ctx.new_int(*callback))
            .collect::<Vec<_>>();

        PyListOf::new(callbacks, vm)
    }
}

/// A heuristic packer label and the evidence behind it; not an authoritative identification.
#[pyclass(module = "br3k.pe.analysis", name = "PackerHint")]
#[derive(Clone, Debug, PyPayload)]
pub struct PePackerHint {
    hint: raw_diagnostics::PackerHint,
}

#[pyclass]
impl PePackerHint {
    /// Heuristic packer or toolchain label.
    #[pygetset]
    fn name(&self) -> String {
        self.hint.name.clone()
    }

    /// Evidence used to produce the heuristic label.
    #[pygetset]
    fn reason(&self) -> String {
        self.hint.reason.clone()
    }
}

/// Metadata and anomaly snapshot for one PE image, without modifying the image.
#[pyclass(module = "br3k.pe.analysis", name = "MetadataSummary")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeMetadataSummary {
    summary: raw_diagnostics::MetadataSummary,
}

impl PeMetadataSummary {
    pub(crate) fn from_summary(summary: raw_diagnostics::MetadataSummary) -> Self { Self { summary } }
}

#[pyclass]
impl PeMetadataSummary {
    /// Certificate-table presence and file-layout extent.
    #[pygetset]
    pub(crate) fn security(&self, vm: &VirtualMachine) -> PyRef<PeSecurityDirectoryInfo> {
        PeSecurityDirectoryInfo {
            info: self.summary.security.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Rich-header detection and fingerprint.
    #[pygetset]
    fn rich_header(&self, vm: &VirtualMachine) -> PyRef<PeRichHeaderInfo> {
        PeRichHeaderInfo {
            info: self.summary.rich_header.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Parsed load-configuration and mitigation fields.
    #[pygetset]
    pub(crate) fn load_config(&self, vm: &VirtualMachine) -> PyRef<PeLoadConfigInfo> {
        PeLoadConfigInfo {
            info: self.summary.load_config.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Base-relocation directory presence and extent.
    #[pygetset]
    fn base_relocations(&self, vm: &VirtualMachine) -> PyRef<PeDirectoryInfo> {
        PeDirectoryInfo {
            info: self.summary.base_relocations.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// TLS directory presence and callback addresses.
    #[pygetset]
    fn tls(&self, vm: &VirtualMachine) -> PyRef<PeTlsDirectoryInfo> {
        PeTlsDirectoryInfo {
            info: self.summary.tls.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Delay-import directory presence and extent.
    #[pygetset]
    fn delay_imports(&self, vm: &VirtualMachine) -> PyRef<PeDirectoryInfo> {
        PeDirectoryInfo {
            info: self.summary.delay_imports.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Bound-import directory presence and extent.
    #[pygetset]
    fn bound_imports(&self, vm: &VirtualMachine) -> PyRef<PeDirectoryInfo> {
        PeDirectoryInfo { info: self.summary.bound_imports.clone() }.into_ref(&vm.ctx)
    }

    /// CLR directory presence and extent.
    #[pygetset]
    pub(crate) fn dotnet(&self, vm: &VirtualMachine) -> PyRef<PeDotNetDirectoryInfo> {
        PeDotNetDirectoryInfo {
            info: self.summary.dotnet.clone(),
        }
        .into_ref(&vm.ctx)
    }

    /// Heuristic packer labels with supporting reasons.
    #[pygetset]
    fn packer_hints(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PePackerHint>> {
        let hints = self.summary
            .packer_hints
            .iter()
            .cloned()
            .map(|hint| PePackerHint { hint }.into_ref(&vm.ctx))
            .collect::<Vec<_>>();

        PyListOf::new(hints, vm)
    }

    /// Typed structural and metadata anomalies found in the image.
    #[pygetset]
    fn anomalies(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeImageAnomaly>> {
        image_anomalies_to_py(&self.summary.anomalies, vm)
    }
}

pub fn normalized_header_hash(args: NormalizedHeaderHashArgs, vm: &VirtualMachine) -> PyResult<u64> {
    raw_diagnostics::normalized_header_hash(args.data.as_bytes())
        .map_err(map_to_py_system_error(vm, "Unable to hash normalized PE headers"))
}

pub fn export_prologue_hashes(args: ExportPrologueHashesArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<PeExportPrologueHash>>> {
    let hashes = raw_diagnostics::export_prologue_hashes(
        args.data.as_bytes(),
        args.image_base.present(),
        args.module_name.present().map(|name| name.to_string()),
        args.prologue_size.unwrap_or(16),
    )
    .map_err(map_to_py_system_error(vm, "Unable to hash PE export prologues"))?
    .into_iter()
    .map(|hash| PeExportPrologueHash { hash }.into_ref(&vm.ctx))
    .collect::<Vec<_>>();

    Ok(PyListOf::new(hashes, vm))
}

fn import_target_text(name: Option<&str>, ordinal: Option<u16>) -> String {
    match (name, ordinal) {
        (Some(name), _) => name.to_string(),
        (None, Some(ordinal)) => format!("#{ordinal}"),
        (None, None) => "<unknown>".to_string(),
    }
}

fn export_target_text(
    module_name: &str,
    name: Option<&str>,
    ordinal: Option<u32>,
    address: u64,
) -> String {
    format!(
        "{}!{}@0x{address:x}",
        module_name,
        match (name, ordinal) {
            (Some(name), _) => name.to_string(),
            (None, Some(ordinal)) => format!("#{ordinal}"),
            (None, None) => "<unknown>".to_string(),
        }
    )
}

fn resolved_address_text(
    module_name: Option<&str>,
    name: Option<&str>,
    ordinal: Option<u32>,
    address: u64,
) -> String {
    match module_name {
        Some(module_name) => export_target_text(module_name, name, ordinal, address),
        None => format!("0x{address:x}"),
    }
}

fn section_comparisons_to_py(
    sections: &[raw_diagnostics::SectionComparison],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeSectionComparison>> {
    let sections = sections
        .iter()
        .cloned()
        .map(|comparison| PeSectionComparison { comparison }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(sections, vm)
}

fn section_byte_changes_to_py(
    changes: &[raw_diagnostics::SectionByteChange],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeSectionByteChange>> {
    let changes = changes
        .iter()
        .cloned()
        .map(|change| PeSectionByteChange { change }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(changes, vm)
}

fn string_list_to_py(items: &[String], vm: &VirtualMachine) -> PyListOf<PyStrRef> {
    let items = items
        .iter()
        .map(|item| vm.ctx.new_str(item.as_str()))
        .collect::<Vec<_>>();

    PyListOf::new(items, vm)
}

pub(crate) fn image_anomalies_to_py(
    anomalies: &[raw_diagnostics::ImageAnomaly],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeImageAnomaly>> {
    let anomalies = anomalies
        .iter()
        .cloned()
        .map(|anomaly| PeImageAnomaly { anomaly }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(anomalies, vm)
}
