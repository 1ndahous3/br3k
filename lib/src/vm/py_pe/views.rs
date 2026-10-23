use crate::vm::prelude::*;

use super::image::*;
use crate::pe::image::{Image as RawPeImage, Layout};
use crate::pe::imports::ImportCodeTraceOptions;
use super::code_refs::*;
use super::bound_imports::*;
use super::delay_imports::*;
use super::image_resources::*;
use super::import_directory::import_descriptors_to_py;
use super::relocations::*;
use super::tls::*;
use super::diagnostics::{PeDotNetDirectoryInfo, PeLoadConfigInfo};
use rustpython_vm::function::Either;

/// Loader directory view. Absence, structural failure, and unsupported formats remain distinct.
#[pyclass(module = "br3k.pe.headers", name = "Directory")]
#[derive(Clone, Debug, PyPayload)]
pub struct Directory { pub(crate) image: RawPeImage, pub(crate) index: usize }
#[pyclass]
impl Directory {
    /// Return this directory's metadata; specialized summaries are used where available.
    #[pymethod]
    fn info(&self, vm: &VirtualMachine) -> PyResult<Either<
        PyRef<PeDataDirectory>,
        Either<PyRef<PeLoadConfigInfo>, PyRef<PeDotNetDirectoryInfo>>,
    >> {
        use crate::pe::format::*;
        if matches!(self.index, PE_DIRECTORY_ENTRY_LOAD_CONFIG | PE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
            let summary = super::diagnostics::PeMetadataSummary::from_summary(self.image.inspect().map_err(map_to_py_value_error(vm, "Unable to inspect loader metadata"))?.clone());
            return Ok(Either::B(if self.index == PE_DIRECTORY_ENTRY_LOAD_CONFIG { Either::A(summary.load_config(vm)) } else { Either::B(summary.dotnet(vm)) }));
        }
        Ok(Either::A(data_directory_to_py(self.image.data_directory(self.index).map_err(map_to_py_value_error(vm, "Unable to read directory"))?, vm)))
    }
    /// Perform bounded structural validation. The typed status distinguishes absent,
    /// invalid, unsupported, file-only, and validated data; it is not loader verification.
    #[pymethod]
    fn check(&self, vm: &VirtualMachine) -> PyResult<DirectoryCheck> {
        Ok(DirectoryCheck { check: self.image.check_directory(self.index).map_err(map_to_py_value_error(vm, "Unable to validate directory"))? })
    }
}

/// Bounded structural validation result for one PE data directory.
#[pyclass(module = "br3k.pe.headers", name = "DirectoryCheck")]
#[derive(Clone, Debug, PyPayload)]
pub struct DirectoryCheck { check: crate::pe::headers::DirectoryCheck }
#[pyclass]
impl DirectoryCheck {
    /// PE data-directory index.
    #[pygetset]
    fn index(&self) -> usize { self.check.index }
    /// Typed validation outcome; absence and unsupported data are distinct from invalid data.
    #[pygetset]
    fn status(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::headers::CheckStatus>> { PyEnumValue::new(self.check.status, vm) }
    /// Explanation of the validation outcome, when available.
    #[pygetset]
    fn message(&self) -> Option<String> { self.check.message.clone() }
}

/// File-only certificate/overlay metadata, explicitly unavailable for mapped captures.
#[pyclass(module = "br3k.pe.security", name = "Security")]
#[derive(Clone, Debug, PyPayload)]
pub struct Security { pub(crate) image: RawPeImage }
#[pyclass]
impl Security {
    /// Return certificate-directory metadata. Mapped images report file-only data as unavailable.
    #[pymethod]
    fn info(&self, vm: &VirtualMachine) -> PyResult<PyRef<super::diagnostics::PeSecurityDirectoryInfo>> {
        let summary = super::diagnostics::PeMetadataSummary::from_summary(self.image.inspect().map_err(map_to_py_value_error(vm, "Unable to inspect security metadata"))?.clone());
        Ok(summary.security(vm))
    }
    /// Return the bytes-after-sections range for a file image, or None if absent. Mapped images raise ValueError.
    #[pymethod]
    fn overlay(&self, vm: &VirtualMachine) -> PyResult<Option<PyRef<super::image_resources::PeOverlayRange>>> {
        self.image.require_layout(Layout::File).map_err(map_to_py_value_error(vm, "Overlay is file-only"))?;
        let range = self.image.overlay_range().map_err(map_to_py_value_error(vm, "Unable to read overlay"))?;
        Ok(range.map(|range| super::image_resources::overlay_range_to_py(range, vm)))
    }
}

/// Read-only headers view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.headers", name = "Headers")]
#[derive(Clone, Debug, PyPayload)]
pub struct Headers { pub(crate) image: RawPeImage }

#[pyclass]
impl Headers {
    /// IMAGE_FILE_MACHINE_* value from the COFF header.
    #[pygetset]
    fn machine(&self) -> u16 { self.image.machine() }

    /// Raw COFF TimeDateStamp value. It is not necessarily a trustworthy build time.
    #[pygetset]
    fn time_date_stamp(&self, vm: &VirtualMachine) -> PyResult<u32> {
        self.image.clone().time_date_stamp().map_err(map_to_py_value_error(vm, "Unable to read PE timestamp"))
    }

    /// Target pointer width in bytes, independent of the Python host's width.
    #[pygetset]
    fn pointer_size(&self, _vm: &VirtualMachine) -> PyResult<usize> {
        Ok(self.image.clone().pointer_size())
    }

    /// Preferred ImageBase from the headers, not necessarily the captured load address.
    #[pygetset]
    fn preferred_base(&self, vm: &VirtualMachine) -> PyResult<u64> {
        self.image.clone()
            .image_base()
            .map_err(map_to_py_system_error(vm, "Unable to read PE image base"))
    }

    /// SizeOfImage from the optional header, in bytes.
    #[pygetset]
    fn image_size(&self, vm: &VirtualMachine) -> PyResult<u32> {
        self.image.clone()
            .image_size()
            .map_err(map_to_py_system_error(vm, "Unable to read PE image size"))
    }

    /// AddressOfEntryPoint from the optional header, as an RVA.
    #[pygetset]
    fn entry_point(&self, vm: &VirtualMachine) -> PyResult<u32> {
        self.image.clone()
            .entry_point()
            .map_err(map_to_py_system_error(vm, "Unable to read PE entry point"))
    }

    /// Return metadata for a PE data-directory index.
    #[pymethod]
    fn directory(&self, args: DataDirectoryArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::image_resources::PeDataDirectory>> {
        let directory = self.image.clone()
            .data_directory(args.index)
            .map_err(map_to_py_system_error(vm, "Unable to read PE data directory"))?;

        Ok(data_directory_to_py(directory, vm))
    }

}

/// Read-only imports view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.imports", name = "Imports")]
#[derive(Clone, Debug, PyPayload)]
pub struct Imports { pub(crate) image: RawPeImage }

#[pyclass]
impl Imports {
    /// Rank IAT-shaped ranges in a captured mapped image against supplied symbols.
    /// Missing section bytes raise an error instead of implying an empty clean scan.
    #[pymethod]
    fn scan(&self, args: ScanImportsArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportAddressTableRangeScore>>> {
        let analyzer = crate::pe::imports::analysis::Analyzer { image: &self.image, symbols: args.symbols.map() };
        let ranges = analyzer.scan(crate::pe::imports::analysis::ScanOptions {
            min_entries: args.min_entries.unwrap_or(2), anchors: args.anchors.present().unwrap_or_default(),
            trace_depth: args.trace_depth.present(), ..Default::default()
        }).map_err(map_to_py_value_error(vm, "Unable to scan import ranges"))?;
        Ok(PyListOf::new(ranges.into_iter().map(|range| super::import_records::import_address_table_range_score_to_py(range, vm)).collect(), vm))
    }

    /// Recover one explicit mapped IAT span into a target-sized editable model.
    #[pymethod]
    fn recover_range(&self, rva: u32, size: usize, symbols: PyRef<super::PeExportMap>, vm: &VirtualMachine) -> PyResult<super::PeImportBuilder> {
        let analyzer = crate::pe::imports::analysis::Analyzer { image: &self.image, symbols: symbols.map() };
        let model = analyzer.recover_range(rva, size, crate::pe::imports::RecoverIatOptions { keep_unresolved: true, ..Default::default() })
            .map_err(map_to_py_value_error(vm, "Unable to recover import range"))?;
        Ok(super::PeImportBuilder::from_model(model, self.image.pointer_size()))
    }
    /// Parse normal import descriptors and their declared functions.
    #[pymethod]
    fn entries(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_directory::PeImportDescriptor>>> {
        let descriptors = self.image.clone()
            .import_entries()
            .map_err(map_to_py_system_error(vm, "Unable to read PE imports"))?;

        Ok(import_descriptors_to_py(&descriptors, vm))
    }

    /// Read-only delay-import view over the same image.
    #[pygetset]
    fn delay(&self) -> DelayImports { DelayImports { image: self.image.clone() } }
    /// Read-only bound-import view over the same image.
    #[pygetset]
    fn bound(&self) -> BoundImports { BoundImports { image: self.image.clone() } }
}

#[derive(FromArgs)]
pub struct ScanImportsArgs {
    #[pyarg(any)] symbols: PyRef<super::PeExportMap>,
    #[pyarg(named, optional)] min_entries: OptionalArg<usize>,
    #[pyarg(named, optional)] anchors: OptionalArg<Vec<u32>>,
    #[pyarg(named, optional)] trace_depth: OptionalArg<usize>,
}

/// Read-only delay-import view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.imports", name = "DelayImports")]
#[derive(Clone, Debug, PyPayload)]
pub struct DelayImports { pub(crate) image: RawPeImage }

#[pyclass]
impl DelayImports {
    /// Parse delay-import descriptors and their function tables.
    #[pymethod]
    fn entries(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::delay_imports::PeDelayImportDescriptor>>> {
        let descriptors = self.image.clone()
            .delay_entries()
            .map_err(map_to_py_system_error(vm, "Unable to read PE delay imports"))?;

        Ok(delay_import_descriptors_to_py(&descriptors, vm))
    }

    /// Analyze recoverable delay-import state, optionally using a validated matching reference image.
    #[pymethod]
    fn recover(&self, args: RecoverDelayImportsArgs, vm: &VirtualMachine) -> PyResult<PeDelayImportRecovery> {
        let image = self.image.clone();
        let recovery = match args.reference.present() {
            Some(source) => {
                image.validate_reference(&source.image).map_err(map_to_py_value_error(vm, "Invalid delay import reference"))?;
                image.discover_delay_from(&source.image)
            }
            None => image.discover_delay(),
        }.map_err(map_to_py_value_error(vm, "Unable to recover delay imports"))?;
        Ok(PeDelayImportRecovery { recovery })
    }

}

/// Read-only bound-import view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.imports", name = "BoundImports")]
#[derive(Clone, Debug, PyPayload)]
pub struct BoundImports { pub(crate) image: RawPeImage }

#[pyclass]
impl BoundImports {
    /// Parse bound-import descriptors and forwarder metadata.
    #[pymethod]
    fn entries(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::bound_imports::PeBoundImportDescriptor>>> {
        let descriptors = self.image.clone()
            .bound_entries()
            .map_err(map_to_py_system_error(vm, "Unable to read PE bound imports"))?;
        Ok(bound_import_descriptors_to_py(descriptors, vm))
    }

    /// Check bound-import timestamps and module expectations against the supplied export map.
    #[pymethod]
    fn check(&self, args: BoundImportChecksArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::bound_imports::PeBoundImportCheck>>> {
        let checks = self.image.clone().check_bound_entries(args.export_map.map())
            .map_err(map_to_py_value_error(vm, "Unable to check bound imports"))?;
        Ok(bound_import_checks_to_py(&checks, vm))
    }

}

/// Read-only resources view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.resources", name = "Resources")]
#[derive(Clone, Debug, PyPayload)]
pub struct Resources { pub(crate) image: RawPeImage }

#[pyclass]
impl Resources {
    /// Return a structural summary of the resource directory.
    #[pymethod]
    fn info(&self, vm: &VirtualMachine) -> PyResult<PyRef<super::image_resources::PeResourceDirectoryInfo>> {
        let info = self.image.clone()
            .resource_info()
            .map_err(map_to_py_system_error(vm, "Unable to read PE resource directory info"))?;

        Ok(resource_directory_info_to_py(info, vm))
    }

    /// Return resource data leaves with typed paths and payload locations.
    #[pymethod]
    fn entries(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::image_resources::PeResourceDataEntry>>> {
        let entries = self.image.clone()
            .resources()
            .map_err(map_to_py_system_error(vm, "Unable to read PE resource data entries"))?
            .into_iter()
            .map(|entry| resource_data_entry_to_py(entry, vm))
            .collect::<Vec<_>>();

        Ok(PyListOf::new(entries, vm))
    }

}

/// Read-only relocations view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.relocations", name = "Relocations")]
#[derive(Clone, Debug, PyPayload)]
pub struct Relocations { pub(crate) image: RawPeImage }

#[pyclass]
impl Relocations {
    /// Parse base-relocation blocks and entries.
    #[pymethod]
    fn entries(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::relocations::PeBaseRelocationBlock>>> {
        let blocks = self.image.clone()
            .relocation_entries()
            .map_err(map_to_py_system_error(vm, "Unable to read PE base relocations"))?;

        Ok(base_relocation_blocks_to_py(&blocks, vm))
    }

    /// Find heuristic relocation candidates. Candidate addresses are not proof of original relocation records.
    #[pymethod]
    fn discover(&self, vm: &VirtualMachine) -> PyResult<PyRef<super::relocations::PeRelocationDiscovery>> {
        let discovery = self.image.clone()
            .discover_relocations()
            .map_err(map_to_py_system_error(vm, "Unable to discover PE relocation candidates"))?;

        Ok(relocation_discovery_to_py(discovery, vm))
    }

    /// Encode a base-relocation table for the supplied RVAs using this image's architecture. Does not insert it into the image.
    #[pymethod]
    fn build_table(&self, args: BuildRelocationTableArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let table = self.image.clone()
            .build_relocation_table(&args.rvas)
            .map_err(map_to_py_system_error(vm, "Unable to build PE relocation table"))?;

        Ok(vm.ctx.new_bytes(table))
    }

}

/// Read-only TLS view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.tls", name = "Tls")]
#[derive(Clone, Debug, PyPayload)]
pub struct Tls { pub(crate) image: RawPeImage }

#[pyclass]
impl Tls {
    /// Parse the TLS directory and callbacks, or return None when absent. No callbacks are executed.
    #[pymethod]
    fn directory(&self, vm: &VirtualMachine) -> PyResult<Option<PyRef<super::tls::PeTlsDirectory>>> {
        let directory = self.image.clone()
            .tls()
            .map_err(map_to_py_system_error(vm, "Unable to read PE TLS directory"))?;

        Ok(tls_directory_to_py(directory, vm))
    }

}

/// Read-only code view retaining shared image bytes and layout.
#[pyclass(module = "br3k.pe.code", name = "Code")]
#[derive(Clone, Debug, PyPayload)]
pub struct Code { pub(crate) image: RawPeImage }

#[pyclass]
impl Code {
    /// Scan executable mapped sections for bounded supported API-reference patterns.
    /// Decoding follows the image machine; no target instructions are executed.
    #[pymethod]
    fn scan(&self, args: ScanArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::code_refs::PeImportCodeReference>>> {
        self.image.require_layout(Layout::Mapped).map_err(map_to_py_value_error(vm, "Code analysis"))?;
        self.image.validate_contents().map_err(map_to_py_value_error(vm, "Code analysis coverage"))?;
        let exports = export_tables(&args.symbols);
        let image_base = Some(self.image.address_base().map_err(map_to_py_value_error(vm, "Code address base"))?);
        let mut address_resolve_options = address_resolve_options(args.nearest, args.forwarders);
        address_resolve_options.api_set_map = Some(args.symbols.map().api_set_map().clone());
        let references = if args.trace_mapped_thunks.unwrap_or(false) {
            crate::pe::imports::scan_mapped_export_code_references_with_traced_thunks(
                self.image.data(),
                image_base,
                address_resolve_options,
                &exports,
                args.max_trace_depth.unwrap_or(4),
            )
        } else {
            crate::pe::imports::scan_mapped_export_code_references_with_options(
                self.image.data(),
                image_base,
                address_resolve_options,
                &exports,
            )
        }
        .map_err(map_to_py_value_error(vm, "Unable to scan PE code for export references"))?
        .into_iter()
        .map(|reference| import_code_reference_to_py(reference, vm))
        .collect::<Vec<_>>();

        Ok(PyListOf::new(references, vm))
    }

    /// Scan only the supplied RVA range; symbols supply target addresses and API-set context.
    #[pymethod]
    fn scan_range(&self, args: RangeArgs, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::code_refs::PeImportCodeReference>>> {
        self.image.require_layout(Layout::Mapped).map_err(map_to_py_value_error(vm, "Code analysis"))?;
        self.image.validate_contents().map_err(map_to_py_value_error(vm, "Code analysis coverage"))?;
        let exports = export_tables(&args.symbols);
        let image_base = Some(self.image.address_base().map_err(map_to_py_value_error(vm, "Code address base"))?);
        let mut address_resolve_options = address_resolve_options(args.nearest, args.forwarders);
        address_resolve_options.api_set_map = Some(args.symbols.map().api_set_map().clone());
        let references = if args.trace_mapped_thunks.unwrap_or(false) {
            crate::pe::imports::scan_mapped_export_code_references_in_range_with_traced_thunks(
                self.image.data(),
                image_base,
                args.rva,
                args.size,
                address_resolve_options,
                &exports,
                args.max_trace_depth.unwrap_or(4),
            )
        } else {
            crate::pe::imports::scan_mapped_export_code_references_in_range_with_options(
                self.image.data(),
                image_base,
                args.rva,
                args.size,
                address_resolve_options,
                &exports,
            )
        }
        .map_err(map_to_py_value_error(vm, "Unable to scan PE code range for export references"))?
        .into_iter()
        .map(|reference| import_code_reference_to_py(reference, vm))
        .collect::<Vec<_>>();

        Ok(PyListOf::new(references, vm))
    }

    /// Trace bounded reachable code from start_rva using the image architecture.
    /// max_blocks and max_bytes limit work; unsupported patterns are not a complete
    /// deobfuscation result. The returned trace records references and work performed.
    #[pymethod]
    fn trace(&self, args: TraceArgs, vm: &VirtualMachine) -> PyResult<PyRef<super::code_refs::PeImportCodeTrace>> {
        self.image.require_layout(Layout::Mapped).map_err(map_to_py_value_error(vm, "Code analysis"))?;
        self.image.validate_contents().map_err(map_to_py_value_error(vm, "Code analysis coverage"))?;
        let exports = export_tables(&args.symbols);
        let image_base = Some(self.image.address_base().map_err(map_to_py_value_error(vm, "Code address base"))?);
        let mut address_resolve_options = address_resolve_options(args.nearest, args.forwarders);
        address_resolve_options.api_set_map = Some(args.symbols.map().api_set_map().clone());
        let trace_options = ImportCodeTraceOptions {
            start_rva: args.start_rva,
            max_blocks: args.max_blocks.unwrap_or(64),
            max_bytes: args.max_bytes.unwrap_or(0x4000),
            follow_calls: args.follow_calls.unwrap_or(true),
        };
        let trace = if args.trace_mapped_thunks.unwrap_or(false) {
            crate::pe::imports::trace_mapped_export_code_references_with_traced_thunks(
                self.image.data(),
                image_base,
                trace_options,
                address_resolve_options,
                &exports,
                args.max_trace_depth.unwrap_or(4),
            )
        } else {
            crate::pe::imports::trace_mapped_export_code_references(
                self.image.data(),
                image_base,
                trace_options,
                address_resolve_options,
                &exports,
            )
        }
        .map_err(map_to_py_value_error(vm, "Unable to trace PE code for export references"))?;

        Ok(import_code_trace_to_py(trace, vm))
    }

}
