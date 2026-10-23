use crate::pe::api_set::ApiSetMap;
use crate::pe::exports::ExportTable;
use crate::pe::image::{Image as RawPeImage, Layout};
use crate::pe::imports::{ImportAddressResolveMode, ImportAddressResolveOptions, ImportCodeReference, ImportCodeTraceOptions, ImportEvidenceKind, ImportIssue, ImportModel, RecoverIatOptions, RebuildImportsOptions, RebuildImportsReport};
use crate::pe::delay_imports::DelayImportRecovery;
use std::collections::BTreeSet;
use std::sync::Arc;
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};
use crate::pe::diagnostic::{Diagnostic, Stage};

/// Recovery preset controlling analysis effort and use of heuristic evidence. Explicit options may override preset fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportRecoveryStrength {
    /// Use conservative address recovery without thunk tracing or code-reference recovery.
    Fast,
    /// Default: enable forwarders, thunk tracing, and bounded entry-point analysis while retaining exact address matching.
    Auto,
    /// Also allow nearest exports, single-entry and multiple IAT ranges, larger traces, and a full code scan.
    Aggressive,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)] Relocations(#[from] crate::pe::relocations::RelocationError),
    #[error(transparent)] Image(#[from] crate::pe::image::Error),
    #[error(transparent)] Imports(#[from] crate::pe::imports::ImportError),
    #[error(transparent)] DelayImports(#[from] crate::pe::delay_imports::DelayImportError),
    #[error("recovery requires captured section contents; missing ranges must be resolved first")]
    IncompleteCapture,
    #[error("recovery is incomplete; inspect validation and explicitly allow partial output")]
    PartialOutput,
    #[error("invalid recovery policy: {0}")]
    InvalidPolicy(&'static str),
}

#[derive(Clone, Debug)]
pub struct Input {
    pub mapped: RawPeImage,
    pub mapped_data: Arc<Vec<u8>>,
    pub file: RawPeImage,
    pub entry_point: u32,
    pub iat_rva: u32,
    pub iat_size: u32,
    pub pointer_size: usize,
    base: u64,
}

impl Input {
    pub fn new(mapped: RawPeImage) -> Result<Self, Error> {
        mapped.require_layout(Layout::Mapped)?;
        // Gaps between sections may be missing; section bytes may not be fabricated.
        let file = mapped.to_file()?;
        let iat = mapped.data_directory(crate::pe::format::PE_DIRECTORY_ENTRY_IAT).ok();
        Ok(Self {
            base: mapped.address_base()?,
            entry_point: mapped.entry_point()?, pointer_size: mapped.pointer_size(),
            iat_rva: iat.map_or(0, |iat| iat.virtual_address), iat_size: iat.map_or(0, |iat| iat.size),
            mapped_data: mapped.shared_data(), mapped, file,
        })
    }
    pub fn base(&self) -> u64 { self.base }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub strength: ImportRecoveryStrength,
    pub nearest: bool,
    pub forwarders: bool,
    pub api_set_map: Option<ApiSetMap>,
    pub keep_unresolved: bool,
    pub trace_mapped_thunks: bool,
    pub max_trace_depth: usize,
    pub force_iat_scan: bool,
    pub iat_scan_min_entries: usize,
    pub recover_all_iat_ranges: bool,
    pub trace_entry_point: bool,
    pub entry_point_trace_max_blocks: usize,
    pub entry_point_trace_max_bytes: usize,
    pub entry_point_trace_follow_calls: bool,
    pub recover_entry_point_code_references: bool,
    pub recover_entry_point_iat_ranges: bool,
    pub full_code_scan: bool,
    pub recover_full_code_references: bool,
    pub patch_direct_code_references: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self::from_strength(ImportRecoveryStrength::Auto)
    }
}

impl Options {
    pub fn validate(&self) -> Result<(), Error> {
        if self.iat_scan_min_entries == 0 { return Err(Error::InvalidPolicy("IAT minimum entries must be positive")); }
        if self.trace_mapped_thunks && self.max_trace_depth == 0 { return Err(Error::InvalidPolicy("thunk trace depth must be positive")); }
        if self.trace_entry_point && (self.entry_point_trace_max_blocks == 0 || self.entry_point_trace_max_bytes == 0) {
            return Err(Error::InvalidPolicy("entry-point trace limits must be positive"));
        }
        Ok(())
    }

    pub fn from_strength(strength: ImportRecoveryStrength) -> Self {
        let aggressive = strength == ImportRecoveryStrength::Aggressive;
        let fast = strength == ImportRecoveryStrength::Fast;

        Self {
            strength,
            nearest: aggressive,
            forwarders: !fast,
            api_set_map: None,
            keep_unresolved: true,
            trace_mapped_thunks: !fast,
            max_trace_depth: 4,
            force_iat_scan: false,
            iat_scan_min_entries: if aggressive { 1 } else { 2 },
            recover_all_iat_ranges: aggressive,
            trace_entry_point: !fast,
            entry_point_trace_max_blocks: if aggressive { 256 } else { 64 },
            entry_point_trace_max_bytes: if aggressive { 0x10000 } else { 0x4000 },
            entry_point_trace_follow_calls: true,
            recover_entry_point_code_references: !fast,
            recover_entry_point_iat_ranges: !fast,
            full_code_scan: aggressive,
            recover_full_code_references: aggressive,
            patch_direct_code_references: !fast,
        }
    }

}


/// Source-bound recovery analysis. Validation is derived from the current model, never cached across edits.
#[derive(Clone, Debug)]
pub struct Plan {
    pub input: Input,
    pub model: ImportModel,
    pub export_map: crate::pe::export_map::ExportMap,
    pub entry_references: Vec<ImportCodeReference>,
    pub full_references: Vec<ImportCodeReference>,
    pub direct_references: Vec<ImportCodeReference>,
    pub declaration_error: Option<String>,
    pub delay_imports: DelayImportRecovery,
    pub reference: Option<RawPeImage>,
    pub header_recovery: Option<super::headers::Recovery>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Plan {
    pub fn from_image(image: RawPeImage, symbols: &crate::pe::export_map::ExportMap, mut options: Options, reference: Option<RawPeImage>) -> Result<Self, Error> {
        if let Some(source) = &reference { image.validate_reference(source)?; }
        let delay = match &reference { Some(source) => image.discover_delay_from(source), None => image.discover_delay() }?;
        let input = Input::new(image)?;
        let symbols = match &options.api_set_map {
            Some(map) => crate::pe::export_map::ExportMap::with_records(symbols.records().to_vec(), map.clone()),
            None => symbols.clone(),
        };
        options.api_set_map = Some(symbols.api_set_map().clone());
        let mut plan = Self::analyze(input, symbols, options, delay)?;
        plan.reference = reference;
        Ok(plan)
    }

    fn analyze(input: Input, export_map: crate::pe::export_map::ExportMap, options: Options, delay_imports: DelayImportRecovery) -> Result<Self, Error> {
        let dump = &input;
        let exports = export_map.tables().collect::<Vec<_>>();
        options.validate()?;
        let mut model = ImportModel::default();
        let mut diagnostics = Vec::new();
        if matches!(delay_imports.status, crate::pe::delay_imports::DelayImportRecoveryStatus::Ambiguous | crate::pe::delay_imports::DelayImportRecoveryStatus::ScanLimit | crate::pe::delay_imports::DelayImportRecoveryStatus::InvalidImage) {
            diagnostics.push(Diagnostic::warning(Stage::Imports, delay_imports.diagnostic.clone().unwrap_or_else(|| "Delay import recovery is incomplete".into())));
        }
        let entry_references = match entry_point_code_references(dump, &exports, &options) {
            Ok(references) => references,
            Err(error) => { diagnostics.push(Diagnostic::warning(Stage::Code, format!("Entry-point trace: {error}"))); Vec::new() }
        };

        if options.force_iat_scan || dump.iat_rva == 0 || dump.iat_size == 0 {
            recover_iat_scan_ranges(&mut model, dump, &exports, &options, &[])?;
        } else if let Err(error) = recover_iat_range(&mut model, dump, dump.iat_rva, dump.iat_size, &exports, &options, ImportEvidenceKind::IatDirectory) {
            diagnostics.push(Diagnostic::warning(Stage::Imports, format!("Declared IAT recovery failed; scanning ranges: {error}")));
            recover_iat_scan_ranges(&mut model, dump, &exports, &options, &[])?;
        }

        if options.recover_entry_point_iat_ranges {
            let anchors = code_reference_iat_anchors(&entry_references);
            if !anchors.is_empty() { recover_iat_scan_ranges(&mut model, dump, &exports, &options, &anchors)?; }
        }
        if options.recover_entry_point_code_references {
            model.recover_iat_from_code_references(&entry_references, dump.pointer_size)?;
        }
        let full_references = match full_image_code_references(dump, &exports, &options) {
            Ok(references) => references,
            Err(error) => { diagnostics.push(Diagnostic::warning(Stage::Code, format!("Full-image scan: {error}"))); Vec::new() }
        };
        if options.recover_full_code_references { model.recover_iat_from_code_references(&full_references, dump.pointer_size)?; }

        let declaration_error = crate::pe::imports::apply_import_context(&mut model, &dump.mapped, &export_map).err().map(|error| error.to_string());
        if let Some(error) = &declaration_error { diagnostics.push(Diagnostic::warning(Stage::Imports, error.clone())); }
        let direct_references = if options.patch_direct_code_references {
            unique_patchable_direct_branch_references(&entry_references, &full_references)
        } else { Vec::new() };
        Ok(Self { input, model, export_map, entry_references, full_references, direct_references, declaration_error, delay_imports, reference: None, header_recovery: None, diagnostics })
    }

    pub fn validate(&self, model: &ImportModel) -> Result<Vec<ImportIssue>, Error> {
        Ok(model.issues_with_export_map(self.input.pointer_size, &self.export_map)?)
    }

    pub fn rebuild(&self, model: &ImportModel, mut options: RebuildImportsOptions) -> Result<RebuildImportsReport, Error> {
        self.validate(model)?;
        options.code_references = self.direct_references.clone();
        let data = if !options.clear_delay_imports && self.delay_imports.selected().is_some() {
            self.input.file.restore_delay_imports(&self.delay_imports)?
        } else { self.input.file.data().to_vec() };
        Ok(crate::pe::imports::rebuild_imports_with_report(&data, model, options)?)
    }
}
fn recover_iat_range(
    model: &mut ImportModel,
    dump: &Input,
    rva: u32,
    size: u32,
    exports: &[&ExportTable],
    options: &Options,
    evidence_kind: ImportEvidenceKind,
) -> Result<usize, Error> {
    let iat_data = dump.mapped
        .read_mapped_bytes_rva(rva, size as usize)?;
    let recovered = if options.trace_mapped_thunks {
        model.recover_iat_with_traced_thunks_and_evidence(
            rva,
            &iat_data,
            &dump.mapped_data,
            Some(dump.base()),
            dump.pointer_size,
            recover_iat_options(options),
            options.max_trace_depth,
            ImportEvidenceKind::ThunkTrace,
            exports,
        )
    } else {
        model.recover_iat_with_evidence(
            rva,
            &iat_data,
            dump.pointer_size,
            recover_iat_options(options),
            evidence_kind,
            exports,
        )
    }?;

    Ok(recovered)
}

fn recover_iat_scan_ranges(
    model: &mut ImportModel,
    dump: &Input,
    exports: &[&ExportTable],
    options: &Options,
    anchor_rvas: &[u32],
) -> Result<usize, Error> {
    let address_resolve_options = address_resolve_options(options);
    let ranges = if !anchor_rvas.is_empty() && options.trace_mapped_thunks {
        crate::pe::imports::scan_iat_ranges_containing_rvas_with_traced_thunks(
            &dump.mapped_data, 0, dump.pointer_size, address_resolve_options, exports,
            Some(dump.base()), options.max_trace_depth, anchor_rvas,
        )
    } else if !anchor_rvas.is_empty() {
        crate::pe::imports::scan_iat_ranges_containing_rvas_with_options(
            &dump.mapped_data, 0, dump.pointer_size, address_resolve_options, exports, anchor_rvas,
        )
    } else if options.trace_mapped_thunks {
        crate::pe::imports::scan_iat_ranges_with_traced_thunks(
            &dump.mapped_data,
            0,
            dump.pointer_size,
            address_resolve_options,
            exports,
            options.iat_scan_min_entries,
            Some(dump.base()),
            options.max_trace_depth,
        )
    } else {
        crate::pe::imports::scan_iat_ranges_with_options(
            &dump.mapped_data,
            0,
            dump.pointer_size,
            address_resolve_options,
            exports,
            options.iat_scan_min_entries,
        )
    }
    .and_then(|ranges| crate::pe::imports::rank_iat_ranges(ranges, anchor_rvas))?;

    let ranges = if anchor_rvas.is_empty() {
        ranges
    } else {
        ranges
            .into_iter()
            .filter(|range| range.anchor_count != 0)
            .collect::<Vec<_>>()
    };
    let ranges = if options.recover_all_iat_ranges {
        ranges
    } else {
        ranges.into_iter().take(1).collect()
    };

    let mut recovered = 0;
    for range in ranges {
        recovered += recover_iat_range(
            model,
            dump,
            range.range.rva,
            range.range.size,
            exports,
            options,
            ImportEvidenceKind::IatRange,
        )?;
    }

    Ok(recovered)
}

fn entry_point_code_references(
    dump: &Input,
    exports: &[&ExportTable],
    options: &Options,
) -> Result<Vec<ImportCodeReference>, Error> {
    if !options.trace_entry_point || dump.entry_point == 0 {
        return Ok(Vec::new());
    }

    let trace_options = ImportCodeTraceOptions {
        start_rva: dump.entry_point,
        max_blocks: options.entry_point_trace_max_blocks,
        max_bytes: options.entry_point_trace_max_bytes,
        follow_calls: options.entry_point_trace_follow_calls,
    };
    let result = if options.trace_mapped_thunks {
        crate::pe::imports::trace_mapped_export_code_references_with_traced_thunks(
            &dump.mapped_data,
            Some(dump.base()),
            trace_options,
            address_resolve_options(options),
            exports,
            options.max_trace_depth,
        )
    } else {
        crate::pe::imports::trace_mapped_export_code_references(
            &dump.mapped_data,
            Some(dump.base()),
            trace_options,
            address_resolve_options(options),
            exports,
        )
    };

    Ok(result?.references)
}

fn full_image_code_references(
    dump: &Input,
    exports: &[&ExportTable],
    options: &Options,
) -> Result<Vec<ImportCodeReference>, Error> {
    if !options.full_code_scan {
        return Ok(Vec::new());
    }

    let result = if options.trace_mapped_thunks {
        crate::pe::imports::scan_mapped_export_code_references_with_traced_thunks(
            &dump.mapped_data,
            Some(dump.base()),
            address_resolve_options(options),
            exports,
            options.max_trace_depth,
        )
    } else {
        crate::pe::imports::scan_mapped_export_code_references_with_options(
            &dump.mapped_data,
            Some(dump.base()),
            address_resolve_options(options),
            exports,
        )
    };

    Ok(result?)
}

fn recover_iat_options(options: &Options) -> RecoverIatOptions {
    RecoverIatOptions {
        address_resolve_options: address_resolve_options(options),
        keep_unresolved: options.keep_unresolved,
    }
}

fn address_resolve_options(options: &Options) -> ImportAddressResolveOptions {
    ImportAddressResolveOptions {
        mode: if options.nearest {
            ImportAddressResolveMode::Nearest
        } else {
            ImportAddressResolveMode::Exact
        },
        resolve_forwarders: options.forwarders,
        api_set_map: options.api_set_map.clone(),
    }
}

fn code_reference_iat_anchors(references: &[ImportCodeReference]) -> Vec<u32> {
    let mut anchors = Vec::new();

    for reference in references {
        if let Some(iat_rva) = reference.iat_rva && !anchors.contains(&iat_rva) {
            anchors.push(iat_rva);
        }
    }

    anchors
}

fn unique_patchable_direct_branch_references(
    entry_references: &[ImportCodeReference],
    full_references: &[ImportCodeReference],
) -> Vec<ImportCodeReference> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();

    for reference in entry_references.iter().chain(full_references) {
        if !reference.kind.is_patchable_direct_branch() {
            continue;
        }

        let key = code_reference_key(reference);
        if seen.insert(key) {
            unique.push(reference.clone());
        }
    }

    unique
}

pub fn all_references(
    entry_references: &[ImportCodeReference],
    full_references: &[ImportCodeReference],
) -> Vec<ImportCodeReference> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();

    for reference in entry_references.iter().chain(full_references) {
        let key = code_reference_key(reference);
        if seen.insert(key) {
            unique.push(reference.clone());
        }
    }

    unique
}

fn code_reference_key(reference: &ImportCodeReference) -> (u32, u32, String, Option<String>, u32, u64) {
    (
        reference.reference_rva,
        reference.kind as u32,
        reference.module_name.to_ascii_lowercase(),
        reference.name.clone(),
        reference.ordinal,
        reference.target_address,
    )
}
