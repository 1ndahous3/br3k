use crate::vm::prelude::*;

use crate::pe::export_map::ExportMap;
use crate::pe::image::Image as RawPeImage;
use crate::pe::imports::{ImportCodeReference, ImportIssue};
use super::api_set::PeApiSetMap;
use super::exports::PeExportMap;
use super::image::{import_code_reference_to_py, PeImage};
use super::imports::{import_issue_to_py, PeImportBuilder};
use super::types::ImportRecoveryStrength;

#[py_api]
#[derive(FromArgs)]
pub struct OptionsArgs {
    /// Auto uses declared IAT data and bounded entry-point analysis. Fast reduces
    /// tracing; Aggressive enables broader and less restrictive discovery.
    #[pyi(ty = "br3k.pe.recovery.Strength")]
    #[pyarg(named, optional)]
    strength: OptionalArg<PyObjectRef>,
    #[pyarg(named, optional)]
    nearest: OptionalArg<bool>,
    #[pyarg(named, optional)]
    forwarders: OptionalArg<bool>,
    #[pyarg(named, optional)]
    api_set_map: OptionalArg<PyRef<PeApiSetMap>>,
    #[pyarg(named, optional)]
    keep_unresolved: OptionalArg<bool>,
    #[pyarg(named, optional)]
    trace_mapped_thunks: OptionalArg<bool>,
    #[pyarg(named, optional)]
    max_trace_depth: OptionalArg<usize>,
    #[pyarg(named, optional)]
    force_iat_scan: OptionalArg<bool>,
    #[pyarg(named, optional)]
    iat_scan_min_entries: OptionalArg<usize>,
    #[pyarg(named, optional)]
    recover_all_iat_ranges: OptionalArg<bool>,
    #[pyarg(named, optional)]
    trace_entry_point: OptionalArg<bool>,
    #[pyarg(named, optional)]
    entry_point_trace_max_blocks: OptionalArg<usize>,
    #[pyarg(named, optional)]
    entry_point_trace_max_bytes: OptionalArg<usize>,
    #[pyarg(named, optional)]
    entry_point_trace_follow_calls: OptionalArg<bool>,
    #[pyarg(named, optional)]
    recover_entry_point_code_references: OptionalArg<bool>,
    #[pyarg(named, optional)]
    recover_entry_point_iat_ranges: OptionalArg<bool>,
    #[pyarg(named, optional)]
    full_code_scan: OptionalArg<bool>,
    #[pyarg(named, optional)]
    recover_full_code_references: OptionalArg<bool>,
    #[pyarg(named, optional)]
    patch_direct_code_references: OptionalArg<bool>,
}

/// Recovery preset with explicit expert overrides.
///
/// Defaults to Strength.Auto. Overrides affect this analysis only. Nearest-export
/// matching and inferred references are evidence, not proof of the original IAT.
#[pyclass(module = "br3k.pe.recovery", name = "Options")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportRecoveryOptions {
    pub(crate) options: crate::pe::recovery::imports::Options,
}
impl Default for PeImportRecoveryOptions {
    fn default() -> Self { Self { options: Default::default() } }
}
impl std::ops::Deref for PeImportRecoveryOptions {
    type Target = crate::pe::recovery::imports::Options;
    fn deref(&self) -> &Self::Target { &self.options }
}
impl std::ops::DerefMut for PeImportRecoveryOptions {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.options }
}
impl PeImportRecoveryOptions {
    fn from_strength(strength: ImportRecoveryStrength) -> Self {
        Self { options: crate::pe::recovery::imports::Options::from_strength(strength) }
    }
}

impl Constructor for PeImportRecoveryOptions {
    type Args = OptionsArgs;

    /// Create recovery options from a strength preset and optional explicit overrides.
    ///
    /// Omitted fields retain the preset's values. This configures local analysis and rebuilding; it does not execute or modify the target process.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let strength = args
            .strength
            .into_option()
            .map(|value| {
                let value = super::namespaces::enum_value(value, "ImportRecoveryStrength", vm)?;
                ImportRecoveryStrength::from_repr(value).ok_or_else(|| vm.new_value_error(format!("Invalid recovery strength: {value}")))
            })
            .transpose()?
            .unwrap_or(ImportRecoveryStrength::Auto);
        let mut options = Self::from_strength(strength);

        if let Some(value) = args.nearest.present() {
            options.nearest = value;
        }
        if let Some(value) = args.forwarders.present() {
            options.forwarders = value;
        }
        if let Some(value) = args.api_set_map.present() {
            options.api_set_map = Some(value.map_clone());
        }
        if let Some(value) = args.keep_unresolved.present() {
            options.keep_unresolved = value;
        }
        if let Some(value) = args.trace_mapped_thunks.present() {
            options.trace_mapped_thunks = value;
        }
        if let Some(value) = args.max_trace_depth.present() {
            options.max_trace_depth = value;
        }
        if let Some(value) = args.force_iat_scan.present() {
            options.force_iat_scan = value;
        }
        if let Some(value) = args.iat_scan_min_entries.present() {
            options.iat_scan_min_entries = value;
        }
        if let Some(value) = args.recover_all_iat_ranges.present() {
            options.recover_all_iat_ranges = value;
        }
        if let Some(value) = args.trace_entry_point.present() {
            options.trace_entry_point = value;
        }
        if let Some(value) = args.entry_point_trace_max_blocks.present() {
            options.entry_point_trace_max_blocks = value;
        }
        if let Some(value) = args.entry_point_trace_max_bytes.present() {
            options.entry_point_trace_max_bytes = value;
        }
        if let Some(value) = args.entry_point_trace_follow_calls.present() {
            options.entry_point_trace_follow_calls = value;
        }
        if let Some(value) = args.recover_entry_point_code_references.present() {
            options.recover_entry_point_code_references = value;
        }
        if let Some(value) = args.recover_entry_point_iat_ranges.present() {
            options.recover_entry_point_iat_ranges = value;
        }
        if let Some(value) = args.full_code_scan.present() {
            options.full_code_scan = value;
        }
        if let Some(value) = args.recover_full_code_references.present() {
            options.recover_full_code_references = value;
        }
        if let Some(value) = args.patch_direct_code_references.present() {
            options.patch_direct_code_references = value;
        }

        Ok(options)
    }
}

#[pyclass(with(Constructor))]
impl PeImportRecoveryOptions {
    /// Selected recovery preset, before explicit option overrides.
    #[pygetset]
    fn strength(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::ImportRecoveryStrength>> {
        PyEnumValue::new(zelf.strength, vm)
    }

    /// Whether address resolution may consider the nearest export instead of an exact match.
    #[pygetset]
    fn nearest(zelf: &Py<Self>) -> bool { zelf.nearest }

    /// Whether resolution follows export forwarders.
    #[pygetset]
    fn forwarders(zelf: &Py<Self>) -> bool { zelf.forwarders }

    /// Number of API-set contracts supplied for resolving forwarded module names.
    #[pygetset]
    fn api_set_count(zelf: &Py<Self>) -> usize {
        zelf.api_set_map
            .as_ref()
            .map(|map| map.entries().len())
            .unwrap_or(0)
    }

    /// Whether unresolved import slots remain in the recovery model.
    #[pygetset]
    fn keep_unresolved(zelf: &Py<Self>) -> bool { zelf.keep_unresolved }

    /// Whether mapped thunk code may be followed while resolving an import address.
    #[pygetset]
    fn trace_mapped_thunks(zelf: &Py<Self>) -> bool { zelf.trace_mapped_thunks }

    /// Maximum number of thunk-tracing steps per address.
    #[pygetset]
    fn max_trace_depth(zelf: &Py<Self>) -> usize { zelf.max_trace_depth }

    /// Whether to scan for candidate IAT ranges even when declarations are available.
    #[pygetset]
    fn force_iat_scan(zelf: &Py<Self>) -> bool { zelf.force_iat_scan }

    /// Minimum number of entries required for an IAT scan candidate.
    #[pygetset]
    fn iat_scan_min_entries(zelf: &Py<Self>) -> usize { zelf.iat_scan_min_entries }

    /// Whether recovery uses every accepted scanned IAT range instead of the preferred range.
    #[pygetset]
    fn recover_all_iat_ranges(zelf: &Py<Self>) -> bool { zelf.recover_all_iat_ranges }

    /// Whether to trace code reachable from the entry point for API-reference evidence.
    #[pygetset]
    fn trace_entry_point(zelf: &Py<Self>) -> bool { zelf.trace_entry_point }

    /// Maximum number of code blocks visited by entry-point tracing.
    #[pygetset]
    fn entry_point_trace_max_blocks(zelf: &Py<Self>) -> usize { zelf.entry_point_trace_max_blocks }

    /// Maximum number of bytes examined by entry-point tracing.
    #[pygetset]
    fn entry_point_trace_max_bytes(zelf: &Py<Self>) -> usize { zelf.entry_point_trace_max_bytes }

    /// Whether entry-point tracing follows direct calls into the image.
    #[pygetset]
    fn entry_point_trace_follow_calls(zelf: &Py<Self>) -> bool { zelf.entry_point_trace_follow_calls }

    /// Whether API references found by entry-point tracing contribute to import recovery.
    #[pygetset]
    fn recover_entry_point_code_references(zelf: &Py<Self>) -> bool { zelf.recover_entry_point_code_references }

    /// Whether entry-point reference evidence is used to recover IAT ranges.
    #[pygetset]
    fn recover_entry_point_iat_ranges(zelf: &Py<Self>) -> bool { zelf.recover_entry_point_iat_ranges }

    /// Whether to scan executable sections for API references beyond entry-point reachability.
    #[pygetset]
    fn full_code_scan(zelf: &Py<Self>) -> bool { zelf.full_code_scan }

    /// Whether references from the full executable-section scan contribute to import recovery.
    #[pygetset]
    fn recover_full_code_references(zelf: &Py<Self>) -> bool { zelf.recover_full_code_references }

    /// Whether building may rewrite supported direct API branches using recovered import stubs.
    #[pygetset]
    fn patch_direct_code_references(zelf: &Py<Self>) -> bool { zelf.patch_direct_code_references }

    /// Return a short list of selected option values for logging; not a serialized configuration.
    #[pymethod]
    fn describe(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyStrRef>> {
        let strength: &'static str = zelf.strength.into();
        let lines = [
            format!("strength={strength}"),
            format!("nearest={}", zelf.nearest),
            format!("forwarders={}", zelf.forwarders),
            format!("keep_unresolved={}", zelf.keep_unresolved),
            format!("trace_mapped_thunks={} depth={}", zelf.trace_mapped_thunks, zelf.max_trace_depth),
        ]
        .into_iter()
        .map(|line| vm.ctx.new_str(line))
        .collect::<Vec<_>>();

        Ok(PyListOf::new(lines, vm))
    }
}

/// Source-bound recovery analysis with an editable, target-sized import model.
///
/// model edits affect the next validate() and build(); recovered is never a cached
/// count from an older model revision. diagnostics describe analysis stages, while
/// validate() recomputes model issues. build() never accepts a different source image.
#[pyclass(module = "br3k.pe.recovery", name = "Plan")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeImportRecoveryResult {
    /// Editable, target-pointer-sized import model shared with this plan.
    #[pymember(name = "model")]
    builder: PyRef<PeImportBuilder>,
    pub(crate) plan: crate::pe::recovery::imports::Plan,

}

impl PeImportRecoveryResult {
    pub(crate) fn analyze(
        image: RawPeImage, symbols: &ExportMap, options: crate::pe::recovery::imports::Options,
        reference: Option<RawPeImage>, vm: &VirtualMachine,
    ) -> PyResult<Self> {
        let plan = crate::pe::recovery::imports::Plan::from_image(image, symbols, options, reference)
            .map_err(map_to_py_value_error(vm, "Unable to recover import model"))?;
        Ok(Self { builder: PeImportBuilder::from_model(plan.model.clone(), plan.input.pointer_size).into_ref(&vm.ctx), plan })
    }
}

#[derive(FromArgs)]
pub struct BuildArgs {
    /// False by default. Explicitly permit incomplete reconstruction and retain
    /// BuildStatus.Partial plus diagnostics in the returned result.
    #[pyarg(named, optional)] allow_partial: OptionalArg<bool>,
    /// Clear stale checksum, security, and bound-import fields. Defaults to True.
    #[pyarg(named, optional)] sanitize_headers: OptionalArg<bool>,
    /// Restore absent resources from a matching reference. Does not merge
    /// conflicting resource trees. Defaults to True.
    #[pyarg(named, optional)] preserve_resources: OptionalArg<bool>,
    /// Infer a missing relocation table from pointer-shaped values. Defaults to
    /// False; inferred relocations make the resulting build partial.
    #[pyarg(named, optional)] discover_relocations: OptionalArg<bool>,
}

#[derive(FromArgs)]
pub struct AnalyzeArgs {
    #[pyarg(any)] image: PyRef<PeImage>,
    #[pyarg(any)] symbols: PyRef<PeExportMap>,
    #[pyarg(named, optional)] reference: OptionalArg<PyRef<PeImage>>,
    #[pyarg(named, optional)] options: OptionalArg<PyRef<PeImportRecoveryOptions>>,
}

pub(crate) fn analyze(args: AnalyzeArgs, vm: &VirtualMachine) -> PyResult<PeImportRecoveryResult> {
    PeImportRecoveryResult::analyze(
        args.image.image.clone(), args.symbols.map(),
        args.options.present().map(|options| options.options.clone()).unwrap_or_default(),
        args.reference.present().map(|reference| reference.image.clone()), vm,
    )
}

#[pyclass]
impl PeImportRecoveryResult {
    /// Diagnostics collected during analysis. Call validate() to check the current edited model.
    #[pygetset]
    fn diagnostics(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::diagnostic::Diagnostic>> { super::diagnostic::to_py(&zelf.plan.diagnostics, vm) }
    /// Whether analysis reconstructed synthetic PE headers.
    #[pygetset]
    fn synthetic_headers(zelf: &Py<Self>) -> bool { zelf.plan.header_recovery.as_ref().is_some_and(|recovery| recovery.synthetic) }
    /// Bytes preceding the recovered header, or zero when no prefix was identified.
    #[pygetset]
    fn header_prefix(zelf: &Py<Self>) -> u32 { zelf.plan.header_recovery.as_ref().map_or(0, |recovery| recovery.header_prefix) }
    /// Recompute diagnostics from the currently edited model.
    #[pymethod]
    fn validate(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportIssue>>> { zelf.issues(vm) }

    /// Build only against the original capture. Partial output requires explicit opt-in.
    ///
    /// Revalidates the current import model before applying independent resource,
    /// relocation, and sanitation policies. Complete means the selected checks
    /// succeeded, not that Windows can load or execute the reconstructed image.
    /// Raises ValueError for rejected partial output or an unsuccessful rebuild.
    #[pymethod]
    fn build(zelf: &Py<Self>, args: BuildArgs, vm: &VirtualMachine) -> PyResult<super::editor::BuildResult> {
        let result = zelf.plan.build(&zelf.builder.model_clone(), crate::pe::recovery::BuildPolicy {
            allow_partial: args.allow_partial.unwrap_or(false), sanitize_headers: args.sanitize_headers.unwrap_or(true),
            preserve_resources: args.preserve_resources.unwrap_or(true), discover_relocations: args.discover_relocations.unwrap_or(false),
        }).map_err(map_to_py_value_error(vm, "Unable to build recovery plan"))?;
        Ok(super::editor::BuildResult { result })
    }
    /// Delay-import recovery evidence collected during analysis.
    #[pygetset]
    fn delay_imports(zelf: &Py<Self>) -> super::delay_imports::PeDelayImportRecovery {
        super::delay_imports::PeDelayImportRecovery { recovery: zelf.plan.delay_imports.clone() }
    }

    /// Failure encountered while reading declared imports, or None when that step succeeded.
    #[pygetset]
    fn declaration_error(zelf: &Py<Self>) -> Option<String> { zelf.plan.declaration_error.clone() }


    /// Current number of functions in the editable import model, including unresolved entries retained by policy.
    #[pygetset]
    fn recovered(zelf: &Py<Self>) -> usize {
        zelf.builder.model_clone().function_count()
    }

    fn issues(&self, vm: &VirtualMachine) -> PyResult<PyListOf<PyRef<super::import_records::PeImportIssue>>> {
        let issues = self.plan.validate(&self.builder.model_clone()).map_err(map_to_py_value_error(vm, "Unable to validate imports"))?;
        Ok(import_issues_to_py(&issues, vm))
    }

    /// API references discovered by entry-point tracing.
    #[pygetset]
    fn entry_references(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::code_refs::PeImportCodeReference>> {
        import_code_references_to_py(&zelf.plan.entry_references, vm)
    }

    /// API references discovered by the executable-section scan.
    #[pygetset]
    fn full_references(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::code_refs::PeImportCodeReference>> {
        import_code_references_to_py(&zelf.plan.full_references, vm)
    }

    /// Direct API-reference evidence collected for possible branch rewriting.
    #[pygetset]
    fn direct_references(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::code_refs::PeImportCodeReference>> {
        import_code_references_to_py(&zelf.plan.direct_references, vm)
    }

    /// Return the merged entry-point and full-scan reference evidence.
    #[pymethod]
    fn all_references(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<super::code_refs::PeImportCodeReference>> {
        import_code_references_to_py(&crate::pe::recovery::imports::all_references(&zelf.plan.entry_references, &zelf.plan.full_references), vm)
    }
}

fn import_issues_to_py(issues: &[ImportIssue], vm: &VirtualMachine) -> PyListOf<PyRef<super::import_records::PeImportIssue>> {
    let issues = issues
        .iter()
        .cloned()
        .map(|issue| import_issue_to_py(issue, vm))
        .collect::<Vec<_>>();

    PyListOf::new(issues, vm)
}

fn import_code_references_to_py(references: &[ImportCodeReference], vm: &VirtualMachine) -> PyListOf<PyRef<super::code_refs::PeImportCodeReference>> {
    let references = references
        .iter()
        .cloned()
        .map(|reference| import_code_reference_to_py(reference, vm))
        .collect::<Vec<_>>();

    PyListOf::new(references, vm)
}
