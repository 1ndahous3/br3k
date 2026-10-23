use crate::vm::prelude::*;

use crate::pe::{capture, sources::References, export_map::{ExportMap, ExportTableRecord, ExportTableSource}};
use crate::vm::py_proc::{Process, CProcessModule, process_modules, process_api_set_map, read_process_memory};
use super::{owned::PeImage, recovery::PeImportRecoveryResult, PeImportRecoveryOptions};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use crate::pe::diagnostic::{Diagnostic, Stage};
use super::types::ExportResolverSource;

/// Ephemeral process-analysis context. Refresh invalidates sources and symbols, not existing captures.
///
/// The process must already be opened with a configured memory reader. Modules,
/// disk references, and export symbols are cached for one generation. Captures
/// retain their origin; compare(), recover(), and reference() reject captures
/// from another view or a previous generation. This is not an atomic OS snapshot.
#[pyclass(module = "br3k.pe", name = "ProcessView")]
#[derive(Debug, PyPayload)]
pub struct ProcessView {
    process: PyRef<Process>,
    modules: RefCell<Vec<CProcessModule>>,
    generation: Cell<u64>,
    references: RefCell<References>,
    symbols: RefCell<Option<ExportMap>>,
    source_errors: RefCell<Vec<SourceFailure>>,
    identity: Rc<()>,
    source_policy: ExportResolverSource,
}

#[py_api]
#[derive(FromArgs)]
pub struct ProcessViewArgs {
    /// Open process with an initialized memory-read strategy.
    #[pyarg(any)] process: PyRef<Process>,
    /// Auto tries disk exports, then mapped exports on failure. Disk and Mapped
    /// require the selected source. Failures are retained in source_errors.
    #[pyi(ty = "br3k.pe.exports.SourcePolicy")]
    #[pyarg(named, optional)] source_policy: OptionalArg<PyObjectRef>,
}

impl Constructor for ProcessView {
    type Args = ProcessViewArgs;
    /// Create a view over an opened process and snapshot its loaded-module inventory. Export sources are loaded lazily.
    fn py_new(_cls: &Py<PyType>, args: Self::Args, vm: &VirtualMachine) -> PyResult<Self> {
        let source_policy = args.source_policy.present().map(|value| super::namespaces::enum_value(value, "ExportResolverSource", vm)).transpose()?;
        let source_policy = source_policy.and_then(ExportResolverSource::from_repr).unwrap_or(ExportResolverSource::Auto);
        let process = args.process;
        let modules = process_modules(&process).map_err(map_to_py_system_error(vm, "Unable to list process modules"))?;
        Ok(Self { process, modules: RefCell::new(modules), generation: Cell::new(0), references: Default::default(), symbols: Default::default(), source_errors: Default::default(), identity: Rc::new(()), source_policy })
    }
}

#[derive(FromArgs)]
pub struct RecoverArgs {
    #[pyarg(any)] capture: PyRef<Capture>,
    #[pyarg(named, optional)] options: OptionalArg<PyRef<PeImportRecoveryOptions>>,
}

#[derive(FromArgs)]
pub struct ScanArgs {
    #[pyarg(named, optional)] options: OptionalArg<PyRef<super::PeHiddenModuleScanOptions>>,
}

#[pyclass(with(Constructor))]
impl ProcessView {
    /// Loaded-module inventory retained for the current view generation.
    #[pygetset]
    fn modules(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessModule>> { super::hidden::process_modules_to_py(&self.modules.borrow(), vm) }
    /// Current generation number, incremented by refresh().
    #[pygetset]
    fn generation(&self) -> u64 { self.generation.get() }
    /// Policy used to select disk or mapped export sources.
    #[pygetset]
    fn source_policy(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::ExportResolverSource>> { PyEnumValue::new(self.source_policy, vm) }
    /// Lazily built export index using actual target load addresses and the target API-set map.
    #[pygetset]
    fn symbols(&self, vm: &VirtualMachine) -> PyResult<super::PeExportMap> { Ok(super::PeExportMap::from_export_map(self.load_symbols(vm)?)) }
    /// Export-source failures and fallback warnings collected so far. Access symbols to trigger lazy source loading.
    #[pygetset]
    fn source_errors(&self, vm: &VirtualMachine) -> PyListOf<PyRef<SourceFailure>> {
        PyListOf::new(self.source_errors.borrow().iter().cloned().map(|error| error.into_ref(&vm.ctx)).collect(), vm)
    }

    /// Refresh module inventory and clear reference/symbol caches.
    /// Existing captures remain inspectable, but cannot be reused with this view.
    #[pymethod]
    fn refresh(&self, vm: &VirtualMachine) -> PyResult<()> {
        let modules = process_modules(&self.process).map_err(map_to_py_system_error(vm, "Unable to refresh modules"))?;
        *self.modules.borrow_mut() = modules;
        self.generation.set(self.generation.get().checked_add(1).ok_or_else(|| vm.new_value_error("Process view generation overflow"))?);
        self.references.borrow_mut().clear();
        self.symbols.borrow_mut().take();
        self.source_errors.borrow_mut().clear();
        Ok(())
    }

    /// Acquire a selected loaded module or hidden candidate, recording every unreadable page.
    #[pymethod]
    fn capture(&self, target: PyObjectRef, vm: &VirtualMachine) -> PyResult<Capture> {
        if let Some(module) = target.downcast_ref::<CProcessModule>() {
            return self.capture_module(module, vm);
        }
        if let Some(candidate) = target.downcast_ref::<super::PeHiddenModuleCandidate>() {
            let (base, size) = candidate.capture_range().map_err(map_to_py_value_error(vm, "Invalid candidate span"))?;
            let mut capture = self.capture_range(base, size, format!("hidden_{base:x}"), None, vm)?;
            capture.capture.regions = candidate.capture_regions();
            return Ok(capture);
        }
        Err(vm.new_type_error("capture() requires a loaded module or hidden candidate"))
    }

    /// Scan memory, working-set, and thread evidence using this module inventory.
    /// Scores rank candidates; they are not probabilities or proof of a hidden DLL.
    #[pymethod]
    fn scan(&self, args: ScanArgs, vm: &VirtualMachine) -> PyResult<super::PeProcessScan> {
        super::PeProcessScan::build(&self.process, self.modules.borrow().clone(), args.options.present().map(|options| (*options).clone()), vm)
    }

    /// Recover this capture using one shared export index and reference snapshot.
    /// The default strength is Auto. Missing section contents raise ValueError;
    /// missing headers may be reconstructed from surviving capture evidence.
    #[pymethod]
    fn recover(&self, args: RecoverArgs, vm: &VirtualMachine) -> PyResult<PeImportRecoveryResult> {
        self.validate_capture(&args.capture, vm)?;
        let (image, header_recovery) = match args.capture.capture.image() {
            Ok(image) => (image, None),
            Err(error) if args.capture.capture.regions.is_empty() => return Err(map_to_py_value_error(vm, "Capture has no usable PE headers")(error)),
            Err(_) => {
                let modules = self.modules.borrow();
                let main = modules.first().ok_or_else(|| vm.new_value_error("Cannot infer architecture without a main module"))?;
                let source = self.references.borrow_mut().load(&main.full_dll_name).map_err(map_to_py_value_error(vm, "Cannot infer target architecture"))?;
                let machine = crate::pe::format::machine_name(source.machine()).ok_or_else(|| vm.new_value_error("Unsupported target architecture"))?;
                let recovered = crate::pe::recovery::headers::recover(&args.capture.capture, machine)
                    .map_err(map_to_py_value_error(vm, "Unable to reconstruct analysis headers"))?;
                (recovered.image.clone(), Some(recovered))
            }
        };
        let mut diagnostics = Vec::new();
        let source = match args.capture.capture.path.as_ref().map(|path| self.references.borrow_mut().load(path)).transpose() {
            Ok(source) => source,
            Err(error) => { diagnostics.push(Diagnostic::warning(Stage::Reference, error.to_string())); None }
        };
        let options = args.options.present().map(|options| options.options.clone()).unwrap_or_default();
        let symbols = self.load_symbols(vm)?;
        let mut plan = PeImportRecoveryResult::analyze(image, &symbols, options, source, vm)?;
        diagnostics.extend(self.source_errors.borrow().iter().map(|error| Diagnostic::warning(Stage::Reference, format!("{}: {}", error.name, error.message))));
        plan.plan.diagnostics.extend(diagnostics);
        plan.plan.header_recovery = header_recovery;
        Ok(plan)
    }

    /// Read a module or capture's disk reference through the per-view cache.
    /// Raises for an unrelated/stale capture, missing path, or acquisition error.
    #[pymethod]
    fn reference(&self, target: PyObjectRef, vm: &VirtualMachine) -> PyResult<PeImage> {
        let path = if let Some(capture) = target.downcast_ref::<Capture>() {
                self.validate_capture(capture, vm)?;
                capture.capture.path.as_deref()
            }
            else if let Some(module) = target.downcast_ref::<CProcessModule>() {
                self.validate_module(module, vm)?;
                Some(module.full_dll_name.as_str())
            }
            else { return Err(vm.new_type_error("reference() requires a module or capture")); };
        let path = path.ok_or_else(|| vm.new_value_error("Capture has no disk reference path"))?;
        Ok(PeImage::from_image(self.references.borrow_mut().load(path).map_err(map_to_py_system_error(vm, "Reference acquisition failed"))?))
    }

    /// Pair a current capture with its cached disk reference for lazy comparison.
    /// Machine, timestamp, and image size must match; inspect component diagnostics.
    #[pymethod]
    fn compare(&self, capture: PyRef<Capture>, vm: &VirtualMachine) -> PyResult<super::comparison::Comparison> {
        self.validate_capture(&capture, vm)?;
        let reference = self.reference(capture.clone().into(), vm)?;
        let image = capture.capture.image().map_err(map_to_py_value_error(vm, "Capture has no usable PE headers"))?;
        super::comparison::Comparison::new(image, reference.image, vm)
    }
}

impl ProcessView {
    fn validate_capture(&self, capture: &Capture, vm: &VirtualMachine) -> PyResult<()> {
        if !Rc::ptr_eq(&self.identity, &capture.origin) { return Err(vm.new_value_error("Capture belongs to another ProcessView; use offline analysis with explicit symbols/reference")); }
        if capture.capture.generation != self.generation.get() { return Err(vm.new_value_error("Capture predates refresh(); recapture or use offline analysis with the original symbols/reference")); }
        Ok(())
    }
    fn validate_module(&self, module: &CProcessModule, vm: &VirtualMachine) -> PyResult<()> {
        if !self.modules.borrow().iter().any(|known| known.dll_base == module.dll_base && known.size_of_image == module.size_of_image && known.full_dll_name == module.full_dll_name) {
            return Err(vm.new_value_error("Module is not part of this ProcessView generation"));
        }
        Ok(())
    }
    fn capture_module(&self, module: &CProcessModule, vm: &VirtualMachine) -> PyResult<Capture> {
        self.validate_module(module, vm)?;
        self.capture_range(module.dll_base, module.size_of_image, module.base_dll_name.clone(), Some(module.full_dll_name.clone()), vm)
    }
    fn capture_range(&self, base: u64, size: u32, name: String, path: Option<String>, vm: &VirtualMachine) -> PyResult<Capture> {
        let capture = capture::Capture::read(base, size, name, path, self.generation.get(), |address, size| {
            read_process_memory(&self.process, address, size, vm).map_err(|error| error.as_object().str(vm).map(|text| text.to_string()).unwrap_or_else(|_| "memory read failed".into()))
        }).map_err(map_to_py_value_error(vm, "Unable to capture range"))?;
        Ok(Capture { capture, origin: self.identity.clone() })
    }
    fn load_symbols(&self, vm: &VirtualMachine) -> PyResult<ExportMap> {
        if let Some(symbols) = self.symbols.borrow().as_ref() { return Ok(symbols.clone()); }
        let mut records = Vec::new();
        let mut errors = Vec::new();
        for module in self.modules.borrow().iter() {
            let mut source = ExportTableSource::Disk;
            let disk = || self.references.borrow_mut().load(&module.full_dll_name).map_err(|error| error.to_string());
            let mapped = || self.capture_module(module, vm).map_err(|_| "Unable to capture export source".to_string())?
                .capture.image().map_err(|error| error.to_string());
            let parse = |image: crate::pe::image::Image| match image.exports() {
                    Ok(table) => Ok(Some(table)),
                    Err(crate::pe::exports::ExportError::MissingExportDirectory) => Ok(None),
                    Err(error) => Err(error.to_string()),
            };
            let result = match self.source_policy {
                ExportResolverSource::Disk => disk().and_then(parse),
                ExportResolverSource::Mapped => { source = ExportTableSource::Mapped; mapped().and_then(parse) }
                ExportResolverSource::Auto => match disk().and_then(parse) {
                    Ok(table) => Ok(table),
                    Err(error) => {
                        errors.push(SourceFailure { name: module.base_dll_name.clone(), path: module.full_dll_name.clone(), message: format!("Disk source unavailable; trying mapped exports: {error}") });
                        source = ExportTableSource::Mapped;
                        mapped().and_then(parse)
                    }
                },
            };
            match result {
                Ok(Some(mut table)) => {
                    table.image_base = module.dll_base;
                    for symbol in &mut table.symbols { symbol.address = module.dll_base + symbol.rva as u64; }
                    records.push(ExportTableRecord { table, source });
                }
                Ok(None) => (),
                Err(error) => errors.push(SourceFailure { name: module.base_dll_name.clone(), path: module.full_dll_name.clone(), message: error }),
            }
        }
        let api_set = process_api_set_map(&self.process).map_err(map_to_py_system_error(vm, "Unable to read API-set namespace"))?;
        let symbols = ExportMap::with_records(records, api_set);
        *self.source_errors.borrow_mut() = errors;
        *self.symbols.borrow_mut() = Some(symbols.clone());
        Ok(symbols)
    }
}

/// Raw bytes plus acquisition coverage; image parsing is explicit and may fail.
/// Unreadable bytes remain recorded in missing even though data contains a
/// placeholder for their range. Pass image(), not data, to retain that evidence.
#[pyclass(module = "br3k.pe", name = "Capture")]
#[derive(Clone, Debug, PyPayload)]
pub struct Capture { pub(crate) capture: capture::Capture, origin: Rc<()> }
#[pyclass]
impl Capture {
    /// Starting virtual address of the captured range.
    #[pygetset]
    fn base(&self) -> u64 { self.capture.base }
    /// Module name or generated hidden-candidate name for this capture.
    #[pygetset]
    fn name(&self) -> String { self.capture.name.clone() }
    /// Reference file path when known, otherwise None.
    #[pygetset]
    fn path(&self) -> Option<String> { self.capture.path.clone() }
    /// ProcessView generation in which these bytes were acquired.
    #[pygetset]
    fn generation(&self) -> u64 { self.capture.generation }
    /// Whether all requested capture bytes were successfully acquired.
    #[pygetset]
    fn complete(&self) -> bool { self.capture.complete() }
    /// Copy of captured bytes, including placeholders for unreadable ranges. Use image() to preserve coverage metadata.
    #[pygetset]
    fn data(&self, vm: &VirtualMachine) -> PyRef<PyBytes> { vm.ctx.new_bytes(self.capture.data.as_ref().clone()) }
    /// Unreadable ranges and their acquisition errors.
    #[pygetset]
    fn missing(&self, vm: &VirtualMachine) -> PyListOf<PyRef<ReadFailure>> {
        PyListOf::new(self.capture.failures.iter().cloned().map(|failure| ReadFailure { failure }.into_ref(&vm.ctx)).collect(), vm)
    }
    /// Parse captured headers while retaining load address and missing ranges.
    /// Damaged or unreadable headers raise ValueError; the raw Capture remains usable.
    #[pymethod]
    fn image(&self, vm: &VirtualMachine) -> PyResult<PeImage> {
        Ok(PeImage::from_image(self.capture.image().map_err(map_to_py_value_error(vm, "Capture has no usable PE headers"))?))
    }
}

/// One unreadable range in a process capture. Placeholder bytes for this range are not acquired evidence.
#[pyclass(module = "br3k.pe.analysis", name = "ReadFailure")]
#[derive(Clone, Debug, PyPayload)]
pub struct ReadFailure { failure: capture::ReadFailure }
#[pyclass]
impl ReadFailure {
    /// Offset of the unreadable range relative to the capture base.
    #[pygetset]
    fn rva(&self) -> u32 { self.failure.range.rva }
    /// Length of the unreadable range in bytes.
    #[pygetset]
    fn size(&self) -> u32 { self.failure.range.size }
    /// Memory acquisition error for this range.
    #[pygetset]
    fn message(&self) -> String { self.failure.message.clone() }
}

/// One failure or fallback warning encountered while loading a module's export source.
#[pyclass(module = "br3k.pe.exports", name = "SourceFailure")]
#[derive(Clone, Debug, PyPayload)]
pub struct SourceFailure { name: String, path: String, message: String }
#[pyclass]
impl SourceFailure {
    /// Name of the module whose export source could not be used.
    #[pygetset]
    fn name(&self) -> String { self.name.clone() }
    /// Module path associated with the attempted export source.
    #[pygetset]
    fn path(&self) -> String { self.path.clone() }
    /// Source acquisition or parsing error, including fallback context when applicable.
    #[pygetset]
    fn message(&self) -> String { self.message.clone() }
}
