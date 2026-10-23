use crate::vm::prelude::*;

use crate::sysapi;
use crate::vm::py_pe::hidden::{
    find_hidden_modules_inner, hidden_candidates_to_py, process_modules_to_py,
    scan_findings_to_py, PeHiddenModuleScanOptions, PeHiddenModuleScanResult,
};
use crate::vm::py_pe::types::{ThreadStackRegionKind, ThreadStartKind};
use crate::vm::py_proc::{
    process_threads, process_working_set_regions,
    working_set_regions_to_py, CProcessMemoryRegion, CProcessModule,
    CProcessThreadInfo, Process,
};

/// Classification of a thread's start address against module and region snapshots.
#[pyclass(module = "br3k.pe.analysis", name = "ThreadStartEvidence")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeThreadStartEvidence {
    data: sysapi::ProcessThreadInfo,
    kind: ThreadStartKind,
    score: i32,
    region: Option<sysapi::MemoryRegion>,
    module: Option<CProcessModule>,
}

#[pyclass]
impl PeThreadStartEvidence {
    /// Typed classification of this thread-related observation.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::ThreadStartKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Heuristic score assigned to the observation.
    #[pygetset]
    fn score(&self) -> i32 {
        self.score
    }

    /// Whether the heuristic score is greater than zero.
    #[pygetset]
    fn suspicious(&self) -> bool {
        self.score > 0
    }

    /// Owning process ID.
    #[pygetset]
    fn process_id(&self) -> u32 {
        self.data.process_id
    }

    /// Observed thread ID.
    #[pygetset]
    fn thread_id(&self) -> u32 {
        self.data.thread_id
    }

    /// Preferred Win32 start virtual address, falling back to the system start address.
    #[pygetset]
    fn start_address(&self) -> u64 {
        self.data.start_address()
    }

    /// System-reported thread start virtual address.
    #[pygetset]
    fn system_start_address(&self) -> u64 {
        self.data.system_start_address
    }

    /// Win32 thread start virtual address, or None if unavailable.
    #[pygetset]
    fn win32_start_address(&self) -> Option<u64> {
        self.data.win32_start_address
    }

    /// Underlying thread-information snapshot.
    #[pygetset]
    fn thread(&self, vm: &VirtualMachine) -> PyRef<crate::vm::py_proc::CProcessThreadInfo> {
        CProcessThreadInfo { data: self.data.clone() }.into_ref(&vm.ctx)
    }

    /// Memory-region evidence associated with the observation.
    #[pygetset]
    fn region(&self, vm: &VirtualMachine) -> Option<PyRef<crate::vm::py_proc::CProcessMemoryRegion>> {
        match &self.region {
            Some(region) => Some(CProcessMemoryRegion { data: region.clone() }.into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Loader module containing the start address, or None.
    #[pygetset]
    fn module(&self, vm: &VirtualMachine) -> Option<PyRef<crate::vm::py_proc::CProcessModule>> {
        match &self.module {
            Some(module) => Some(module.clone().into_ref(&vm.ctx)),
            None => None,
        }
    }

    /// Human-readable explanation of the typed classification.
    #[pygetset]
    fn reason(&self) -> String {
        thread_start_reason(self.kind).to_string()
    }

    /// Format the record's primary counts or thread-location evidence.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "tid={} start=0x{:x} kind={:?} score={} reason={}",
            self.data.thread_id,
            self.data.start_address(),
            self.kind,
            self.score,
            thread_start_reason(self.kind),
        )
    }
}

/// Classification of a memory region intersecting a thread's reported stack.
#[pyclass(module = "br3k.pe.analysis", name = "ThreadStackRegion")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeThreadStackRegion {
    data: sysapi::ProcessThreadInfo,
    region: sysapi::MemoryRegion,
    kind: ThreadStackRegionKind,
    score: i32,
}

#[pyclass]
impl PeThreadStackRegion {
    /// Typed classification of this thread-related observation.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::vm::py_pe::types::ThreadStackRegionKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Heuristic score assigned to the observation.
    #[pygetset]
    fn score(&self) -> i32 {
        self.score
    }

    /// Whether the heuristic score is greater than zero.
    #[pygetset]
    fn suspicious(&self) -> bool {
        self.score > 0
    }

    /// Observed thread ID.
    #[pygetset]
    fn thread_id(&self) -> u32 {
        self.data.thread_id
    }

    /// Thread environment block virtual address, when available.
    #[pygetset]
    fn teb_address(&self) -> Option<u64> {
        self.data.teb_address
    }

    /// Upper reported stack boundary, when available.
    #[pygetset]
    fn stack_base(&self) -> Option<u64> {
        self.data.stack_base
    }

    /// Lower reported stack boundary, when available.
    #[pygetset]
    fn stack_limit(&self) -> Option<u64> {
        self.data.stack_limit
    }

    /// Underlying thread-information snapshot.
    #[pygetset]
    fn thread(&self, vm: &VirtualMachine) -> PyRef<crate::vm::py_proc::CProcessThreadInfo> {
        CProcessThreadInfo { data: self.data.clone() }.into_ref(&vm.ctx)
    }

    /// Memory-region evidence associated with the observation.
    #[pygetset]
    fn region(&self, vm: &VirtualMachine) -> PyRef<crate::vm::py_proc::CProcessMemoryRegion> {
        CProcessMemoryRegion { data: self.region.clone() }.into_ref(&vm.ctx)
    }

    /// Human-readable explanation of the typed classification.
    #[pygetset]
    fn reason(&self) -> String {
        thread_stack_region_reason(self.kind).to_string()
    }

    /// Format the record's primary counts or thread-location evidence.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "tid={} stack={} region=0x{:x}-0x{:x} kind={:?} score={} reason={}",
            self.data.thread_id,
            self.data
                .stack_limit
                .zip(self.data.stack_base)
                .map(|(limit, base)| format!("0x{limit:x}-0x{base:x}"))
                .unwrap_or_else(|| "none".to_string()),
            self.region.base_address,
            self.region.end_address(),
            self.kind,
            self.score,
            thread_stack_region_reason(self.kind),
        )
    }
}

/// Combined hidden-image, working-set, thread-start, and stack-region evidence.
///
/// Subqueries are best-effort: inspect working_set_error and thread_error before
/// interpreting empty lists or zero counters. Suspicious flags are heuristic.
#[pyclass(module = "br3k.pe.analysis", name = "ProcessScan")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeProcessScan {
    modules: Vec<CProcessModule>,
    hidden_modules: PeHiddenModuleScanResult,
    working_set_regions: Vec<sysapi::WorkingSetRegionSummary>,
    working_set_error: Option<String>,
    thread_starts: Vec<PeThreadStartEvidence>,
    thread_stack_regions: Vec<PeThreadStackRegion>,
    thread_error: Option<String>,
}

impl PeProcessScan {
    pub(crate) fn build(
        process: &Process,
        modules: Vec<CProcessModule>,
        hidden_options: Option<PeHiddenModuleScanOptions>,
        vm: &VirtualMachine,
    ) -> PyResult<Self> {
        let hidden_modules = find_hidden_modules_inner(
            process,
            modules.clone(),
            hidden_options.unwrap_or_default(),
            vm,
        )?;
        let (working_set_regions, working_set_error) = match process_working_set_regions(
            process,
            hidden_modules.executable_region_values(),
        ) {
            Ok(regions) => (regions, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        let (thread_starts, thread_stack_regions, thread_error) = match process_threads(process) {
            Ok(threads) => {
                let thread_starts = classify_thread_starts(&threads, &modules, hidden_modules.region_values());
                let thread_stack_regions = classify_thread_stack_regions(&threads, hidden_modules.region_values());

                (thread_starts, thread_stack_regions, None)
            }
            Err(error) => (Vec::new(), Vec::new(), Some(error)),
        };

        Ok(Self {
            modules,
            hidden_modules,
            working_set_regions,
            working_set_error,
            thread_starts,
            thread_stack_regions,
            thread_error,
        })
    }
}

#[pyclass]
impl PeProcessScan {
    /// Loader modules used for scan classification.
    #[pygetset]
    fn modules(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessModule>> {
        process_modules_to_py(&self.modules, vm)
    }

    /// Complete hidden-module scan result, including its options and unfiltered candidates.
    #[pygetset]
    fn hidden_modules(&self, vm: &VirtualMachine) -> PyRef<super::hidden::PeHiddenModuleScanResult> {
        self.hidden_modules.clone().into_ref(&vm.ctx)
    }

    /// Residency and sharing summaries for queried executable regions.
    #[pygetset]
    fn working_set_regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<crate::vm::py_proc::CProcessWorkingSetRegion>> {
        working_set_regions_to_py(&self.working_set_regions, vm)
    }

    /// Working-set query failure, or None if that stage succeeded.
    #[pygetset]
    fn working_set_error(&self) -> Option<String> {
        self.working_set_error.clone()
    }

    /// Classified start-address evidence for the enumerated threads.
    #[pygetset]
    fn thread_starts(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeThreadStartEvidence>> {
        thread_start_evidence_to_py(&self.thread_starts, vm)
    }

    /// Thread-start observations whose heuristic score is positive.
    #[pygetset]
    fn suspicious_thread_starts(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeThreadStartEvidence>> {
        thread_start_evidence_to_py(
            &self.thread_starts
                .iter()
                .filter(|thread| thread.suspicious())
                .cloned()
                .collect::<Vec<_>>(),
            vm,
        )
    }

    /// Classified regions intersecting reported thread stacks.
    #[pygetset]
    fn thread_stack_regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeThreadStackRegion>> {
        thread_stack_regions_to_py(&self.thread_stack_regions, vm)
    }

    /// Stack-region observations whose heuristic score is positive.
    #[pygetset]
    fn suspicious_thread_stack_regions(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeThreadStackRegion>> {
        thread_stack_regions_to_py(
            &self.thread_stack_regions
                .iter()
                .filter(|region| region.suspicious())
                .cloned()
                .collect::<Vec<_>>(),
            vm,
        )
    }

    /// Thread-enumeration failure, or None if that stage succeeded.
    #[pygetset]
    fn thread_error(&self) -> Option<String> {
        self.thread_error.clone()
    }

    /// Reportable findings from the hidden-image scan.
    #[pygetset]
    fn findings(&self, vm: &VirtualMachine) -> PyListOf<PyRef<super::hidden::PeScanFinding>> {
        let findings = self.hidden_modules.findings_values();

        scan_findings_to_py(&findings, vm)
    }

    /// Hidden-image candidates passing the scan's reporting threshold.
    #[pygetset]
    fn hidden_candidates(&self, vm: &VirtualMachine) -> PyListOf<PyRef<super::hidden::PeHiddenModuleCandidate>> {
        let candidates = self
            .hidden_modules
            .visible_candidate_values()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        hidden_candidates_to_py(&candidates, vm)
    }

    /// Number of loader-listed modules.
    #[pygetset]
    fn module_count(&self) -> usize {
        self.hidden_modules.module_count()
    }

    /// Number of regions in the memory-map snapshot.
    #[pygetset]
    fn region_count(&self) -> usize {
        self.hidden_modules.region_count()
    }

    /// Number of executable regions considered by the hidden-image scan.
    #[pygetset]
    fn executable_region_count(&self) -> usize {
        self.hidden_modules.executable_region_count()
    }

    /// Executable regions outside loader-module coverage.
    #[pygetset]
    fn orphan_executable_region_count(&self) -> usize {
        self.hidden_modules.orphan_executable_region_count()
    }

    /// Number of candidates before reporting filters.
    #[pygetset]
    fn hidden_candidate_count(&self) -> usize {
        self.hidden_modules.candidate_count()
    }

    /// Number of candidates passing reporting filters.
    #[pygetset]
    fn visible_hidden_candidate_count(&self) -> usize {
        self.hidden_modules.visible_candidate_values().len()
    }

    /// Number of reportable hidden-image findings.
    #[pygetset]
    fn finding_count(&self) -> usize {
        self.hidden_modules.findings_values().len()
    }

    /// Number of executable regions with working-set summaries.
    #[pygetset]
    fn working_set_region_count(&self) -> usize {
        self.working_set_regions.len()
    }

    /// Number of threads with start-address classifications.
    #[pygetset]
    fn thread_count(&self) -> usize {
        self.thread_starts.len()
    }

    /// Number of classified thread/stack-region observations.
    #[pygetset]
    fn thread_stack_region_count(&self) -> usize {
        self.thread_stack_regions.len()
    }

    /// Number of stack-region observations with positive score.
    #[pygetset]
    fn suspicious_thread_stack_region_count(&self) -> usize {
        self.thread_stack_regions
            .iter()
            .filter(|region| region.suspicious())
            .count()
    }

    /// Number of thread-start observations with positive score.
    #[pygetset]
    fn suspicious_thread_start_count(&self) -> usize {
        self.thread_starts
            .iter()
            .filter(|thread| thread.suspicious())
            .count()
    }

    /// Total pages queried across executable regions.
    #[pygetset]
    fn working_set_page_count(&self) -> usize {
        self.working_set_sum(|region| region.page_count)
    }

    /// Total valid working-set pages across queried executable regions.
    #[pygetset]
    fn working_set_valid_page_count(&self) -> usize {
        self.working_set_sum(|region| region.valid_page_count)
    }

    /// Total valid shared pages across queried executable regions.
    #[pygetset]
    fn working_set_shared_page_count(&self) -> usize {
        self.working_set_sum(|region| region.shared_page_count)
    }

    /// Total valid nonshared pages across queried executable regions.
    #[pygetset]
    fn working_set_private_page_count(&self) -> usize {
        self.working_set_sum(|region| region.private_page_count)
    }

    /// Valid nonshared pages in executable MEM_IMAGE regions.
    #[pygetset]
    fn image_executable_private_page_count(&self) -> usize {
        self.working_set_private_page_count_for(|region| region.region.is_image())
    }

    /// Valid nonshared pages in executable MEM_MAPPED regions.
    #[pygetset]
    fn mapped_executable_private_page_count(&self) -> usize {
        self.working_set_private_page_count_for(|region| region.region.is_mapped())
    }

    /// Valid pages in executable MEM_PRIVATE regions.
    #[pygetset]
    fn private_executable_valid_page_count(&self) -> usize {
        self.working_set_valid_page_count_for(|region| region.region.is_private())
    }

    /// Valid nonshared pages in executable regions outside loader-module coverage.
    #[pygetset]
    fn orphan_executable_private_page_count(&self) -> usize {
        self.working_set_private_page_count_for(|region| {
            self.hidden_modules
                .orphan_executable_region_values()
                .iter()
                .any(|orphan| same_region(orphan, &region.region))
        })
    }

    /// Format the record's primary counts or thread-location evidence.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "modules={} regions={} executable_regions={} orphan_executable_regions={} hidden_candidates={} findings={} executable_private_pages={} image_executable_private_pages={} threads={} suspicious_thread_starts={} suspicious_thread_stack_regions={}",
            self.module_count(),
            self.region_count(),
            self.executable_region_count(),
            self.orphan_executable_region_count(),
            self.visible_hidden_candidate_count(),
            self.finding_count(),
            self.working_set_private_page_count(),
            self.image_executable_private_page_count(),
            self.thread_count(),
            self.suspicious_thread_start_count(),
            self.suspicious_thread_stack_region_count(),
        )
    }
}

impl PeProcessScan {
    fn working_set_sum<F>(&self, value: F) -> usize
    where
        F: Fn(&sysapi::WorkingSetRegionSummary) -> usize,
    {
        self.working_set_regions
            .iter()
            .map(value)
            .sum()
    }

    fn working_set_private_page_count_for<F>(&self, predicate: F) -> usize
    where
        F: Fn(&sysapi::WorkingSetRegionSummary) -> bool,
    {
        self.working_set_regions
            .iter()
            .filter(|region| predicate(region))
            .map(|region| region.private_page_count)
            .sum()
    }

    fn working_set_valid_page_count_for<F>(&self, predicate: F) -> usize
    where
        F: Fn(&sysapi::WorkingSetRegionSummary) -> bool,
    {
        self.working_set_regions
            .iter()
            .filter(|region| predicate(region))
            .map(|region| region.valid_page_count)
            .sum()
    }
}

fn same_region(left: &sysapi::MemoryRegion, right: &sysapi::MemoryRegion) -> bool {
    left.base_address == right.base_address && left.region_size == right.region_size
}

fn thread_start_evidence_to_py(
    starts: &[PeThreadStartEvidence],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeThreadStartEvidence>> {
    let starts = starts
        .iter()
        .cloned()
        .map(|start| start.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(starts, vm)
}

fn thread_stack_regions_to_py(
    regions: &[PeThreadStackRegion],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeThreadStackRegion>> {
    let regions = regions
        .iter()
        .cloned()
        .map(|region| region.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(regions, vm)
}

fn classify_thread_starts(
    starts: &[sysapi::ProcessThreadInfo],
    modules: &[CProcessModule],
    regions: &[sysapi::MemoryRegion],
) -> Vec<PeThreadStartEvidence> {
    starts
        .iter()
        .cloned()
        .map(|data| {
            let address = data.start_address();
            let module = module_for_address(address, modules).cloned();
            let region = region_for_address(address, regions).cloned();
            let kind = thread_start_kind(&data, module.as_ref(), region.as_ref());

            PeThreadStartEvidence {
                data,
                kind,
                score: thread_start_score(kind),
                region,
                module,
            }
        })
        .collect()
}

fn classify_thread_stack_regions(
    threads: &[sysapi::ProcessThreadInfo],
    regions: &[sysapi::MemoryRegion],
) -> Vec<PeThreadStackRegion> {
    let mut stack_regions = Vec::new();

    for thread in threads {
        let Some((stack_limit, stack_base)) = thread.stack_limit.zip(thread.stack_base) else {
            continue;
        };

        if stack_limit == 0 || stack_limit >= stack_base {
            continue;
        }

        for region in regions {
            if !ranges_overlap(stack_limit, stack_base, region.base_address, region.end_address()) {
                continue;
            }

            let kind = thread_stack_region_kind(region);
            stack_regions.push(PeThreadStackRegion {
                data: thread.clone(),
                region: region.clone(),
                kind,
                score: thread_stack_region_score(kind),
            });
        }
    }

    stack_regions.sort_by_key(|region| (-region.score, region.data.thread_id, region.region.base_address));
    stack_regions
}

fn thread_start_kind(
    data: &sysapi::ProcessThreadInfo,
    module: Option<&CProcessModule>,
    region: Option<&sysapi::MemoryRegion>,
) -> ThreadStartKind {
    let address = data.start_address();

    if address == 0 {
        return ThreadStartKind::Unknown;
    }

    if module.is_some() {
        return ThreadStartKind::LoadedModule;
    }

    match region {
        None => ThreadStartKind::Unmapped,
        Some(region) if !region.is_executable() => ThreadStartKind::NonExecutableRegion,
        Some(region) if region.is_private() => ThreadStartKind::PrivateExecutableRegion,
        Some(region) if region.is_mapped() => ThreadStartKind::MappedExecutableRegion,
        Some(region) if region.is_image() => ThreadStartKind::DetachedImageRegion,
        Some(_) => ThreadStartKind::OrphanExecutableRegion,
    }
}

fn thread_stack_region_kind(region: &sysapi::MemoryRegion) -> ThreadStackRegionKind {
    if region.is_writable_executable() {
        ThreadStackRegionKind::WritableExecutableStackRegion
    } else if region.is_executable() {
        ThreadStackRegionKind::ExecutableStackRegion
    } else {
        ThreadStackRegionKind::StackRegion
    }
}

fn thread_stack_region_score(kind: ThreadStackRegionKind) -> i32 {
    match kind {
        ThreadStackRegionKind::StackRegion => 0,
        ThreadStackRegionKind::ExecutableStackRegion => 3,
        ThreadStackRegionKind::WritableExecutableStackRegion => 4,
    }
}

fn thread_start_score(kind: ThreadStartKind) -> i32 {
    match kind {
        ThreadStartKind::LoadedModule |
        ThreadStartKind::Unknown => 0,
        ThreadStartKind::NonExecutableRegion => 1,
        ThreadStartKind::Unmapped |
        ThreadStartKind::OrphanExecutableRegion => 2,
        ThreadStartKind::MappedExecutableRegion |
        ThreadStartKind::DetachedImageRegion => 3,
        ThreadStartKind::PrivateExecutableRegion => 4,
    }
}

fn thread_stack_region_reason(kind: ThreadStackRegionKind) -> &'static str {
    match kind {
        ThreadStackRegionKind::StackRegion => "thread stack memory region",
        ThreadStackRegionKind::ExecutableStackRegion => "thread stack overlaps executable memory",
        ThreadStackRegionKind::WritableExecutableStackRegion => "thread stack overlaps writable executable memory",
    }
}

fn thread_start_reason(kind: ThreadStartKind) -> &'static str {
    match kind {
        ThreadStartKind::LoadedModule => "thread start is inside a loaded module",
        ThreadStartKind::PrivateExecutableRegion => "thread start is inside executable MEM_PRIVATE memory outside loaded modules",
        ThreadStartKind::MappedExecutableRegion => "thread start is inside executable MEM_MAPPED memory outside loaded modules",
        ThreadStartKind::DetachedImageRegion => "thread start is inside executable MEM_IMAGE memory outside loaded modules",
        ThreadStartKind::OrphanExecutableRegion => "thread start is inside executable memory outside loaded modules",
        ThreadStartKind::NonExecutableRegion => "thread start resolves to a non-executable memory region",
        ThreadStartKind::Unmapped => "thread start does not resolve to a committed memory region",
        ThreadStartKind::Unknown => "thread start address is not available",
    }
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn module_for_address<'a>(
    address: u64,
    modules: &'a [CProcessModule],
) -> Option<&'a CProcessModule> {
    modules
        .iter()
        .find(|module| {
            let end = module.dll_base.saturating_add(module.size_of_image as u64);
            address >= module.dll_base && address < end
        })
}

fn region_for_address<'a>(
    address: u64,
    regions: &'a [sysapi::MemoryRegion],
) -> Option<&'a sysapi::MemoryRegion> {
    regions
        .iter()
        .find(|region| address >= region.base_address && address < region.end_address())
}
