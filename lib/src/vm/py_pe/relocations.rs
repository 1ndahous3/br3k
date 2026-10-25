use crate::vm::prelude::*;

use crate::pe::relocations::{
    BaseRelocationBlock, BaseRelocationEntry, RebaseResult, RelocationBuild,
    RelocationCandidate, RelocationDiscovery,
};

/// One PE base-relocation entry with its raw type and architecture-aware classification.
#[pyclass(module = "br3k.pe.relocations", name = "Entry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeBaseRelocationEntry {
    entry: BaseRelocationEntry,
}

#[pyclass]
impl PeBaseRelocationEntry {
    /// Image-relative address of the relocation site.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 {
        zelf.entry.rva
    }

    /// Byte offset of the relocation site within its relocation page.
    #[pygetset]
    fn offset(zelf: &Py<Self>) -> u16 {
        zelf.entry.offset
    }

    /// Uninterpreted numeric relocation type from the entry.
    #[pygetset]
    fn raw_kind(zelf: &Py<Self>) -> u16 {
        zelf.entry.raw_kind
    }

    /// Architecture-aware relocation kind.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::relocations::BaseRelocationKind>> {
        PyEnumValue::new(zelf.entry.kind, vm)
    }

    /// Display name for the relocation kind.
    #[pygetset]
    fn kind_name(zelf: &Py<Self>) -> &'static str {
        zelf.entry.kind.as_str()
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "{} rva=0x{:x} offset=0x{:x} raw_kind={}",
            zelf.entry.kind.as_str(),
            zelf.entry.rva,
            zelf.entry.offset,
            zelf.entry.raw_kind
        )
    }
}

/// A page-grouped base-relocation block and its decoded entries.
#[pyclass(module = "br3k.pe.relocations", name = "Block")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeBaseRelocationBlock {
    block: BaseRelocationBlock,
}

#[pyclass]
impl PeBaseRelocationBlock {
    /// Image-relative base of the relocation block's page.
    #[pygetset]
    fn page_rva(zelf: &Py<Self>) -> u32 {
        zelf.block.page_rva
    }

    /// Encoded relocation-block size in bytes, including its header.
    #[pygetset]
    fn block_size(zelf: &Py<Self>) -> u32 {
        zelf.block.block_size
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(zelf: &Py<Self>) -> usize {
        zelf.block.entries.len()
    }

    /// Decoded entries in the block, including padding entries.
    #[pygetset]
    fn entries(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeBaseRelocationEntry>> {
        base_relocation_entries_to_py(&zelf.block.entries, vm)
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "page=0x{:x} size=0x{:x} entries={}",
            zelf.block.page_rva,
            zelf.block.block_size,
            zelf.block.entries.len()
        )
    }
}

/// A pointer-shaped value that may need relocation; heuristics can produce false positives.
#[pyclass(module = "br3k.pe.relocations", name = "Candidate")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeRelocationCandidate {
    candidate: RelocationCandidate,
}

#[pyclass]
impl PeRelocationCandidate {
    /// Image-relative address of the relocation site.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 {
        zelf.candidate.rva
    }

    /// Byte offset of the candidate within the scanned image storage layout.
    #[pygetset]
    fn offset(zelf: &Py<Self>) -> usize {
        zelf.candidate.offset
    }

    /// Pointer-sized value observed at the candidate site.
    #[pygetset]
    fn value(zelf: &Py<Self>) -> u64 {
        zelf.candidate.value
    }

    /// Image-relative target implied by the candidate value and load base.
    #[pygetset]
    fn target_rva(zelf: &Py<Self>) -> u32 {
        zelf.candidate.target_rva
    }

    /// Section containing the candidate site, when known.
    #[pygetset]
    fn section_name(zelf: &Py<Self>) -> Option<String> {
        zelf.candidate.section_name.clone()
    }

    /// Section containing the candidate target, when known.
    #[pygetset]
    fn target_section_name(zelf: &Py<Self>) -> Option<String> {
        zelf.candidate.target_section_name.clone()
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        let section = zelf.candidate.section_name.as_deref().unwrap_or("?");
        let target_section = zelf.candidate.target_section_name.as_deref().unwrap_or("?");

        format!(
            "rva=0x{:x} value=0x{:x} target_rva=0x{:x} section={} target_section={}",
            zelf.candidate.rva,
            zelf.candidate.value,
            zelf.candidate.target_rva,
            section,
            target_section,
        )
    }
}

/// Candidate relocations discovered by scanning an image under a chosen load base.
#[pyclass(module = "br3k.pe.relocations", name = "Discovery")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeRelocationDiscovery {
    discovery: RelocationDiscovery,
}

#[pyclass]
impl PeRelocationDiscovery {
    /// Load base used to interpret pointer values.
    #[pygetset]
    fn image_base(zelf: &Py<Self>) -> u64 {
        zelf.discovery.image_base
    }

    /// Image size used to bound candidate targets, in bytes.
    #[pygetset]
    fn image_size(zelf: &Py<Self>) -> u32 {
        zelf.discovery.image_size
    }

    /// Pointer width in bytes for this image.
    #[pygetset]
    fn pointer_size(zelf: &Py<Self>) -> usize {
        zelf.discovery.pointer_size
    }

    /// Number of retained relocation candidates.
    #[pygetset]
    fn candidate_count(zelf: &Py<Self>) -> usize {
        zelf.discovery.candidates.len()
    }

    /// Pointer-shaped relocation candidates requiring validation.
    #[pygetset]
    fn candidates(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeRelocationCandidate>> {
        relocation_candidates_to_py(&zelf.discovery.candidates, vm)
    }

    /// Return the discovered relocation-site RVAs.
    #[pymethod]
    fn rvas(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<rustpython_vm::builtins::PyInt>> {
        let rvas = zelf.discovery
            .rvas()
            .into_iter()
            .map(|rva| vm.ctx.new_int(rva))
            .collect::<Vec<_>>();

        PyListOf::new(rvas, vm)
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "base=0x{:x} size=0x{:x} pointer_size={} candidates={}",
            zelf.discovery.image_base,
            zelf.discovery.image_size,
            zelf.discovery.pointer_size,
            zelf.discovery.candidates.len(),
        )
    }
}

/// Rebased image bytes with the applied base delta and relocation counts.
#[pyclass(module = "br3k.pe.relocations", name = "RebaseResult")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeRebaseResult {
    result: RebaseResult,
}

#[pyclass]
impl PeRebaseResult {
    /// Independent bytes produced by the relocation operation.
    #[pygetset]
    fn image(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(zelf.result.image.clone())
    }

    /// Base before rebasing.
    #[pygetset]
    fn old_image_base(zelf: &Py<Self>) -> u64 {
        zelf.result.old_image_base
    }

    /// Requested base after rebasing.
    #[pygetset]
    fn new_image_base(zelf: &Py<Self>) -> u64 {
        zelf.result.new_image_base
    }

    /// Signed byte difference between new and old bases.
    #[pygetset]
    fn delta(zelf: &Py<Self>) -> i64 {
        zelf.result.delta
    }

    /// Number of relocation blocks processed or produced.
    #[pygetset]
    fn block_count(zelf: &Py<Self>) -> usize {
        zelf.result.block_count
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(zelf: &Py<Self>) -> usize {
        zelf.result.entry_count
    }

    /// Number of relocation entries applied to image bytes.
    #[pygetset]
    fn applied_count(zelf: &Py<Self>) -> usize {
        zelf.result.applied_count
    }

    /// Number of entries not applied, such as padding.
    #[pygetset]
    fn skipped_count(zelf: &Py<Self>) -> usize {
        zelf.result.skipped_count
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "0x{:x}->0x{:x} delta={} blocks={} entries={} applied={} skipped={}",
            zelf.result.old_image_base,
            zelf.result.new_image_base,
            zelf.result.delta,
            zelf.result.block_count,
            zelf.result.entry_count,
            zelf.result.applied_count,
            zelf.result.skipped_count
        )
    }
}

/// Image bytes with a rebuilt relocation directory and its generated layout.
#[pyclass(module = "br3k.pe.relocations", name = "Build")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeRelocationBuild {
    result: RelocationBuild,
}

#[pyclass]
impl PeRelocationBuild {
    /// Independent bytes produced by the relocation operation.
    #[pygetset]
    fn image(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(zelf.result.image.clone())
    }

    /// RVA of the section containing rebuilt relocation metadata.
    #[pygetset]
    fn section_rva(zelf: &Py<Self>) -> u32 {
        zelf.result.section_rva
    }

    /// Generated relocation section size in bytes.
    #[pygetset]
    fn section_size(zelf: &Py<Self>) -> u32 {
        zelf.result.section_size
    }

    /// RVA of the rebuilt relocation directory.
    #[pygetset]
    fn directory_rva(zelf: &Py<Self>) -> u32 {
        zelf.result.directory_rva
    }

    /// Rebuilt relocation directory size in bytes.
    #[pygetset]
    fn directory_size(zelf: &Py<Self>) -> u32 {
        zelf.result.directory_size
    }

    /// Number of relocation blocks processed or produced.
    #[pygetset]
    fn block_count(zelf: &Py<Self>) -> usize {
        zelf.result.block_count
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(zelf: &Py<Self>) -> usize {
        zelf.result.entry_count
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "section=0x{:x}/0x{:x} directory=0x{:x}/0x{:x} blocks={} entries={}",
            zelf.result.section_rva,
            zelf.result.section_size,
            zelf.result.directory_rva,
            zelf.result.directory_size,
            zelf.result.block_count,
            zelf.result.entry_count
        )
    }
}

pub(crate) fn base_relocation_blocks_to_py(
    blocks: &[BaseRelocationBlock],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeBaseRelocationBlock>> {
    let blocks = blocks
        .iter()
        .cloned()
        .map(|block| PeBaseRelocationBlock { block }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(blocks, vm)
}

pub(crate) fn rebase_result_to_py(result: RebaseResult, vm: &VirtualMachine) -> PyRef<PeRebaseResult> {
    PeRebaseResult { result }.into_ref(&vm.ctx)
}

pub(crate) fn relocation_build_to_py(
    result: RelocationBuild,
    vm: &VirtualMachine,
) -> PyRef<PeRelocationBuild> {
    PeRelocationBuild { result }.into_ref(&vm.ctx)
}

pub(crate) fn relocation_discovery_to_py(
    discovery: RelocationDiscovery,
    vm: &VirtualMachine,
) -> PyRef<PeRelocationDiscovery> {
    PeRelocationDiscovery { discovery }.into_ref(&vm.ctx)
}

fn base_relocation_entries_to_py(
    entries: &[BaseRelocationEntry],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeBaseRelocationEntry>> {
    let entries = entries
        .iter()
        .copied()
        .map(|entry| PeBaseRelocationEntry { entry }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(entries, vm)
}

fn relocation_candidates_to_py(
    candidates: &[RelocationCandidate],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeRelocationCandidate>> {
    let candidates = candidates
        .iter()
        .cloned()
        .map(|candidate| PeRelocationCandidate { candidate }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(candidates, vm)
}
