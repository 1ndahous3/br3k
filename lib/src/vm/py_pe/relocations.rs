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
    fn rva(&self) -> u32 {
        self.entry.rva
    }

    /// Byte offset of the relocation site within its relocation page.
    #[pygetset]
    fn offset(&self) -> u16 {
        self.entry.offset
    }

    /// Uninterpreted numeric relocation type from the entry.
    #[pygetset]
    fn raw_kind(&self) -> u16 {
        self.entry.raw_kind
    }

    /// Architecture-aware relocation kind.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::relocations::BaseRelocationKind>> {
        PyEnumValue::new(self.entry.kind, vm)
    }

    /// Display name for the relocation kind.
    #[pygetset]
    fn kind_name(&self) -> &'static str {
        self.entry.kind.as_str()
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "{} rva=0x{:x} offset=0x{:x} raw_kind={}",
            self.entry.kind.as_str(),
            self.entry.rva,
            self.entry.offset,
            self.entry.raw_kind
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
    fn page_rva(&self) -> u32 {
        self.block.page_rva
    }

    /// Encoded relocation-block size in bytes, including its header.
    #[pygetset]
    fn block_size(&self) -> u32 {
        self.block.block_size
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(&self) -> usize {
        self.block.entries.len()
    }

    /// Decoded entries in the block, including padding entries.
    #[pygetset]
    fn entries(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeBaseRelocationEntry>> {
        base_relocation_entries_to_py(&self.block.entries, vm)
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "page=0x{:x} size=0x{:x} entries={}",
            self.block.page_rva,
            self.block.block_size,
            self.block.entries.len()
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
    fn rva(&self) -> u32 {
        self.candidate.rva
    }

    /// Byte offset of the candidate within the scanned image storage layout.
    #[pygetset]
    fn offset(&self) -> usize {
        self.candidate.offset
    }

    /// Pointer-sized value observed at the candidate site.
    #[pygetset]
    fn value(&self) -> u64 {
        self.candidate.value
    }

    /// Image-relative target implied by the candidate value and load base.
    #[pygetset]
    fn target_rva(&self) -> u32 {
        self.candidate.target_rva
    }

    /// Section containing the candidate site, when known.
    #[pygetset]
    fn section_name(&self) -> Option<String> {
        self.candidate.section_name.clone()
    }

    /// Section containing the candidate target, when known.
    #[pygetset]
    fn target_section_name(&self) -> Option<String> {
        self.candidate.target_section_name.clone()
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        let section = self.candidate.section_name.as_deref().unwrap_or("?");
        let target_section = self.candidate.target_section_name.as_deref().unwrap_or("?");

        format!(
            "rva=0x{:x} value=0x{:x} target_rva=0x{:x} section={} target_section={}",
            self.candidate.rva,
            self.candidate.value,
            self.candidate.target_rva,
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
    fn image_base(&self) -> u64 {
        self.discovery.image_base
    }

    /// Image size used to bound candidate targets, in bytes.
    #[pygetset]
    fn image_size(&self) -> u32 {
        self.discovery.image_size
    }

    /// Pointer width in bytes for this image.
    #[pygetset]
    fn pointer_size(&self) -> usize {
        self.discovery.pointer_size
    }

    /// Number of retained relocation candidates.
    #[pygetset]
    fn candidate_count(&self) -> usize {
        self.discovery.candidates.len()
    }

    /// Pointer-shaped relocation candidates requiring validation.
    #[pygetset]
    fn candidates(&self, vm: &VirtualMachine) -> PyListOf<PyRef<PeRelocationCandidate>> {
        relocation_candidates_to_py(&self.discovery.candidates, vm)
    }

    /// Return the discovered relocation-site RVAs.
    #[pymethod]
    fn rvas(&self, vm: &VirtualMachine) -> PyListOf<PyRef<rustpython_vm::builtins::PyInt>> {
        let rvas = self.discovery
            .rvas()
            .into_iter()
            .map(|rva| vm.ctx.new_int(rva))
            .collect::<Vec<_>>();

        PyListOf::new(rvas, vm)
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "base=0x{:x} size=0x{:x} pointer_size={} candidates={}",
            self.discovery.image_base,
            self.discovery.image_size,
            self.discovery.pointer_size,
            self.discovery.candidates.len(),
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
    fn image(&self, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(self.result.image.clone())
    }

    /// Base before rebasing.
    #[pygetset]
    fn old_image_base(&self) -> u64 {
        self.result.old_image_base
    }

    /// Requested base after rebasing.
    #[pygetset]
    fn new_image_base(&self) -> u64 {
        self.result.new_image_base
    }

    /// Signed byte difference between new and old bases.
    #[pygetset]
    fn delta(&self) -> i64 {
        self.result.delta
    }

    /// Number of relocation blocks processed or produced.
    #[pygetset]
    fn block_count(&self) -> usize {
        self.result.block_count
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(&self) -> usize {
        self.result.entry_count
    }

    /// Number of relocation entries applied to image bytes.
    #[pygetset]
    fn applied_count(&self) -> usize {
        self.result.applied_count
    }

    /// Number of entries not applied, such as padding.
    #[pygetset]
    fn skipped_count(&self) -> usize {
        self.result.skipped_count
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "0x{:x}->0x{:x} delta={} blocks={} entries={} applied={} skipped={}",
            self.result.old_image_base,
            self.result.new_image_base,
            self.result.delta,
            self.result.block_count,
            self.result.entry_count,
            self.result.applied_count,
            self.result.skipped_count
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
    fn image(&self, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(self.result.image.clone())
    }

    /// RVA of the section containing rebuilt relocation metadata.
    #[pygetset]
    fn section_rva(&self) -> u32 {
        self.result.section_rva
    }

    /// Generated relocation section size in bytes.
    #[pygetset]
    fn section_size(&self) -> u32 {
        self.result.section_size
    }

    /// RVA of the rebuilt relocation directory.
    #[pygetset]
    fn directory_rva(&self) -> u32 {
        self.result.directory_rva
    }

    /// Rebuilt relocation directory size in bytes.
    #[pygetset]
    fn directory_size(&self) -> u32 {
        self.result.directory_size
    }

    /// Number of relocation blocks processed or produced.
    #[pygetset]
    fn block_count(&self) -> usize {
        self.result.block_count
    }

    /// Number of relocation entries described or processed.
    #[pygetset]
    fn entry_count(&self) -> usize {
        self.result.entry_count
    }

    /// Format relocation locations, layout, or operation counters.
    #[pymethod]
    fn summary(&self) -> String {
        format!(
            "section=0x{:x}/0x{:x} directory=0x{:x}/0x{:x} blocks={} entries={}",
            self.result.section_rva,
            self.result.section_size,
            self.result.directory_rva,
            self.result.directory_size,
            self.result.block_count,
            self.result.entry_count
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
