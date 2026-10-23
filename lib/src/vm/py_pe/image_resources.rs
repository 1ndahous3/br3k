use crate::vm::prelude::*;

use crate::pe::image::{
    DataDirectory, OverlayRange, ResourceDataEntry, ResourceDirectoryInfo,
    ResourceMergePreference, ResourcePathEntry,
};

/// A PE data-directory address and byte size.
///
/// The security-directory address is a file offset; other directory addresses
/// are RVAs. An empty record is not a validated or parsed directory.
#[pyclass(module = "br3k.pe.headers", name = "DataDirectory")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[pyclass]
impl PeDataDirectory {
    /// Raw directory address: an RVA except for the security directory's file offset.
    #[pygetset]
    fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    /// Directory, overlay, or resource-data size in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.size
    }

    /// Whether the directory address or size is zero.
    #[pygetset]
    fn empty(&self) -> bool {
        self.virtual_address == 0 || self.size == 0
    }
}

/// Trailing file-layout range beyond the image's section-backed content.
#[pyclass(module = "br3k.pe.security", name = "OverlayRange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeOverlayRange {
    offset: usize,
    size: usize,
}

#[pyclass]
impl PeOverlayRange {
    /// File byte offset where the overlay begins.
    #[pygetset]
    fn offset(&self) -> usize {
        self.offset
    }

    /// Directory, overlay, or resource-data size in bytes.
    #[pygetset]
    fn size(&self) -> usize {
        self.size
    }
}

/// Resource-tree extent and aggregate counts from parsing.
#[pyclass(module = "br3k.pe.resources", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourceDirectoryInfo {
    virtual_address: u32,
    size: u32,
    directory_count: usize,
    named_entry_count: usize,
    id_entry_count: usize,
    data_entry_count: usize,
    data_size: u64,
    max_depth: usize,
}

#[pyclass]
impl PeResourceDirectoryInfo {
    /// RVA of the resource directory.
    #[pygetset]
    fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    /// Directory, overlay, or resource-data size in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.size
    }

    /// Number of resource-directory nodes.
    #[pygetset]
    fn directory_count(&self) -> usize {
        self.directory_count
    }

    /// Number of named resource-tree entries.
    #[pygetset]
    fn named_entry_count(&self) -> usize {
        self.named_entry_count
    }

    /// Number of numeric-ID resource-tree entries.
    #[pygetset]
    fn id_entry_count(&self) -> usize {
        self.id_entry_count
    }

    /// Number of resource-data leaves.
    #[pygetset]
    fn data_entry_count(&self) -> usize {
        self.data_entry_count
    }

    /// Aggregate resource-data size in bytes.
    #[pygetset]
    fn data_size(&self) -> u64 {
        self.data_size
    }

    /// Maximum observed resource-tree nesting depth.
    #[pygetset]
    fn max_depth(&self) -> usize {
        self.max_depth
    }
}

/// One named or numeric component of a resource path.
#[pyclass(module = "br3k.pe.resources", name = "PathEntry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourcePathEntry {
    name: Option<String>,
    id: Option<u32>,
    text: String,
}

#[pyclass]
impl PeResourcePathEntry {
    /// Text name of this path component, when named.
    #[pygetset]
    fn name(&self) -> Option<String> {
        self.name.clone()
    }

    /// Numeric ID of this path component, when ID-based.
    #[pygetset]
    fn id(&self) -> Option<u32> {
        self.id
    }

    /// Display form of the path component, using # for numeric IDs.
    #[pygetset]
    fn text(&self) -> String {
        self.text.clone()
    }
}

/// A resource leaf's path, data location, size, and code-page metadata.
#[pyclass(module = "br3k.pe.resources", name = "DataEntry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourceDataEntry {
    path: PyListOf<PyRef<PeResourcePathEntry>>,
    path_text: String,
    type_name: Option<String>,
    type_id: Option<u32>,
    resource_name: Option<String>,
    resource_id: Option<u32>,
    language_id: Option<u32>,
    data_rva: u32,
    size: u32,
    code_page: u32,
    reserved: u32,
}

#[pyclass]
impl PeResourceDataEntry {
    /// Cached typed resource-path components.
    #[pygetset]
    fn path(&self) -> PyListOf<PyRef<PeResourcePathEntry>> {
        self.path.clone()
    }

    /// Slash-separated display form of the resource path.
    #[pygetset]
    fn path_text(&self) -> String {
        self.path_text.clone()
    }

    /// Named resource type from the first path component, when present.
    #[pygetset]
    fn type_name(&self) -> Option<String> {
        self.type_name.clone()
    }

    /// Numeric resource type from the first path component, when present.
    #[pygetset]
    fn type_id(&self) -> Option<u32> {
        self.type_id
    }

    /// Named resource identity from the second path component, when present.
    #[pygetset]
    fn resource_name(&self) -> Option<String> {
        self.resource_name.clone()
    }

    /// Numeric resource identity from the second path component, when present.
    #[pygetset]
    fn resource_id(&self) -> Option<u32> {
        self.resource_id
    }

    /// Numeric language identifier from the third path component, when present.
    #[pygetset]
    fn language_id(&self) -> Option<u32> {
        self.language_id
    }

    /// RVA of the resource leaf's payload bytes.
    #[pygetset]
    fn data_rva(&self) -> u32 {
        self.data_rva
    }

    /// Directory, overlay, or resource-data size in bytes.
    #[pygetset]
    fn size(&self) -> u32 {
        self.size
    }

    /// Declared resource-data code page.
    #[pygetset]
    fn code_page(&self) -> u32 {
        self.code_page
    }

    /// Raw reserved field from IMAGE_RESOURCE_DATA_ENTRY.
    #[pygetset]
    fn reserved(&self) -> u32 {
        self.reserved
    }
}

pub(crate) fn data_directory_to_py(directory: DataDirectory, vm: &VirtualMachine) -> PyRef<PeDataDirectory> {
    PeDataDirectory {
        virtual_address: directory.virtual_address,
        size: directory.size,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn overlay_range_to_py(range: OverlayRange, vm: &VirtualMachine) -> PyRef<PeOverlayRange> {
    PeOverlayRange {
        offset: range.offset,
        size: range.size,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn resource_directory_info_to_py(
    info: ResourceDirectoryInfo,
    vm: &VirtualMachine,
) -> PyRef<PeResourceDirectoryInfo> {
    PeResourceDirectoryInfo {
        virtual_address: info.virtual_address,
        size: info.size,
        directory_count: info.directory_count,
        named_entry_count: info.named_entry_count,
        id_entry_count: info.id_entry_count,
        data_entry_count: info.data_entry_count,
        data_size: info.data_size,
        max_depth: info.max_depth,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn resource_data_entry_to_py(
    entry: ResourceDataEntry,
    vm: &VirtualMachine,
) -> PyRef<PeResourceDataEntry> {
    let path_entries = entry
        .path
        .iter()
        .map(|entry| resource_path_entry_to_py(entry, vm))
        .collect::<Vec<_>>();
    let type_entry = entry.path.first();
    let name_entry = entry.path.get(1);
    let language_entry = entry.path.get(2);

    PeResourceDataEntry {
        path: PyListOf::new(path_entries, vm),
        path_text: resource_path_text(&entry.path),
        type_name: type_entry.and_then(|entry| entry.name.clone()),
        type_id: type_entry.and_then(|entry| entry.id),
        resource_name: name_entry.and_then(|entry| entry.name.clone()),
        resource_id: name_entry.and_then(|entry| entry.id),
        language_id: language_entry.and_then(|entry| entry.id),
        data_rva: entry.data_rva,
        size: entry.size,
        code_page: entry.code_page,
        reserved: entry.reserved,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn resource_merge_preference(
    value: u32,
    vm: &VirtualMachine,
) -> PyResult<ResourceMergePreference> {
    ResourceMergePreference::from_repr(value)
        .ok_or_else(|| vm.new_value_error(format!("Invalid ResourceMergePreference: {value}")))
}

pub(crate) fn resource_path_text(path: &[ResourcePathEntry]) -> String {
    path.iter()
        .map(resource_path_entry_text)
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn resource_path_entry_to_py(entry: &ResourcePathEntry, vm: &VirtualMachine) -> PyRef<PeResourcePathEntry> {
    PeResourcePathEntry {
        name: entry.name.clone(),
        id: entry.id,
        text: resource_path_entry_text(entry),
    }
    .into_ref(&vm.ctx)
}

fn resource_path_entry_text(entry: &ResourcePathEntry) -> String {
    match (&entry.name, entry.id) {
        (Some(name), _) => name.clone(),
        (None, Some(id)) => format!("#{id}"),
        (None, None) => "?".to_string(),
    }
}
