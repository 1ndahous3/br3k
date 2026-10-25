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
    /// Raw directory address: an RVA except for the security directory's file offset.
    #[pymember]
    virtual_address: u32,
    /// Directory, overlay, or resource-data size in bytes.
    #[pymember]
    size: u32,
}

#[pyclass]
impl PeDataDirectory {
    /// Whether the directory address or size is zero.
    #[pygetset]
    fn empty(zelf: &Py<Self>) -> bool {
        zelf.virtual_address == 0 || zelf.size == 0
    }
}

/// Trailing file-layout range beyond the image's section-backed content.
#[pyclass(module = "br3k.pe.security", name = "OverlayRange")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeOverlayRange {
    /// File byte offset where the overlay begins.
    #[pymember]
    offset: PyRef<PyInt>,
    /// Directory, overlay, or resource-data size in bytes.
    #[pymember]
    size: PyRef<PyInt>,
}

#[pyclass]
impl PeOverlayRange {}

/// Resource-tree extent and aggregate counts from parsing.
#[pyclass(module = "br3k.pe.resources", name = "DirectoryInfo")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourceDirectoryInfo {
    /// RVA of the resource directory.
    #[pymember]
    virtual_address: u32,
    /// Directory, overlay, or resource-data size in bytes.
    #[pymember]
    size: u32,
    /// Number of resource-directory nodes.
    #[pymember]
    directory_count: PyRef<PyInt>,
    /// Number of named resource-tree entries.
    #[pymember]
    named_entry_count: PyRef<PyInt>,
    /// Number of numeric-ID resource-tree entries.
    #[pymember]
    id_entry_count: PyRef<PyInt>,
    /// Number of resource-data leaves.
    #[pymember]
    data_entry_count: PyRef<PyInt>,
    /// Aggregate resource-data size in bytes.
    #[pymember]
    data_size: u64,
    /// Maximum observed resource-tree nesting depth.
    #[pymember]
    max_depth: PyRef<PyInt>,
}

#[pyclass]
impl PeResourceDirectoryInfo {}

/// One named or numeric component of a resource path.
#[pyclass(module = "br3k.pe.resources", name = "PathEntry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourcePathEntry {
    /// Text name of this path component, when named.
    #[pymember]
    name: Option<PyStrRef>,
    /// Numeric ID of this path component, when ID-based.
    #[pymember]
    id: Option<PyRef<PyInt>>,
    /// Display form of the path component, using # for numeric IDs.
    #[pymember]
    text: PyStrRef,
}

#[pyclass]
impl PeResourcePathEntry {}

/// A resource leaf's path, data location, size, and code-page metadata.
#[py_api]
#[pyclass(module = "br3k.pe.resources", name = "DataEntry")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeResourceDataEntry {
    /// Cached typed resource-path components.
    #[pyi(ty = "list[br3k.pe.resources.PathEntry]")]
    #[pymember]
    path: PyListRef,
    /// Slash-separated display form of the resource path.
    #[pymember]
    path_text: PyStrRef,
    /// Named resource type from the first path component, when present.
    #[pymember]
    type_name: Option<PyStrRef>,
    /// Numeric resource type from the first path component, when present.
    #[pymember]
    type_id: Option<PyRef<PyInt>>,
    /// Named resource identity from the second path component, when present.
    #[pymember]
    resource_name: Option<PyStrRef>,
    /// Numeric resource identity from the second path component, when present.
    #[pymember]
    resource_id: Option<PyRef<PyInt>>,
    /// Numeric language identifier from the third path component, when present.
    #[pymember]
    language_id: Option<PyRef<PyInt>>,
    /// RVA of the resource leaf's payload bytes.
    #[pymember]
    data_rva: u32,
    /// Directory, overlay, or resource-data size in bytes.
    #[pymember]
    size: u32,
    /// Declared resource-data code page.
    #[pymember]
    code_page: u32,
    /// Raw reserved field from IMAGE_RESOURCE_DATA_ENTRY.
    #[pymember]
    reserved: u32,
}

#[pyclass]
impl PeResourceDataEntry {}

pub(crate) fn data_directory_to_py(directory: DataDirectory, vm: &VirtualMachine) -> PyRef<PeDataDirectory> {
    PeDataDirectory {
        virtual_address: directory.virtual_address,
        size: directory.size,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn overlay_range_to_py(range: OverlayRange, vm: &VirtualMachine) -> PyRef<PeOverlayRange> {
    PeOverlayRange {
        offset: vm.ctx.new_int(range.offset),
        size: vm.ctx.new_int(range.size),
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
        directory_count: vm.ctx.new_int(info.directory_count),
        named_entry_count: vm.ctx.new_int(info.named_entry_count),
        id_entry_count: vm.ctx.new_int(info.id_entry_count),
        data_entry_count: vm.ctx.new_int(info.data_entry_count),
        data_size: info.data_size,
        max_depth: vm.ctx.new_int(info.max_depth),
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
        path: PyListOf::new(path_entries, vm).into(),
        path_text: vm.ctx.new_str(resource_path_text(&entry.path)),
        type_name: type_entry.and_then(|entry| entry.name.as_deref()).map(|value| vm.ctx.new_str(value)),
        type_id: type_entry.and_then(|entry| entry.id).map(|value| vm.ctx.new_int(value)),
        resource_name: name_entry.and_then(|entry| entry.name.as_deref()).map(|value| vm.ctx.new_str(value)),
        resource_id: name_entry.and_then(|entry| entry.id).map(|value| vm.ctx.new_int(value)),
        language_id: language_entry.and_then(|entry| entry.id).map(|value| vm.ctx.new_int(value)),
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
        name: entry.name.as_deref().map(|value| vm.ctx.new_str(value)),
        id: entry.id.map(|value| vm.ctx.new_int(value)),
        text: vm.ctx.new_str(resource_path_entry_text(entry)),
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
