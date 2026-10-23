use super::*;

impl Image {
    pub fn copy_resource_directory_from_file(
        &self,
        source_data: &[u8],
        section_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut image = self.clone();

        image.copy_resource_directory_from_in_place(source_data, ResourceDirectorySourceLayout::File, section_name)?;
        Ok(image.into_data())
    }

    pub fn copy_resource_directory_from_mapped_image(
        &self,
        source_data: &[u8],
        section_name: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut image = self.clone();

        image.copy_resource_directory_from_in_place(source_data, ResourceDirectorySourceLayout::MappedImage, section_name)?;
        Ok(image.into_data())
    }

    pub fn copy_merged_resource_directory_from_file_and_mapped_image(
        &self,
        file_data: &[u8],
        mapped_data: &[u8],
        section_name: &str,
        preference: ResourceMergePreference,
    ) -> Result<Vec<u8>, Error> {
        let mut image = self.clone();

        image.copy_merged_resource_directory_from_in_place(file_data, mapped_data, section_name, preference)?;
        Ok(image.into_data())
    }

    pub fn resource_directory_info(&self) -> Result<ResourceDirectoryInfo, Error> {
        self.resource_directory_info_from(ResourceDirectorySourceLayout::File)
    }

    pub fn mapped_resource_directory_info(&self) -> Result<ResourceDirectoryInfo, Error> {
        self.resource_directory_info_from(ResourceDirectorySourceLayout::MappedImage)
    }

    pub fn resource_data_entries(&self) -> Result<Vec<ResourceDataEntry>, Error> {
        self.resource_data_entries_from(ResourceDirectorySourceLayout::File)
    }

    pub fn mapped_resource_data_entries(&self) -> Result<Vec<ResourceDataEntry>, Error> {
        self.resource_data_entries_from(ResourceDirectorySourceLayout::MappedImage)
    }

    fn copy_resource_directory_from_in_place(
        &mut self,
        source_data: &[u8],
        source_layout: ResourceDirectorySourceLayout,
        section_name: &str,
    ) -> Result<(), Error> {
        let source = Self::parse(source_data.to_vec())?;
        self.validate_same_machine_and_format(&source)?;

        let directory = source.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if directory.is_empty() {
            return Err(Error::DataDirectoryEmpty {
                index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
            });
        }

        let section = self.append_section_with_characteristics(
            section_name,
            directory.size as usize,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )?;
        let mut directory_data = match source_layout {
            ResourceDirectorySourceLayout::File => source.read_bytes_rva(directory.virtual_address, directory.size as usize)?,
            ResourceDirectorySourceLayout::MappedImage => source.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize)?,
        };
        rebase_resource_directory_data_rvas(&mut directory_data, directory.virtual_address, section.virtual_address)?;

        self.write_bytes(section.raw_offset, &directory_data)?;
        self.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, section.virtual_address, directory.size)
    }

    fn copy_merged_resource_directory_from_in_place(
        &mut self,
        file_data: &[u8],
        mapped_data: &[u8],
        section_name: &str,
        preference: ResourceMergePreference,
    ) -> Result<(), Error> {
        let file_source = Self::parse(file_data.to_vec())?;
        let mapped_source = Self::parse(mapped_data.to_vec())?;
        self.validate_same_machine_and_format(&file_source)?;
        self.validate_same_machine_and_format(&mapped_source)?;

        let file_leaves = file_source.resource_data_leaves_from(ResourceDirectorySourceLayout::File)?;
        let mapped_leaves = mapped_source.resource_data_leaves_from(ResourceDirectorySourceLayout::MappedImage)?;
        let merged_leaves = merge_resource_data_leaves(file_leaves, mapped_leaves, preference);
        let mut directory_data = build_resource_directory_data(&merged_leaves)?;
        let directory_size = u32::try_from(directory_data.len())
            .map_err(|_| Error::Overflow("converting merged resource directory size to u32"))?;
        let section = self.append_section_with_characteristics(
            section_name,
            directory_data.len(),
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )?;

        rebase_resource_directory_data_rvas(&mut directory_data, 0, section.virtual_address)?;
        self.write_bytes(section.raw_offset, &directory_data)?;
        self.set_data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, section.virtual_address, directory_size)
    }

    fn resource_directory_info_from(
        &self,
        source_layout: ResourceDirectorySourceLayout,
    ) -> Result<ResourceDirectoryInfo, Error> {
        let directory = self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if directory.is_empty() {
            return Err(Error::DataDirectoryEmpty {
                index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
            });
        }

        let directory_data = match source_layout {
            ResourceDirectorySourceLayout::File => self.read_bytes_rva(directory.virtual_address, directory.size as usize)?,
            ResourceDirectorySourceLayout::MappedImage => self.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize)?,
        };

        resource_directory_info_from_data(&directory_data, directory.virtual_address)
    }

    fn resource_data_entries_from(
        &self,
        source_layout: ResourceDirectorySourceLayout,
    ) -> Result<Vec<ResourceDataEntry>, Error> {
        let directory = self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if directory.is_empty() {
            return Err(Error::DataDirectoryEmpty {
                index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
            });
        }

        let directory_data = match source_layout {
            ResourceDirectorySourceLayout::File => self.read_bytes_rva(directory.virtual_address, directory.size as usize)?,
            ResourceDirectorySourceLayout::MappedImage => self.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize)?,
        };

        resource_data_entries_from_data(&directory_data, directory.virtual_address)
    }

    fn resource_data_leaves_from(
        &self,
        source_layout: ResourceDirectorySourceLayout,
    ) -> Result<Vec<ResourceDataLeaf>, Error> {
        let directory = self.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if directory.is_empty() {
            return Err(Error::DataDirectoryEmpty {
                index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
            });
        }

        let directory_data = match source_layout {
            ResourceDirectorySourceLayout::File => self.read_bytes_rva(directory.virtual_address, directory.size as usize)?,
            ResourceDirectorySourceLayout::MappedImage => self.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize)?,
        };

        resource_data_leaves_from_data(&directory_data, directory.virtual_address)
    }

}

struct ResourceRebaseState {
    directories: BTreeSet<usize>,
    data_entries: BTreeSet<usize>,
}

struct ResourceScanState {
    directories: BTreeSet<usize>,
    data_entries: BTreeSet<usize>,
    info: ResourceDirectoryInfo,
}

struct ResourceDataEntryScanState {
    directories: BTreeSet<usize>,
    entries: Vec<ResourceDataEntry>,
}

#[derive(Clone, Debug)]
pub(super) struct ResourceDataLeaf {
    pub(super) path: Vec<ResourcePathEntry>,
    pub(super) data: Vec<u8>,
    pub(super) code_page: u32,
    pub(super) reserved: u32,
}

#[derive(Clone, Debug, Default)]
struct ResourceTreeNode {
    children: BTreeMap<ResourceTreeKey, ResourceTreeNode>,
    leaf: Option<ResourceDataLeaf>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResourceTreeKey {
    Name(String),
    Id(u32),
}

pub(super) fn rebase_resource_directory_data_rvas(
    data: &mut [u8],
    old_resource_rva: u32,
    new_resource_rva: u32,
) -> Result<(), Error> {
    let resource_size = u32::try_from(data.len())
        .map_err(|_| Error::Overflow("converting resource directory size to u32"))?;
    let old_resource_end_rva = old_resource_rva
        .checked_add(resource_size)
        .ok_or(Error::Overflow("sizing resource directory RVA range"))?;
    let mut state = ResourceRebaseState {
        directories: BTreeSet::new(),
        data_entries: BTreeSet::new(),
    };

    rebase_resource_directory_at(data, 0, old_resource_rva, old_resource_end_rva, new_resource_rva, &mut state)
}

fn resource_directory_info_from_data(
    data: &[u8],
    resource_rva: u32,
) -> Result<ResourceDirectoryInfo, Error> {
    let resource_size = u32::try_from(data.len())
        .map_err(|_| Error::Overflow("converting resource directory size to u32"))?;
    let resource_end_rva = resource_rva
        .checked_add(resource_size)
        .ok_or(Error::Overflow("sizing resource directory RVA range"))?;
    let mut state = ResourceScanState {
        directories: BTreeSet::new(),
        data_entries: BTreeSet::new(),
        info: ResourceDirectoryInfo {
            virtual_address: resource_rva,
            size: resource_size,
            directory_count: 0,
            named_entry_count: 0,
            id_entry_count: 0,
            data_entry_count: 0,
            data_size: 0,
            max_depth: 0,
        },
    };

    scan_resource_directory_at(data, 0, resource_rva, resource_end_rva, 0, &mut state)?;
    Ok(state.info)
}

fn resource_data_entries_from_data(
    data: &[u8],
    resource_rva: u32,
) -> Result<Vec<ResourceDataEntry>, Error> {
    let resource_size = u32::try_from(data.len())
        .map_err(|_| Error::Overflow("converting resource directory size to u32"))?;
    let resource_end_rva = resource_rva
        .checked_add(resource_size)
        .ok_or(Error::Overflow("sizing resource directory RVA range"))?;
    let mut state = ResourceDataEntryScanState {
        directories: BTreeSet::new(),
        entries: Vec::new(),
    };
    let mut path = Vec::new();

    scan_resource_data_entries_at(data, 0, resource_rva, resource_end_rva, &mut path, &mut state)?;
    Ok(state.entries)
}

fn resource_data_leaves_from_data(
    data: &[u8],
    resource_rva: u32,
) -> Result<Vec<ResourceDataLeaf>, Error> {
    resource_data_entries_from_data(data, resource_rva)?
        .into_iter()
        .map(|entry| {
            if entry.path.is_empty() {
                return Err(Error::ResourceDataPathEmpty);
            }

            let data_offset = (entry.data_rva - resource_rva) as usize;
            Ok(ResourceDataLeaf {
                path: entry.path,
                data: checked_range(data, data_offset, entry.size as usize)?.to_vec(),
                code_page: entry.code_page,
                reserved: entry.reserved,
            })
        })
        .collect()
}

fn merge_resource_data_leaves(
    file_leaves: Vec<ResourceDataLeaf>,
    mapped_leaves: Vec<ResourceDataLeaf>,
    preference: ResourceMergePreference,
) -> Vec<ResourceDataLeaf> {
    let mut merged = BTreeMap::new();

    for leaf in file_leaves {
        merged.insert(resource_leaf_key(&leaf), leaf);
    }
    for leaf in mapped_leaves {
        let key = resource_leaf_key(&leaf);
        match merged.get(&key) {
            Some(existing) if !prefer_mapped_resource_leaf(existing, &leaf, preference) => {}
            _ => {
                merged.insert(key, leaf);
            }
        }
    }

    merged.into_iter().map(|(_, leaf)| leaf).collect()
}

fn resource_leaf_key(leaf: &ResourceDataLeaf) -> Vec<ResourceTreeKey> {
    leaf.path
        .iter()
        .map(|entry| match &entry.name {
            Some(name) => ResourceTreeKey::Name(name.clone()),
            None => ResourceTreeKey::Id(entry.id.unwrap_or_default()),
        })
        .collect()
}

fn prefer_mapped_resource_leaf(
    file_leaf: &ResourceDataLeaf,
    mapped_leaf: &ResourceDataLeaf,
    preference: ResourceMergePreference,
) -> bool {
    match preference {
        ResourceMergePreference::File => false,
        ResourceMergePreference::Mapped => true,
        ResourceMergePreference::Larger => mapped_leaf.data.len() > file_leaf.data.len(),
    }
}

pub(super) fn build_resource_directory_data(leaves: &[ResourceDataLeaf]) -> Result<Vec<u8>, Error> {
    if leaves.is_empty() {
        return Err(Error::DataDirectoryEmpty {
            index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
        });
    }

    let mut root = ResourceTreeNode::default();
    for leaf in leaves {
        insert_resource_data_leaf(&mut root, leaf.clone())?;
    }

    let mut data = Vec::new();
    let root_offset = write_resource_tree_node(&root, &mut data)?;
    debug_assert_eq!(root_offset, 0);
    Ok(data)
}

fn insert_resource_data_leaf(
    root: &mut ResourceTreeNode,
    leaf: ResourceDataLeaf,
) -> Result<(), Error> {
    if leaf.path.is_empty() {
        return Err(Error::ResourceDataPathEmpty);
    }

    let mut node = root;
    for (index, entry) in leaf.path.iter().enumerate() {
        let key = resource_tree_key_from_path_entry(entry)?;
        node = node.children.entry(key).or_default();
        if index + 1 != leaf.path.len() && node.leaf.is_some() {
            return Err(Error::ResourcePathConflict);
        }
    }

    if !node.children.is_empty() {
        return Err(Error::ResourcePathConflict);
    }
    node.leaf = Some(leaf);
    Ok(())
}

fn resource_tree_key_from_path_entry(entry: &ResourcePathEntry) -> Result<ResourceTreeKey, Error> {
    match (&entry.name, entry.id) {
        (Some(name), None) => Ok(ResourceTreeKey::Name(name.clone())),
        (None, Some(id)) => Ok(ResourceTreeKey::Id(id)),
        _ => Err(Error::ResourcePathMissingKey),
    }
}

fn write_resource_tree_node(
    node: &ResourceTreeNode,
    data: &mut Vec<u8>,
) -> Result<usize, Error> {
    if node.children.is_empty() && node.leaf.is_none() {
        return Err(Error::ResourcePathConflict);
    }

    let directory_offset = append_aligned_zeroes(data, IMAGE_RESOURCE_DIRECTORY_SIZE)?;
    let named_entries = node.children.keys().filter(|key| matches!(key, ResourceTreeKey::Name(_))).count();
    let id_entries = node.children.len() - named_entries;

    write_u16_at(data, directory_offset + 12, checked_u16(named_entries, "counting named resource entries")?)?;
    write_u16_at(data, directory_offset + 14, checked_u16(id_entries, "counting id resource entries")?)?;

    let entries_offset = append_zeroes(
        data,
        checked_mul_usize(
            node.children.len(),
            IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE,
            "sizing resource directory entries",
        )?,
    )?;

    for (index, (key, child)) in node.children.iter().enumerate() {
        let entry_offset = entries_offset + index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
        write_resource_tree_key(data, entry_offset, key)?;

        if child.children.is_empty() {
            let leaf = child.leaf.as_ref().ok_or(Error::ResourcePathConflict)?;
            let data_entry_offset = append_aligned_zeroes(data, IMAGE_RESOURCE_DATA_ENTRY_SIZE)?;
            let payload_offset = append_resource_payload(data, &leaf.data)?;

            write_u32_at(data, data_entry_offset, checked_u32(payload_offset, "writing resource data RVA")?)?;
            write_u32_at(data, data_entry_offset + 4, checked_u32(leaf.data.len(), "writing resource data size")?)?;
            write_u32_at(data, data_entry_offset + 8, leaf.code_page)?;
            write_u32_at(data, data_entry_offset + 12, leaf.reserved)?;
            write_u32_at(data, entry_offset + 4, checked_u32(data_entry_offset, "writing resource data entry offset")?)?;
        } else {
            if child.leaf.is_some() {
                return Err(Error::ResourcePathConflict);
            }

            let child_offset = write_resource_tree_node(child, data)?;
            write_u32_at(
                data,
                entry_offset + 4,
                IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY | checked_u32(child_offset, "writing resource child directory offset")?,
            )?;
        }
    }

    Ok(directory_offset)
}

fn write_resource_tree_key(
    data: &mut Vec<u8>,
    entry_offset: usize,
    key: &ResourceTreeKey,
) -> Result<(), Error> {
    match key {
        ResourceTreeKey::Name(name) => {
            let name_offset = append_resource_name(data, name)?;
            write_u32_at(
                data,
                entry_offset,
                IMAGE_RESOURCE_DIRECTORY_ENTRY_NAME_IS_STRING | checked_u32(name_offset, "writing resource name offset")?,
            )
        }
        ResourceTreeKey::Id(id) => {
            let id = checked_u16(*id as usize, "writing resource id")?;
            write_u32_at(data, entry_offset, id as u32)
        }
    }
}

fn append_resource_name(data: &mut Vec<u8>, name: &str) -> Result<usize, Error> {
    let chars = name.encode_utf16().collect::<Vec<_>>();
    let name_size = checked_add_usize(
        2,
        checked_mul_usize(chars.len(), 2, "sizing resource name string")?,
        "sizing resource name string",
    )?;
    let offset = append_aligned_zeroes(data, name_size)?;

    write_u16_at(data, offset, checked_u16(chars.len(), "writing resource name string length")?)?;
    for (index, ch) in chars.iter().copied().enumerate() {
        write_u16_at(data, offset + 2 + index * 2, ch)?;
    }

    Ok(offset)
}

fn append_resource_payload(data: &mut Vec<u8>, payload: &[u8]) -> Result<usize, Error> {
    align_resource_data(data)?;
    let offset = data.len();
    data.extend_from_slice(payload);
    Ok(offset)
}

fn append_aligned_zeroes(data: &mut Vec<u8>, size: usize) -> Result<usize, Error> {
    align_resource_data(data)?;
    append_zeroes(data, size)
}

fn append_zeroes(data: &mut Vec<u8>, size: usize) -> Result<usize, Error> {
    let offset = data.len();
    let new_len = checked_add_usize(offset, size, "sizing rebuilt resource directory")?;

    data.resize(new_len, 0);
    Ok(offset)
}

fn align_resource_data(data: &mut Vec<u8>) -> Result<(), Error> {
    let padding = (4 - data.len() % 4) % 4;
    if padding == 0 {
        return Ok(());
    }

    let new_len = checked_add_usize(data.len(), padding, "aligning rebuilt resource directory")?;
    data.resize(new_len, 0);
    Ok(())
}

fn scan_resource_data_entries_at(
    data: &[u8],
    directory_offset: usize,
    resource_rva: u32,
    resource_end_rva: u32,
    path: &mut Vec<ResourcePathEntry>,
    state: &mut ResourceDataEntryScanState,
) -> Result<(), Error> {
    if !state.directories.insert(directory_offset) {
        return Err(Error::ResourceDirectoryLoop { offset: directory_offset });
    }

    checked_range(data, directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE)?;
    let named_entries = read_u16(data, directory_offset + 12)? as usize;
    let id_entries = read_u16(data, directory_offset + 14)? as usize;
    let entry_count = named_entries
        .checked_add(id_entries)
        .ok_or(Error::Overflow("counting resource directory entries"))?;
    let entries_offset = checked_add_usize(directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE, "locating resource directory entries")?;
    let entries_size = entry_count
        .checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
        .ok_or(Error::Overflow("sizing resource directory entries"))?;
    checked_range(data, entries_offset, entries_size)?;

    for entry_index in 0..entry_count {
        let entry_offset = entries_offset + entry_index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
        let offset_to_data = read_u32(data, entry_offset + 4)?;
        let target_offset = (offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_OFFSET_MASK) as usize;
        let path_entry = resource_path_entry_at(data, entry_offset)?;
        path.push(path_entry);

        if offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY != 0 {
            scan_resource_data_entries_at(data, target_offset, resource_rva, resource_end_rva, path, state)?;
        } else {
            state.entries.push(resource_data_entry_at(data, target_offset, resource_rva, resource_end_rva, path)?);
        }

        path.pop();
    }

    Ok(())
}

fn resource_path_entry_at(data: &[u8], entry_offset: usize) -> Result<ResourcePathEntry, Error> {
    let raw_name = read_u32(data, entry_offset)?;
    if raw_name & IMAGE_RESOURCE_DIRECTORY_ENTRY_NAME_IS_STRING == 0 {
        return Ok(ResourcePathEntry {
            name: None,
            id: Some(raw_name & 0xffff),
        });
    }

    let name_offset = (raw_name & IMAGE_RESOURCE_DIRECTORY_ENTRY_OFFSET_MASK) as usize;
    Ok(ResourcePathEntry {
        name: Some(resource_string_at(data, name_offset)?),
        id: None,
    })
}

fn resource_string_at(data: &[u8], offset: usize) -> Result<String, Error> {
    let len = read_u16(data, offset)? as usize;
    let chars_offset = checked_add_usize(offset, 2, "locating resource name string")?;
    let chars_size = len
        .checked_mul(2)
        .ok_or(Error::Overflow("sizing resource name string"))?;
    checked_range(data, chars_offset, chars_size)?;

    let mut chars = Vec::with_capacity(len);
    for index in 0..len {
        let char_offset = checked_add_usize(chars_offset, index * 2, "reading resource name string")?;
        chars.push(read_u16(data, char_offset)?);
    }

    Ok(String::from_utf16_lossy(&chars))
}

fn resource_data_entry_at(
    data: &[u8],
    data_entry_offset: usize,
    resource_rva: u32,
    resource_end_rva: u32,
    path: &[ResourcePathEntry],
) -> Result<ResourceDataEntry, Error> {
    checked_range(data, data_entry_offset, IMAGE_RESOURCE_DATA_ENTRY_SIZE)?;
    let data_rva = read_u32(data, data_entry_offset)?;
    let size = read_u32(data, data_entry_offset + 4)?;
    let data_end_rva = data_rva
        .checked_add(size)
        .ok_or(Error::Overflow("sizing resource data RVA range"))?;

    if data_rva < resource_rva || data_end_rva > resource_end_rva {
        return Err(Error::ResourceDataRvaOutOfRange {
            rva: data_rva,
            start: resource_rva,
            end: resource_end_rva,
        });
    }

    Ok(ResourceDataEntry {
        path: path.to_vec(),
        data_rva,
        size,
        code_page: read_u32(data, data_entry_offset + 8)?,
        reserved: read_u32(data, data_entry_offset + 12)?,
    })
}

fn scan_resource_directory_at(
    data: &[u8],
    directory_offset: usize,
    resource_rva: u32,
    resource_end_rva: u32,
    depth: usize,
    state: &mut ResourceScanState,
) -> Result<(), Error> {
    if !state.directories.insert(directory_offset) {
        return Err(Error::ResourceDirectoryLoop { offset: directory_offset });
    }

    checked_range(data, directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE)?;
    let named_entries = read_u16(data, directory_offset + 12)? as usize;
    let id_entries = read_u16(data, directory_offset + 14)? as usize;

    state.info.directory_count = state.info
        .directory_count
        .checked_add(1)
        .ok_or(Error::Overflow("counting resource directories"))?;
    state.info.named_entry_count = state.info
        .named_entry_count
        .checked_add(named_entries)
        .ok_or(Error::Overflow("counting named resource entries"))?;
    state.info.id_entry_count = state.info
        .id_entry_count
        .checked_add(id_entries)
        .ok_or(Error::Overflow("counting id resource entries"))?;
    state.info.max_depth = state.info.max_depth.max(depth);

    let entry_count = named_entries
        .checked_add(id_entries)
        .ok_or(Error::Overflow("counting resource directory entries"))?;
    let entries_offset = checked_add_usize(directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE, "locating resource directory entries")?;
    let entries_size = entry_count
        .checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
        .ok_or(Error::Overflow("sizing resource directory entries"))?;
    checked_range(data, entries_offset, entries_size)?;

    for entry_index in 0..entry_count {
        let entry_offset = entries_offset + entry_index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
        let offset_to_data = read_u32(data, entry_offset + 4)?;
        let target_offset = (offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_OFFSET_MASK) as usize;

        if offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY != 0 {
            scan_resource_directory_at(
                data,
                target_offset,
                resource_rva,
                resource_end_rva,
                depth.checked_add(1).ok_or(Error::Overflow("counting resource directory depth"))?,
                state,
            )?;
        } else {
            scan_resource_data_entry_at(data, target_offset, resource_rva, resource_end_rva, state)?;
        }
    }

    Ok(())
}

fn scan_resource_data_entry_at(
    data: &[u8],
    data_entry_offset: usize,
    resource_rva: u32,
    resource_end_rva: u32,
    state: &mut ResourceScanState,
) -> Result<(), Error> {
    if !state.data_entries.insert(data_entry_offset) {
        return Ok(());
    }

    checked_range(data, data_entry_offset, IMAGE_RESOURCE_DATA_ENTRY_SIZE)?;
    let data_rva = read_u32(data, data_entry_offset)?;
    let data_size = read_u32(data, data_entry_offset + 4)?;
    let data_end_rva = data_rva
        .checked_add(data_size)
        .ok_or(Error::Overflow("sizing resource data RVA range"))?;

    if data_rva < resource_rva || data_end_rva > resource_end_rva {
        return Err(Error::ResourceDataRvaOutOfRange {
            rva: data_rva,
            start: resource_rva,
            end: resource_end_rva,
        });
    }

    state.info.data_entry_count = state.info
        .data_entry_count
        .checked_add(1)
        .ok_or(Error::Overflow("counting resource data entries"))?;
    state.info.data_size = state.info
        .data_size
        .checked_add(data_size as u64)
        .ok_or(Error::Overflow("counting resource data bytes"))?;
    Ok(())
}

fn rebase_resource_directory_at(
    data: &mut [u8],
    directory_offset: usize,
    old_resource_rva: u32,
    old_resource_end_rva: u32,
    new_resource_rva: u32,
    state: &mut ResourceRebaseState,
) -> Result<(), Error> {
    if !state.directories.insert(directory_offset) {
        return Err(Error::ResourceDirectoryLoop { offset: directory_offset });
    }

    checked_range(data, directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE)?;
    let named_entries = read_u16(data, directory_offset + 12)? as usize;
    let id_entries = read_u16(data, directory_offset + 14)? as usize;
    let entry_count = named_entries
        .checked_add(id_entries)
        .ok_or(Error::Overflow("counting resource directory entries"))?;
    let entries_offset = checked_add_usize(directory_offset, IMAGE_RESOURCE_DIRECTORY_SIZE, "locating resource directory entries")?;
    let entries_size = entry_count
        .checked_mul(IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE)
        .ok_or(Error::Overflow("sizing resource directory entries"))?;
    checked_range(data, entries_offset, entries_size)?;

    for entry_index in 0..entry_count {
        let entry_offset = entries_offset + entry_index * IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE;
        let offset_to_data = read_u32(data, entry_offset + 4)?;
        let target_offset = (offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_OFFSET_MASK) as usize;

        if offset_to_data & IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY != 0 {
            rebase_resource_directory_at(
                data,
                target_offset,
                old_resource_rva,
                old_resource_end_rva,
                new_resource_rva,
                state,
            )?;
        } else {
            rebase_resource_data_entry_at(
                data,
                target_offset,
                old_resource_rva,
                old_resource_end_rva,
                new_resource_rva,
                state,
            )?;
        }
    }

    Ok(())
}

fn rebase_resource_data_entry_at(
    data: &mut [u8],
    data_entry_offset: usize,
    old_resource_rva: u32,
    old_resource_end_rva: u32,
    new_resource_rva: u32,
    state: &mut ResourceRebaseState,
) -> Result<(), Error> {
    if !state.data_entries.insert(data_entry_offset) {
        return Ok(());
    }

    checked_range(data, data_entry_offset, IMAGE_RESOURCE_DATA_ENTRY_SIZE)?;
    let old_data_rva = read_u32(data, data_entry_offset)?;
    let data_size = read_u32(data, data_entry_offset + 4)?;
    let old_data_end_rva = old_data_rva
        .checked_add(data_size)
        .ok_or(Error::Overflow("sizing resource data RVA range"))?;

    if old_data_rva < old_resource_rva || old_data_end_rva > old_resource_end_rva {
        return Err(Error::ResourceDataRvaOutOfRange {
            rva: old_data_rva,
            start: old_resource_rva,
            end: old_resource_end_rva,
        });
    }

    let new_data_rva = new_resource_rva
        .checked_add(old_data_rva - old_resource_rva)
        .ok_or(Error::Overflow("rebasing resource data RVA"))?;
    write_u32_at(data, data_entry_offset, new_data_rva)
}
