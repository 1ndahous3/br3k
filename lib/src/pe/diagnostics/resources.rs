use crate::pe::image::{Image, Error, ResourceDataEntry, ResourcePathEntry};
use std::collections::{BTreeMap, BTreeSet};
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Difference for one typed resource-tree path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ResourceChangeKind {
    /// Leaf is present in the capture but absent from the reference.
    Added,
    /// Leaf is present in the reference but absent from the capture.
    Removed,
    /// Leaf exists in both inputs with differing metadata or payload.
    Changed,
}

#[derive(Clone, Debug)]
pub struct ResourceChange {
    pub kind: ResourceChangeKind,
    pub path: Vec<ResourcePathEntry>,
    pub before: Option<ResourceDataEntry>,
    pub after: Option<ResourceDataEntry>,
    pub before_hash: Option<u64>,
    pub after_hash: Option<u64>,
}

fn entries(image: &Image) -> Result<BTreeMap<Vec<ResourcePathEntry>, ResourceDataEntry>, Error> {
    let entries = match image.resources() {
        Ok(entries) => entries,
        Err(Error::DataDirectoryEmpty { .. } | Error::DataDirectoryMissing { .. }) => Vec::new(),
        Err(error) => return Err(error),
    };
    let mut result = BTreeMap::new();
    for entry in entries {
        if result.insert(entry.path.clone(), entry).is_some() { return Err(Error::TooSmall("ambiguous duplicate resource path")); }
    }
    Ok(result)
}

/// Compare typed resource identities and payloads, not just size/code-page metadata.
pub fn compare(captured: &Image, reference: &Image) -> Result<Vec<ResourceChange>, Error> {
    let before = entries(reference)?;
    let after = entries(captured)?;
    let paths = before.keys().chain(after.keys()).cloned().collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for path in paths {
        let old = before.get(&path);
        let new = after.get(&path);
        let old_data = old.map(|entry| reference.read_rva(entry.data_rva, entry.size as usize)).transpose()?;
        let new_data = new.map(|entry| captured.read_rva(entry.data_rva, entry.size as usize)).transpose()?;
        if old_data == new_data && old.map(|entry| (entry.code_page, entry.reserved)) == new.map(|entry| (entry.code_page, entry.reserved)) { continue; }
        changes.push(ResourceChange {
            kind: if old.is_none() { ResourceChangeKind::Added } else if new.is_none() { ResourceChangeKind::Removed } else { ResourceChangeKind::Changed },
            path, before: old.cloned(), after: new.cloned(),
            before_hash: old_data.map(super::fnv1a64), after_hash: new_data.map(super::fnv1a64),
        });
    }
    Ok(changes)
}
