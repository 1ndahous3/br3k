use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ApiSetError {
    #[error("API set namespace is too small")]
    NamespaceTooSmall,
    #[error("API set namespace size {0} is too large")]
    NamespaceTooLarge(u32),
    #[error("API set namespace range is outside the buffer")]
    RangeOutOfBounds,
    #[error("API set namespace string has an odd byte length")]
    InvalidStringLength,
    #[error("API set namespace string is not valid UTF-16")]
    InvalidString,
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiSetMap {
    entries: Vec<ApiSetEntry>,
    hosts_by_contract: BTreeMap<String, String>,
}

impl ApiSetMap {
    pub fn parse(data: &[u8]) -> Result<Self, ApiSetError> {
        let header = ApiSetNamespaceHeader::parse(data)?;
        if header.size > MAX_API_SET_NAMESPACE_SIZE as u32 {
            return Err(ApiSetError::NamespaceTooLarge(header.size));
        }

        let namespace_size = header.size as usize;
        if namespace_size > data.len() {
            return Err(ApiSetError::RangeOutOfBounds);
        }

        let data = &data[..namespace_size];
        let mut entries = Vec::new();
        let mut hosts_by_contract = BTreeMap::new();

        for index in 0..header.count {
            let entry_offset = table_offset(
                header.entry_offset,
                index,
                API_SET_NAMESPACE_ENTRY_SIZE,
                "reading API set namespace entries",
            )?;
            let entry = ApiSetNamespaceEntry::parse_at(data, entry_offset)?;
            let contract = read_utf16(data, entry.name_offset, entry.name_length)?;
            let hosts = read_value_hosts(data, entry.value_offset, entry.value_count)?;

            if let Some(default_host) = hosts.first() {
                hosts_by_contract.insert(api_set_key(&contract), default_host.clone());
            }

            entries.push(ApiSetEntry {
                contract,
                hosts,
            });
        }

        Ok(Self {
            entries,
            hosts_by_contract,
        })
    }

    pub fn entries(&self) -> &[ApiSetEntry] {
        &self.entries
    }

    pub fn resolve_contract(&self, contract_name: &str) -> Option<&str> {
        self.hosts_by_contract
            .get(&api_set_key(contract_name))
            .map(String::as_str)
    }

    pub fn resolve_module_name<'a>(&'a self, module_name: &'a str) -> &'a str {
        self.resolve_contract(module_name)
            .unwrap_or(module_name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiSetEntry {
    pub contract: String,
    pub hosts: Vec<String>,
}

pub fn namespace_size(data: &[u8]) -> Result<u32, ApiSetError> {
    Ok(ApiSetNamespaceHeader::parse(data)?.size)
}

fn read_value_hosts(
    data: &[u8],
    value_offset: u32,
    value_count: u32,
) -> Result<Vec<String>, ApiSetError> {
    let mut hosts = Vec::<String>::new();

    for index in 0..value_count {
        let entry_offset = table_offset(
            value_offset,
            index,
            API_SET_VALUE_ENTRY_SIZE,
            "reading API set value entries",
        )?;
        let entry = ApiSetValueEntry::parse_at(data, entry_offset)?;
        if entry.value_length == 0 {
            continue;
        }

        let host = read_utf16(data, entry.value_offset, entry.value_length)?;
        if !host.is_empty() && !hosts.iter().any(|known| known.eq_ignore_ascii_case(&host)) {
            hosts.push(host);
        }
    }

    Ok(hosts)
}

fn read_utf16(
    data: &[u8],
    offset: u32,
    size: u32,
) -> Result<String, ApiSetError> {
    if size == 0 {
        return Ok(String::new());
    }
    if size % 2 != 0 {
        return Err(ApiSetError::InvalidStringLength);
    }

    let bytes = range(data, offset as usize, size as usize)?;
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();

    String::from_utf16(&utf16)
        .map_err(|_| ApiSetError::InvalidString)
}

fn api_set_key(name: &str) -> String {
    let mut key = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();

    if let Some(stripped) = key.strip_suffix(".dll") {
        key = stripped.to_string();
    }

    key
}

fn table_offset(
    base: u32,
    index: u32,
    stride: usize,
    operation: &'static str,
) -> Result<usize, ApiSetError> {
    let index = usize::try_from(index)
        .map_err(|_| ApiSetError::Overflow(operation))?;
    let base = usize::try_from(base)
        .map_err(|_| ApiSetError::Overflow(operation))?;
    let delta = index
        .checked_mul(stride)
        .ok_or(ApiSetError::Overflow(operation))?;

    base.checked_add(delta)
        .ok_or(ApiSetError::Overflow(operation))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ApiSetError> {
    let bytes = range(data, offset, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn range(data: &[u8], offset: usize, size: usize) -> Result<&[u8], ApiSetError> {
    let end = offset
        .checked_add(size)
        .ok_or(ApiSetError::Overflow("sizing API set namespace range"))?;

    data.get(offset..end)
        .ok_or(ApiSetError::RangeOutOfBounds)
}

#[derive(Clone, Copy, Debug)]
struct ApiSetNamespaceHeader {
    size: u32,
    count: u32,
    entry_offset: u32,
}

impl ApiSetNamespaceHeader {
    fn parse(data: &[u8]) -> Result<Self, ApiSetError> {
        if data.len() < API_SET_NAMESPACE_HEADER_SIZE {
            return Err(ApiSetError::NamespaceTooSmall);
        }

        Ok(Self {
            size: read_u32(data, 4)?,
            count: read_u32(data, 12)?,
            entry_offset: read_u32(data, 16)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ApiSetNamespaceEntry {
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_count: u32,
}

impl ApiSetNamespaceEntry {
    fn parse_at(data: &[u8], offset: usize) -> Result<Self, ApiSetError> {
        let _ = range(data, offset, API_SET_NAMESPACE_ENTRY_SIZE)?;

        Ok(Self {
            name_offset: read_u32(data, offset + 4)?,
            name_length: read_u32(data, offset + 8)?,
            value_offset: read_u32(data, offset + 16)?,
            value_count: read_u32(data, offset + 20)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ApiSetValueEntry {
    value_offset: u32,
    value_length: u32,
}

impl ApiSetValueEntry {
    fn parse_at(data: &[u8], offset: usize) -> Result<Self, ApiSetError> {
        let _ = range(data, offset, API_SET_VALUE_ENTRY_SIZE)?;

        Ok(Self {
            value_offset: read_u32(data, offset + 12)?,
            value_length: read_u32(data, offset + 16)?,
        })
    }
}

pub const API_SET_NAMESPACE_HEADER_SIZE: usize = 28;
const API_SET_NAMESPACE_ENTRY_SIZE: usize = 24;
const API_SET_VALUE_ENTRY_SIZE: usize = 20;
pub const MAX_API_SET_NAMESPACE_SIZE: usize = 0x10_0000;

#[cfg(test)]
#[path = "tests/api_set.rs"]
mod tests;
