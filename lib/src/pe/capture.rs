use super::image::{Error, Image, MissingRange};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ReadFailure {
    pub range: MissingRange,
    pub message: String,
}

/// Raw acquisition, including holes. Parsing is explicit and does not erase coverage.
#[derive(Clone, Debug)]
pub struct Capture {
    pub base: u64,
    pub name: String,
    pub path: Option<String>,
    pub generation: u64,
    pub data: Arc<Vec<u8>>,
    pub failures: Vec<ReadFailure>,
    pub regions: Vec<crate::sysapi::MemoryRegion>,
}

impl Capture {
    pub fn read(
        base: u64, size: u32, name: String, path: Option<String>, generation: u64,
        mut reader: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
    ) -> Result<Self, Error> {
        base.checked_add(size as u64).ok_or(Error::Overflow("sizing capture address range"))?;
        let mut data = Vec::new();
        data.try_reserve_exact(size as usize).map_err(|_| Error::TooSmall("capture allocation"))?;
        data.resize(size as usize, 0);
        let mut failures = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let address = base + offset as u64;
            let size = (4096 - (address as usize & 4095)).min(data.len() - offset);
            match reader(address, size) {
                Ok(bytes) if bytes.len() == size => data[offset..offset + size].copy_from_slice(&bytes),
                result => failures.push(ReadFailure {
                    range: MissingRange { rva: offset as u32, size: size as u32 },
                    message: result.err().unwrap_or_else(|| "short memory read".to_string()),
                }),
            }
            offset += size;
        }
        Ok(Self { base, name, path, generation, data: Arc::new(data), failures, regions: Vec::new() })
    }

    pub fn complete(&self) -> bool { self.failures.is_empty() }

    pub fn image(&self) -> Result<Image, Error> {
        Image::from_mapped_shared(self.data.clone(), self.base, self.failures.iter().map(|failure| failure.range.clone()).collect())
    }
}
