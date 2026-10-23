use crate::pe::format::IMAGE_SCN_MEM_EXECUTE;
use crate::pe::image::{Error, Image};

#[derive(Debug, thiserror::Error)]
pub(super) enum ValidationError {
    #[error(transparent)]
    Image(#[from] Error),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Parser(String),
}

pub(super) struct Reader<'a> {
    pub image: &'a Image,
}

impl<'a> Reader<'a> {
    pub fn bytes(&self, rva: u32, size: usize) -> Result<&'a [u8], ValidationError> {
        let end = (rva as usize).checked_add(size).ok_or(ValidationError::Invalid("Directory range overflow"))?;
        if rva < self.image.size_of_headers() || end as u64 > self.image.image_size()? as u64 {
            return Err(ValidationError::Invalid("Referenced data overlaps rebuilt headers or exceeds SizeOfImage"));
        }
        self.image.data().get(rva as usize..end).ok_or(ValidationError::Invalid("Referenced data is outside captured bytes"))
    }

    pub fn u32(&self, rva: u32) -> Result<u32, ValidationError> {
        Ok(u32::from_le_bytes(self.bytes(rva, 4)?.try_into().unwrap()))
    }

    pub fn va(&self, address: u64) -> Result<u32, ValidationError> {
        address.checked_sub(self.image.image_base()?).and_then(|rva| u32::try_from(rva).ok())
            .ok_or(ValidationError::Invalid("Referenced VA is outside this image"))
    }

    pub fn code(&self, rva: u32, size: u32) -> Result<(), ValidationError> {
        self.bytes(rva, size as usize)?;
        if size == 0 || !self.image.sections()?.iter().any(|section| {
            section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 && rva >= section.virtual_address
                && rva as u64 + size as u64 <= section.virtual_address as u64 + section.virtual_size.max(section.raw_size) as u64
        }) {
            return Err(ValidationError::Invalid("Function range is not captured executable code"));
        }
        Ok(())
    }

    pub fn directory(&self, index: usize) -> Result<&'a [u8], ValidationError> {
        let directory = self.image.data_directory(index)?;
        self.bytes(directory.virtual_address, directory.size as usize)
    }
}

pub(super) fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
