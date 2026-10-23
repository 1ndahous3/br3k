use super::image::Image;
use std::collections::BTreeMap;

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("native file acquisition failed: {0}")]
    Read(#[from] crate::sysapi::NtStatusError),
    #[error("source exceeds the 128 MiB analysis limit")]
    TooLarge,
    #[error("source file was not read completely")]
    ShortRead,
    #[error(transparent)]
    Image(#[from] super::image::Error),
}

/// Per-view reference snapshots, including failed reads. Refresh drops this entire cache.
#[derive(Debug, Default)]
pub struct References { files: BTreeMap<String, Result<Image, Error>> }

impl References {
    pub fn load(&mut self, path: &str) -> Result<Image, Error> {
        self.files.entry(path.to_string()).or_insert_with(|| read_image(path)).clone()
    }
    pub fn clear(&mut self) { self.files.clear(); }
}

pub fn read_image(path: &str) -> Result<Image, Error> {
    let handle = crate::sysapi::open_file(path)?;
    let size = crate::sysapi::get_file_size(*handle)?;
    if size > 128 * 1024 * 1024 { return Err(Error::TooLarge); }
    let mut data = vec![0; size];
    if !crate::sysapi::read_file(*handle, data.as_mut_ptr().cast(), size)? {
        return Err(Error::ShortRead);
    }
    Ok(Image::parse(data)?)
}
