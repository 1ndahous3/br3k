use crate::pe::image::Error as ImageError;
use crate::pe::imports::ImportError;

#[derive(Clone, Debug, thiserror::Error)]
pub enum DiagnosticsError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error(transparent)]
    Import(#[from] ImportError),
    #[error("mapped PE pointer size {mapped} differs from disk PE pointer size {disk}")]
    PointerSizeMismatch { mapped: usize, disk: usize },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}
