mod anomalies;
mod compare;
pub mod comparison;
pub mod resources;
mod error;
mod hashes;
mod iat_hooks;
mod metadata;

pub(crate) use metadata::load_config_info;
pub use metadata::inspect_image;

#[cfg(test)]
#[path = "tests/diagnostics.rs"]
mod tests;

pub use anomalies::{
    image_anomalies, ImageAnomaly, ImageAnomalyKind, ImageAnomalySeverity,
};
pub use compare::{
    compare_mapped_to_disk, section_byte_changes, ByteChangeOptions, ImageByteChanges,
    ImageComparison, SectionByteChange, SectionComparison, CompareOptions,
};
pub use error::DiagnosticsError;
pub use hashes::{
    export_prologue_hashes, fnv1a64, normalized_header_hash, ExportPrologueHash,
};
pub use iat_hooks::{
    import_address_changes, ImportAddressChange, ImportComparison,
};
pub use metadata::{
    metadata_summary, DataDirectoryInfo, DotNetDirectoryInfo, LoadConfigCodeIntegrityInfo,
    LoadConfigInfo, MetadataSummary, PackerHint, RichHeaderInfo, SecurityDirectoryInfo,
    TlsDirectoryInfo,
};
