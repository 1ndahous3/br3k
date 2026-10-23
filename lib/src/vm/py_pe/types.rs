use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

pub use crate::pe::recovery::imports::ImportRecoveryStrength;

/// Export-source selection policy for a process analysis view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ExportResolverSource {
    /// Try disk exports first, falling back to mapped exports on acquisition or parsing failure.
    Auto,
    /// Require file-backed exports; record failures without using mapped fallback.
    Disk,
    /// Require exports parsed from captured target memory.
    Mapped,
}

/// Evidence contributing to a hidden-module candidate's ranking. No single reason proves malicious code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum HiddenModuleReasonKind {
    /// Candidate allocation is outside the loader's module inventory.
    OutsidePebModuleList,
    /// Image-backed memory is not associated with a listed loader module.
    DetachedImageRegion,
    /// Allocation contains private executable memory.
    PrivateExecutableRegion,
    /// Allocation contains executable mapped-section memory.
    MappedExecutableRegion,
    /// Memory protection permits both writing and execution.
    WritableExecutableProtection,
    /// Allocation combines executable and non-executable regions.
    MixedExecutableAndNonExecutableRegions,
    /// Range was explicitly selected by the caller.
    ManualSelection,
    /// PE-shaped header or section-table evidence was found.
    HeaderArtifact,
}

/// Classification of a process-memory scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum FindingKind {
    /// Allocation retained as a ranked hidden-module candidate.
    HiddenModuleCandidate,
    /// Executable memory outside known module ownership.
    OrphanExecutableRegion,
    /// Private memory with executable protection.
    PrivateExecutableRegion,
    /// Mapped-section memory with executable protection.
    MappedExecutableRegion,
    /// Image-backed memory absent from the loader module inventory.
    DetachedImageRegion,
    /// Memory permits both writing and execution.
    WritableExecutableRegion,
}

/// Classification of the memory containing a thread's recorded start address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ThreadStartKind {
    /// Address belongs to a listed loaded module.
    LoadedModule,
    /// Address belongs to private executable memory.
    PrivateExecutableRegion,
    /// Address belongs to executable mapped-section memory.
    MappedExecutableRegion,
    /// Address belongs to image-backed memory outside listed modules.
    DetachedImageRegion,
    /// Address belongs to other executable memory without module ownership.
    OrphanExecutableRegion,
    /// Address belongs to a region without executable protection.
    NonExecutableRegion,
    /// No region in the captured map contains the address.
    Unmapped,
    /// Start address or classification evidence is unavailable.
    Unknown,
}

/// Protection classification of a memory region intersecting a thread's stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ThreadStackRegionKind {
    /// Stack-intersecting memory without executable protection.
    StackRegion,
    /// Stack-intersecting memory permits execution.
    ExecutableStackRegion,
    /// Stack-intersecting memory permits both writing and execution.
    WritableExecutableStackRegion,
}
