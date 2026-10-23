use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Operation stage responsible for an analysis or build diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum Stage {
    /// Process-memory acquisition.
    Capture,
    /// Reference-image or symbol-source acquisition.
    Reference,
    /// Layout or relocation normalization.
    Normalization,
    /// Comparison between captured and reference data.
    Comparison,
    /// Import analysis or reconstruction.
    Imports,
    /// Static code-reference analysis.
    Code,
    /// Header inspection or recovery.
    Headers,
    /// Local output-image construction or validation.
    Build,
}

/// Severity of an operation diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum Severity {
    /// Informational observation.
    Information,
    /// Limitation or recoverable problem affecting interpretation.
    Warning,
    /// Failure or blocking correctness problem.
    Error,
}

/// An incomplete or failed stage is evidence, not an empty successful result.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub stage: Stage,
    pub severity: Severity,
    pub message: String,
    pub rva: Option<u32>,
}

impl Diagnostic {
    pub fn warning(stage: Stage, message: impl Into<String>) -> Self {
        Self { stage, severity: Severity::Warning, message: message.into(), rva: None }
    }
}
