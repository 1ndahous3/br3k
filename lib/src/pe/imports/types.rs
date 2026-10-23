use super::*;

use crate::pe::api_set::ApiSetMap;

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

#[derive(Clone, Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("module '{0}' was not registered in the import model")]
    ModuleNotFound(String),
    #[error("module '{0}' already contains a thunk at RVA 0x{1:x}")]
    DuplicateThunk(String, u32),
    #[error("import function RVA 0x{0:x} was not found")]
    FunctionNotFound(u32),
    #[error("import module containing thunk RVA 0x{0:x} was not found")]
    ModuleThunkNotFound(u32),
    #[error("import module '{0}' already exists")]
    ModuleNameCollision(String),
    #[error("import name contains an interior NUL byte: {0}")]
    NameContainsNul(String),
    #[error("import function must be specified by name or ordinal")]
    MissingFunctionTarget,
    #[error("unresolved import target 0x{0:x} cannot be written into a valid import table")]
    UnresolvedImportTarget(u64),
    #[error("import model does not contain any valid imports")]
    EmptyImportModel,
    #[error("IAT data size {size} is not aligned to pointer size {pointer_size}")]
    InvalidIatSize { size: usize, pointer_size: usize },
    #[error("minimum IAT range entry count must be greater than zero")]
    InvalidMinIatEntries,
    #[error("import descriptor table has no null terminator within {limit} descriptors")]
    ImportDescriptorTableTooLong { limit: usize },
    #[error("import descriptor {descriptor_index} has no null thunk terminator within {limit} entries")]
    ImportThunkTableTooLong {
        descriptor_index: usize,
        limit: usize,
    },
    #[error("unterminated import string at RVA 0x{rva:x}")]
    UnterminatedString { rva: u32 },
    #[error("unsupported IAT pointer size: {0}")]
    InvalidPointerSize(usize),
    #[error("unsupported PE machine type 0x{0:x}")]
    UnsupportedMachine(u16),
    #[error("cannot preserve overlapping IAT slots for module '{module_name}'")]
    InvalidPreservedIatLayout { module_name: String },
    #[error("code reference patch at RVA 0x{reference_rva:x} cannot reach stub RVA 0x{stub_rva:x}")]
    CodeReferencePatchOutOfRange { reference_rva: u32, stub_rva: u32 },
    #[error("ARM64 code reference patch at RVA 0x{reference_rva:x} is not 4-byte aligned with stub RVA 0x{stub_rva:x}")]
    CodeReferencePatchMisaligned { reference_rva: u32, stub_rva: u32 },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

/// Placement policy for rebuilt imports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportWriteMode {
    /// Retain existing IAT slot RVAs; allocate new slots only for additional direct-branch imports.
    PreserveIatSlots,
    /// Allocate a new IAT and patch direct branches only. Other references must be updated by the caller.
    NewIat,
}

/// Policy for matching an observed address to an export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportAddressResolveMode {
    /// Require an exact export-address match.
    #[default]
    Exact,
    /// Allow a preceding nearby export match. This is heuristic evidence, not proof of a function boundary.
    Nearest,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportAddressResolveOptions {
    pub mode: ImportAddressResolveMode,
    pub resolve_forwarders: bool,
    pub api_set_map: Option<ApiSetMap>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoverIatOptions {
    pub address_resolve_options: ImportAddressResolveOptions,
    pub keep_unresolved: bool,
}

/// Origin of evidence supporting a recovered import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportEvidenceKind {
    /// Slot came from the declared IAT directory.
    IatDirectory,
    /// Slot came from an explicitly selected or scanned IAT range.
    IatRange,
    /// A recognized code pattern refers to an IAT slot.
    CodeReference,
    /// A recognized direct API branch supplied import evidence.
    DirectBranch,
    /// Following supported thunk patterns led to an export.
    ThunkTrace,
    /// Caller explicitly supplied this import slot.
    ManualSlot,
    /// Surviving import declaration supplied the name or ordinal.
    ImportDeclaration,
    /// Neighboring import-module context helped select the target.
    ImportModuleContext,
}

impl ImportEvidenceKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// How an observed target was associated with an import.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportResolutionKind {
    /// Observed address matched an export exactly.
    Exact,
    /// Observed address was associated with a nearby preceding export.
    Nearest,
    /// Export forwarding was used to identify the target.
    Forwarded,
    /// API-set contract resolution was used to identify the target.
    ApiSet,
    /// No usable export identity was established.
    Unresolved,
}

impl ImportResolutionKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportEvidence {
    pub kind: ImportEvidenceKind,
    pub resolution: ImportResolutionKind,
    pub confidence: u8,
    pub source_rva: u32,
    pub target_address: Option<u64>,
    pub reference_rva: Option<u32>,
    pub iat_rva: Option<u32>,
}

impl ImportEvidence {
    pub fn manual_slot(rva: u32, target: &ImportTarget, valid: bool) -> Self {
        let (resolution, confidence, target_address) = match target {
            ImportTarget::Unknown(address) => (ImportResolutionKind::Unresolved, 20, Some(*address)),
            _ if valid => (ImportResolutionKind::Exact, 100, None),
            _ => (ImportResolutionKind::Exact, 40, None),
        };

        Self {
            kind: ImportEvidenceKind::ManualSlot,
            resolution,
            confidence,
            source_rva: rva,
            target_address,
            reference_rva: None,
            iat_rva: Some(rva),
        }
    }

    pub fn slot(
        kind: ImportEvidenceKind,
        resolution: ImportResolutionKind,
        rva: u32,
        target_address: Option<u64>,
    ) -> Self {
        Self {
            kind,
            resolution,
            confidence: Self::confidence(kind, resolution),
            source_rva: rva,
            target_address,
            reference_rva: None,
            iat_rva: Some(rva),
        }
    }

    pub fn code_reference(
        reference: &ImportCodeReference,
        kind: ImportEvidenceKind,
        iat_rva: Option<u32>,
    ) -> Self {
        Self {
            kind,
            resolution: ImportResolutionKind::Exact,
            confidence: Self::confidence(kind, ImportResolutionKind::Exact),
            source_rva: reference.reference_rva,
            target_address: Some(reference.target_address),
            reference_rva: Some(reference.reference_rva),
            iat_rva,
        }
    }

    pub fn confidence(
        kind: ImportEvidenceKind,
        resolution: ImportResolutionKind,
    ) -> u8 {
        match resolution {
            ImportResolutionKind::Exact => match kind {
                ImportEvidenceKind::ManualSlot => 100,
                ImportEvidenceKind::ImportDeclaration => 100,
                ImportEvidenceKind::ImportModuleContext => 95,
                ImportEvidenceKind::IatDirectory => 95,
                ImportEvidenceKind::IatRange => 85,
                ImportEvidenceKind::DirectBranch => 90,
                ImportEvidenceKind::CodeReference => 80,
                ImportEvidenceKind::ThunkTrace => 75,
            },
            ImportResolutionKind::Forwarded => 90,
            ImportResolutionKind::ApiSet => 85,
            ImportResolutionKind::Nearest => 70,
            ImportResolutionKind::Unresolved => 20,
        }
    }
}

/// Recognized instruction-pattern family for an API reference. Recognition depends on the image architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportCodeReferenceKind {
    /// Direct relative call to an API target.
    DirectCall,
    /// Direct relative jump to an API target.
    DirectJump,
    /// Call through a target materialized from an immediate value.
    ImmediateCall,
    /// Jump through a target materialized from an immediate value.
    ImmediateJump,
    /// Indirect call through a pointer slot.
    IndirectCall,
    /// Indirect jump through a pointer slot.
    IndirectJump,
}

impl ImportCodeReferenceKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn is_patchable_direct_branch(self) -> bool {
        matches!(self, Self::DirectCall | Self::DirectJump)
    }
}

#[derive(Clone, Debug)]
pub struct RebuildImportsOptions {
    pub section_name: String,
    pub write_mode: ImportWriteMode,
    pub import_by_ordinal: bool,
    pub clear_bound_imports: bool,
    pub clear_delay_imports: bool,
    pub code_references: Vec<ImportCodeReference>,
    pub code_stub_section_name: String,
}

impl Default for RebuildImportsOptions {
    fn default() -> Self {
        Self {
            section_name: ".idata".to_string(),
            write_mode: ImportWriteMode::PreserveIatSlots,
            import_by_ordinal: false,
            clear_bound_imports: true,
            clear_delay_imports: false,
            code_references: Vec::new(),
            code_stub_section_name: ".br3kstb".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuildImportsReport {
    pub image: Vec<u8>,
    pub import_section_rva: u32,
    pub import_section_size: u32,
    pub iat_rva: u32,
    pub iat_size: u32,
    pub code_stub_section_rva: Option<u32>,
    pub code_stub_section_size: u32,
    pub direct_imports_added: usize,
    pub patchable_code_references: usize,
    pub patched_code_references: usize,
}

#[derive(Clone, Debug)]
pub enum ImportTarget {
    Name {
        hint: u16,
        ordinal: Option<u16>,
        name: String,
    },
    Ordinal(u16),
    Unknown(u64),
}

#[derive(Clone, Debug)]
pub struct ImportThunk {
    pub rva: u32,
    pub target: ImportTarget,
    pub valid: bool,
    pub evidence: Vec<ImportEvidence>,
}

#[derive(Clone, Debug)]
pub struct ImportEntry {
    pub module_name: String,
    pub rva: u32,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub hint: Option<u16>,
    pub valid: bool,
    pub address: Option<u64>,
    pub confidence: u8,
    pub evidence: Vec<ImportEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportModuleEntry {
    pub module_name: String,
    pub first_thunk: u32,
    pub nb_thunks: u32,
    pub function_count: usize,
    pub valid_function_count: usize,
}

/// Structural or heuristic issue found in an editable import model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportIssueKind {
    /// Function is marked invalid or retains an unresolved target.
    InvalidFunction,
    /// Adjacent slots are assigned to different modules.
    AdjacentDifferentModule,
    /// Multiple modules claim the same IAT slot RVA.
    DuplicateThunkRvaAcrossModules,
    /// A module contains repeated references to the same import target.
    DuplicateImportTargetInModule,
    /// Module declares an empty IAT range.
    EmptyModuleRange,
    /// Function lies next to an unpopulated part of a module's IAT range.
    FunctionAdjacentToRangeGap,
    /// No export table is available to validate the import module.
    ImportModuleMissingExportTable,
    /// Declared import target could not be found in the available export table.
    ImportTargetMissingFromExports,
    /// Module has no functions marked valid.
    ModuleWithoutValidFunctions,
    /// Ordinal import resolves to an export that also has a name.
    OrdinalOnlyImportHasNamedExport,
    /// Declared IAT spans of different modules overlap.
    OverlappingModuleRange,
    /// Consecutive slots repeat the same target.
    RepeatedImportTargetRun,
    /// Declared module span has gaps between populated slots.
    SparseModuleRange,
    /// Only one valid function supports a module range.
    SingletonValidFunction,
    /// IAT slot is misaligned for the model's target pointer width.
    ThunkMisalignedInModuleRange,
    /// Function's slot RVA lies outside its module's declared span.
    ThunkOutsideModuleRange,
}

impl ImportIssueKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    pub fn severity(self) -> ImportIssueSeverity {
        match self {
            Self::InvalidFunction => ImportIssueSeverity::Error,
            Self::AdjacentDifferentModule => ImportIssueSeverity::Warning,
            Self::DuplicateThunkRvaAcrossModules => ImportIssueSeverity::Error,
            Self::DuplicateImportTargetInModule => ImportIssueSeverity::Suspect,
            Self::EmptyModuleRange => ImportIssueSeverity::Error,
            Self::FunctionAdjacentToRangeGap => ImportIssueSeverity::Suspect,
            Self::ImportModuleMissingExportTable => ImportIssueSeverity::Warning,
            Self::ImportTargetMissingFromExports => ImportIssueSeverity::Error,
            Self::ModuleWithoutValidFunctions => ImportIssueSeverity::Error,
            Self::OrdinalOnlyImportHasNamedExport => ImportIssueSeverity::Suspect,
            Self::OverlappingModuleRange => ImportIssueSeverity::Warning,
            Self::RepeatedImportTargetRun => ImportIssueSeverity::Suspect,
            Self::SparseModuleRange => ImportIssueSeverity::Warning,
            Self::SingletonValidFunction => ImportIssueSeverity::Suspect,
            Self::ThunkMisalignedInModuleRange => ImportIssueSeverity::Error,
            Self::ThunkOutsideModuleRange => ImportIssueSeverity::Error,
        }
    }
}

/// Impact of an import-model finding. Heuristic findings do not prove malicious or incorrect code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImportIssueSeverity {
    /// Structural or unresolved-target problem requiring attention before a complete build.
    Error,
    /// Inconsistency that should be reviewed.
    Warning,
    /// Heuristic pattern that may warrant closer inspection.
    Suspect,
}

impl ImportIssueSeverity {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportIssue {
    pub kind: ImportIssueKind,
    pub severity: ImportIssueSeverity,
    pub rva: u32,
    pub module_name: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
    pub address: Option<u64>,
    pub next_rva: Option<u32>,
    pub next_module_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportAddressTableRange {
    pub rva: u32,
    pub size: u32,
    pub entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportAddressTableRangeScore {
    pub range: ImportAddressTableRange,
    pub score: u32,
    pub anchor_count: usize,
    pub nearest_anchor_distance: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportAddressSlot {
    pub rva: u32,
    pub address: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCodeReference {
    pub reference_rva: u32,
    pub kind: ImportCodeReferenceKind,
    pub target_address: u64,
    pub export_address: u64,
    pub iat_rva: Option<u32>,
    pub module_name: String,
    pub name: Option<String>,
    pub ordinal: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportCodeTraceOptions {
    pub start_rva: u32,
    pub max_blocks: usize,
    pub max_bytes: usize,
    pub follow_calls: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCodeTrace {
    pub references: Vec<ImportCodeReference>,
    pub visited_blocks: usize,
    pub scanned_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ImportModule {
    pub name: String,
    pub first_thunk: u32,
    pub nb_thunks: u32,
    pub thunks: BTreeMap<u32, ImportThunk>,
}
