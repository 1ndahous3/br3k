use super::{read_bound_imports, BoundImportError, Layout};
use crate::pe::export_map::{ExportMap, ExportTableSource};
use crate::pe::image::Image;
use crate::pe::imports::{import_headers_with_layout, ImportDirectoryLayout};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Origin of a bound-import dependency check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum BoundImportKind {
    /// Entry in the bound-import directory.
    BoundDescriptor,
    /// Binding timestamp carried by a normal import descriptor.
    LegacyDescriptor,
    /// Forwarder dependency associated with a bound-import descriptor.
    ForwarderRef,
}

/// Result of matching bound-import metadata to available dependency evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum BoundImportStatus {
    /// Recorded and dependency timestamps agree.
    TimestampMatch,
    /// Recorded and dependency timestamps differ.
    TimestampMismatch,
    /// Dependency export source is unavailable.
    DependencyMissing,
    /// Multiple dependency sources prevent an unambiguous match.
    DependencyAmbiguous,
    /// The dependency source has no usable timestamp.
    TimestampUnavailable,
    /// Import metadata expects a bound descriptor that was not found.
    MissingBoundDescriptor,
    /// Recorded binding timestamp is not valid for the descriptor form.
    InvalidTimestamp,
    /// Forwarder metadata failed validation.
    InvalidForwarder,
}

#[derive(Clone, Debug)]
pub struct BoundImportCheck {
    pub rva: u32,
    pub dll_name: String,
    pub kind: BoundImportKind,
    pub status: BoundImportStatus,
    pub expected_timestamp: Option<u32>,
    pub dependency_timestamp: Option<u32>,
    pub dependency_source: Option<ExportTableSource>,
    pub reserved: Option<u16>,
    pub forwarders: Vec<BoundImportCheck>,
}

impl BoundImportCheck {
    pub fn matches_dependencies(&self) -> bool {
        self.status == BoundImportStatus::TimestampMatch && self.forwarders.iter().all(Self::matches_dependencies)
    }
}

impl Image {
    pub fn bound_import_checks(&self, exports: &ExportMap) -> Result<Vec<BoundImportCheck>, BoundImportError> {
        check_imports(self, exports, Layout::File)
    }

    pub fn mapped_bound_import_checks(&self, exports: &ExportMap) -> Result<Vec<BoundImportCheck>, BoundImportError> {
        check_imports(self, exports, Layout::MappedImage)
    }
}

fn check_imports(image: &Image, exports: &ExportMap, layout: Layout) -> Result<Vec<BoundImportCheck>, BoundImportError> {
    let bound = read_bound_imports(image, layout)?;
    let import_layout = match layout { Layout::File => ImportDirectoryLayout::File, Layout::MappedImage => ImportDirectoryLayout::MappedImage };
    // Binding metadata is useful even when the corresponding lookup/address table has been damaged.
    let imports = import_headers_with_layout(image, import_layout)?;
    let mut checks = Vec::new();
    for descriptor in &bound {
        let mut check = check_dependency(exports, &descriptor.dll_name, descriptor.descriptor_rva, Some(descriptor.time_date_stamp), BoundImportKind::BoundDescriptor);
        for forwarder in &descriptor.forwarders {
            let mut item = check_dependency(exports, &forwarder.dll_name, forwarder.rva, Some(forwarder.time_date_stamp), BoundImportKind::ForwarderRef);
            item.reserved = Some(forwarder.reserved);
            if forwarder.reserved != 0 { item.status = BoundImportStatus::InvalidForwarder; }
            check.forwarders.push(item);
        }
        checks.push(check);
    }
    for descriptor in imports {
        if descriptor.time_date_stamp == 0 { continue; }
        let Some(name) = descriptor.dll_name else { continue };
        if descriptor.time_date_stamp == u32::MAX {
            if !bound.iter().any(|item| item.dll_name.eq_ignore_ascii_case(&name)) {
                checks.push(check_dependency(exports, &name, descriptor.descriptor_rva, None, BoundImportKind::BoundDescriptor));
            }
        } else {
            checks.push(check_dependency(exports, &name, descriptor.descriptor_rva, Some(descriptor.time_date_stamp), BoundImportKind::LegacyDescriptor));
        }
    }
    Ok(checks)
}

fn check_dependency(exports: &ExportMap, name: &str, rva: u32, expected: Option<u32>, kind: BoundImportKind) -> BoundImportCheck {
    // API-set redirection cannot establish which binary was used when an image was bound.
    let mut dependencies = exports.records().iter().filter(|record| record.table.matches_module_name(name));
    let dependency = dependencies.next();
    let ambiguous = dependencies.next().is_some();
    let actual = dependency.filter(|_| !ambiguous).and_then(|record| record.table.time_date_stamp);
    let status = match expected {
        None => BoundImportStatus::MissingBoundDescriptor,
        Some(0 | u32::MAX) => BoundImportStatus::InvalidTimestamp,
        Some(_) if ambiguous => BoundImportStatus::DependencyAmbiguous,
        Some(_) if dependency.is_none() => BoundImportStatus::DependencyMissing,
        Some(_) if actual.is_none_or(|stamp| matches!(stamp, 0 | u32::MAX)) => BoundImportStatus::TimestampUnavailable,
        Some(stamp) if actual == Some(stamp) => BoundImportStatus::TimestampMatch,
        Some(_) => BoundImportStatus::TimestampMismatch,
    };
    BoundImportCheck {
        rva, dll_name: name.to_string(), kind, status, expected_timestamp: expected, dependency_timestamp: actual,
        dependency_source: dependency.filter(|_| !ambiguous).map(|record| record.source), reserved: None, forwarders: Vec::new(),
    }
}
