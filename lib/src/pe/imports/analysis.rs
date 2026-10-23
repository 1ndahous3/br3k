use crate::pe::{image::{Image, Layout}, export_map::ExportMap};
use super::{ImportModel, ImportError, ImportAddressResolveOptions, ImportAddressTableRangeScore, RecoverIatOptions};

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub min_entries: usize,
    pub anchors: Vec<u32>,
    pub trace_depth: Option<usize>,
    pub resolution: ImportAddressResolveOptions,
}

impl Default for ScanOptions {
    fn default() -> Self { Self { min_entries: 2, anchors: Vec::new(), trace_depth: None, resolution: Default::default() } }
}

/// Contextual import discovery, separate from editing an ImportModel.
pub struct Analyzer<'a> { pub image: &'a Image, pub symbols: &'a ExportMap }

impl Analyzer<'_> {
    pub fn scan(&self, mut options: ScanOptions) -> Result<Vec<ImportAddressTableRangeScore>, ImportError> {
        self.image.require_layout(Layout::Mapped)?;
        self.image.validate_contents()?;
        options.resolution.api_set_map = Some(self.symbols.api_set_map().clone());
        let exports = self.symbols.tables().collect::<Vec<_>>();
        let ranges = match options.trace_depth {
            Some(depth) => super::scan_iat_ranges_with_traced_thunks(self.image.data(), 0, self.image.pointer_size(), options.resolution, &exports, options.min_entries, self.image.load_base(), depth)?,
            None => super::scan_iat_ranges_with_options(self.image.data(), 0, self.image.pointer_size(), options.resolution, &exports, options.min_entries)?,
        };
        for range in &ranges { self.image.read_rva(range.rva, range.size as usize)?; }
        super::rank_iat_ranges(ranges, &options.anchors)
    }

    pub fn recover_range(&self, rva: u32, size: usize, mut options: RecoverIatOptions) -> Result<ImportModel, ImportError> {
        self.image.require_layout(Layout::Mapped)?;
        options.address_resolve_options.api_set_map = Some(self.symbols.api_set_map().clone());
        let mut model = ImportModel::default();
        super::recover_iat_with_recovery_options(&mut model, rva, self.image.read_rva(rva, size)?, self.image.pointer_size(), options, &self.symbols.tables().collect::<Vec<_>>())?;
        Ok(model)
    }
}
