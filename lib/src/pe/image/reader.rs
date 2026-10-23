use super::{Error, Image};
use std::sync::Arc;
use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Storage layout, independent of the preferred and captured virtual addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum Layout {
    /// Headers and section bytes use on-disk file offsets.
    #[default]
    File,
    /// Section bytes use their RVAs within a memory-image buffer.
    Mapped,
}

/// Unavailable bytes in mapped RVA space. Filled bytes are never evidence of capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingRange {
    pub rva: u32,
    pub size: u32,
}

impl Image {
    pub fn from_mapped(data: Vec<u8>, load_base: u64, missing: Vec<MissingRange>) -> Result<Self, Error> {
        Self::from_mapped_shared(Arc::new(data), load_base, missing)
    }

    pub fn from_mapped_shared(data: Arc<Vec<u8>>, load_base: u64, missing: Vec<MissingRange>) -> Result<Self, Error> {
        let headers = super::Headers::parse(&data)?;
        let mut image = Self { data, headers, layout: Layout::Mapped, load_base: Some(load_base), missing: Arc::new(Vec::new()), sections: Default::default(), metadata: Default::default() };
        for range in &missing {
            image.slice(range.rva as usize, range.size as usize)?;
        }
        image.layout = Layout::Mapped;
        image.load_base = Some(load_base);
        image.missing = Arc::new(missing);
        let table_end = image.section_table_offset().checked_add(image.sections()?.len() * 40)
            .ok_or(Error::Overflow("checking captured section table"))?;
        image.check_coverage(0, table_end.max(image.size_of_headers() as usize))?;
        Ok(image)
    }

    pub fn layout(&self) -> Layout { self.layout }
    pub fn shared_data(&self) -> Arc<Vec<u8>> { self.data.clone() }
    pub fn load_base(&self) -> Option<u64> { self.load_base }
    pub fn missing_ranges(&self) -> &[MissingRange] { &self.missing }
    pub fn address_base(&self) -> Result<u64, Error> { self.load_base.map_or_else(|| self.image_base(), Ok) }

    pub fn require_layout(&self, expected: Layout) -> Result<(), Error> {
        if self.layout == expected { Ok(()) } else { Err(Error::LayoutMismatch { expected, actual: self.layout }) }
    }

    pub fn rva_to_va(&self, rva: u32) -> Result<u64, Error> {
        self.address_base()?.checked_add(rva as u64).ok_or(Error::Overflow("converting RVA to VA"))
    }

    pub fn va_to_rva(&self, va: u64) -> Result<u32, Error> {
        va.checked_sub(self.address_base()?).and_then(|rva| u32::try_from(rva).ok())
            .ok_or(Error::Overflow("converting VA to RVA"))
    }

    pub fn read_rva(&self, rva: u32, size: usize) -> Result<&[u8], Error> {
        match self.layout {
            Layout::File => self.read_file_rva(rva, size),
            Layout::Mapped => self.read_mapped_rva(rva, size),
        }
    }

    pub fn read_file_rva(&self, rva: u32, size: usize) -> Result<&[u8], Error> {
        let (offset, mut available) = self.file_range(rva)?;
        while size > available {
            let next_rva = rva.checked_add(u32::try_from(available).map_err(|_| Error::Overflow("reading RVA range"))?)
                .ok_or(Error::Overflow("reading RVA range"))?;
            let (next_offset, next_size) = self.file_range(next_rva)?;
            if offset.checked_add(available) != Some(next_offset) || next_size == 0 {
                return Err(Error::RvaNotMapped { rva: next_rva });
            }
            available = available.checked_add(next_size).ok_or(Error::Overflow("reading RVA range"))?;
        }
        self.slice(offset, size)
    }

    pub fn read_mapped_rva(&self, rva: u32, size: usize) -> Result<&[u8], Error> {
        self.check_coverage(rva, size)?;
        self.slice(rva as usize, size)
    }

    fn check_coverage(&self, rva: u32, size: usize) -> Result<(), Error> {
        let end = (rva as u64).checked_add(size as u64).ok_or(Error::Overflow("checking capture coverage"))?;
        if size != 0 && self.missing.iter().any(|range| {
            (range.rva as u64) < end && (rva as u64) < range.rva as u64 + range.size as u64
        }) {
            return Err(Error::MissingData { rva, size });
        }
        Ok(())
    }

    pub(super) fn file_range(&self, rva: u32) -> Result<(usize, usize), Error> {
        let mut selected = (rva < self.headers.size_of_headers).then(|| (rva as usize, (self.headers.size_of_headers - rva) as usize));
        let mut next_section = None;
        for section in self.section_view()? {
            if section.virtual_address > rva && section.virtual_size.max(section.raw_size) != 0 {
                next_section = Some(next_section.map_or(section.virtual_address, |next: u32| next.min(section.virtual_address)));
            }
            let Some(delta) = rva.checked_sub(section.virtual_address) else { continue };
            if delta >= section.virtual_size.max(section.raw_size) { continue; }
            // A virtual tail has no file backing, even if another section's bytes follow it.
            if delta >= section.raw_size || selected.is_some() { return Err(Error::RvaNotMapped { rva }); }
            let offset = section.raw_offset.checked_add(delta).ok_or(Error::Overflow("mapping RVA to file offset"))?;
            selected = Some((offset as usize, (section.raw_size - delta) as usize));
        }
        let (offset, size) = selected.ok_or(Error::RvaNotMapped { rva })?;
        // Recheck ownership at the next section boundary, even when this section has raw bytes beyond it.
        Ok((offset, next_section.map_or(size, |next| size.min((next - rva) as usize))))
    }
}
