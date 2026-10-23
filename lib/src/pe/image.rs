use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

mod placement;
mod resources;
#[cfg(test)]
use resources::{ResourceDataLeaf, rebase_resource_directory_data_rvas, build_resource_directory_data};
mod reader;
mod features;
pub mod editor;

pub use reader::{Layout, MissingRange};

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("PE data is too small to contain {0}")]
    TooSmall(&'static str),
    #[error("invalid DOS signature")]
    InvalidDosSignature,
    #[error("invalid PE signature")]
    InvalidPeSignature,
    #[error("unsupported PE optional header magic 0x{0:x}")]
    UnsupportedOptionalHeaderMagic(u16),
    #[error("PE range at offset 0x{offset:x} with size 0x{size:x} is outside image data")]
    OutOfBounds { offset: usize, size: usize },
    #[error("RVA 0x{rva:x} does not map to file data")]
    RvaNotMapped { rva: u32 },
    #[error("data directory {index} is not present")]
    DataDirectoryMissing { index: usize },
    #[error("data directory {index} is empty")]
    DataDirectoryEmpty { index: usize },
    #[error("section name must fit in 8 bytes: {0}")]
    SectionNameTooLong(String),
    #[error("section table has no room for an additional section header")]
    SectionHeaderSpace,
    #[error("resource directory contains a recursive directory at offset 0x{offset:x}")]
    ResourceDirectoryLoop { offset: usize },
    #[error("resource data RVA 0x{rva:x} is outside resource directory RVA range 0x{start:x}..0x{end:x}")]
    ResourceDataRvaOutOfRange { rva: u32, start: u32, end: u32 },
    #[error("resource data entry has an empty path")]
    ResourceDataPathEmpty,
    #[error("resource path has neither name nor id")]
    ResourcePathMissingKey,
    #[error("resource path is both a directory and a data entry")]
    ResourcePathConflict,
    #[error("trusted PE header mismatch for {field}: current 0x{current:x}, trusted 0x{trusted:x}")]
    TrustedHeaderMismatch {
        field: &'static str,
        current: u64,
        trusted: u64,
    },
    #[error("trusted PE header size 0x{trusted:x} is larger than destination header size 0x{current:x}")]
    TrustedHeadersTooLarge { current: u32, trusted: u32 },
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
    #[error("alignment value for {0} is zero")]
    ZeroAlignment(&'static str),
    #[error("unterminated C string at RVA 0x{rva:x}")]
    UnterminatedCString { rva: u32 },
    #[error("range at RVA 0x{rva:x} with size 0x{size:x} contains uncaptured bytes")]
    MissingData { rva: u32, size: usize },
    #[error("operation requires {expected:?} layout, got {actual:?}")]
    LayoutMismatch { expected: Layout, actual: Layout },
    #[error("reference identity differs in {0}")]
    ReferenceIdentity(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pe32,
    Pe64,
}

#[derive(Clone, Copy, Debug)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn is_empty(self) -> bool {
        self.virtual_address == 0 || self.size == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceDirectoryInfo {
    pub virtual_address: u32,
    pub size: u32,
    pub directory_count: usize,
    pub named_entry_count: usize,
    pub id_entry_count: usize,
    pub data_entry_count: usize,
    pub data_size: u64,
    pub max_depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourcePathEntry {
    pub name: Option<String>,
    pub id: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceDataEntry {
    pub path: Vec<ResourcePathEntry>,
    pub data_rva: u32,
    pub size: u32,
    pub code_page: u32,
    pub reserved: u32,
}

/// Conflict policy when the same resource leaf exists in file and mapped sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ResourceMergePreference {
    /// Prefer the file-source resource on conflict.
    File,
    /// Prefer the mapped-source resource on conflict.
    Mapped,
    /// Prefer the larger resource payload on conflict.
    #[default]
    Larger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlayRange {
    pub offset: usize,
    pub size: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct AddedSection {
    pub virtual_address: u32,
    pub raw_offset: usize,
}

/// File-offset policy when converting mapped sections to file layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum SectionRawLayout {
    /// Pack raw section data using file alignment.
    #[default]
    Packed,
    /// Keep raw section offsets aligned with their virtual addresses.
    MappedOffsets,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MappedToFileImageOptions {
    pub image_base: Option<u64>,
    pub image_size: Option<u32>,
    pub entry_point: Option<u32>,
    pub section_raw_layout: SectionRawLayout,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SanitizeHeadersOptions {
    pub clear_checksum: bool,
    pub clear_security_directory: bool,
    pub clear_bound_import_directory: bool,
    pub clear_delay_import_directory: bool,
    pub raw_sections_from_virtual: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct TrustedHeadersOptions {
    pub keep_image_base: bool,
    pub keep_image_size: bool,
    pub keep_entry_point: bool,
    pub keep_section_raw_layout: bool,
    pub raw_sections_from_virtual: bool,
}

impl Default for TrustedHeadersOptions {
    fn default() -> Self {
        Self {
            keep_image_base: true,
            keep_image_size: true,
            keep_entry_point: true,
            keep_section_raw_layout: true,
            raw_sections_from_virtual: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Headers {
    file_header_offset: usize,
    optional_header_offset: usize,
    section_table_offset: usize,
    machine: u16,
    number_of_sections: u16,
    number_of_rva_and_sizes: u32,
    format: Format,
    section_alignment: u32,
    file_alignment: u32,
    size_of_headers: u32,
}

#[derive(Clone, Copy, Debug)]
enum ResourceDirectorySourceLayout {
    File,
    MappedImage,
}

#[derive(Clone, Debug)]
pub struct Image {
    data: Arc<Vec<u8>>,
    headers: Headers,
    layout: Layout,
    load_base: Option<u64>,
    missing: Arc<Vec<MissingRange>>,
    sections: Arc<OnceLock<Result<Vec<SectionInfo>, Error>>>,
    metadata: Arc<OnceLock<Result<crate::pe::diagnostics::MetadataSummary, crate::pe::diagnostics::DiagnosticsError>>>,
}

impl Image {
    pub fn parse(data: Vec<u8>) -> Result<Self, Error> {
        let headers = Headers::parse(&data)?;
        Ok(Self { data: Arc::new(data), headers, layout: Layout::File, load_base: None, missing: Arc::new(Vec::new()), sections: Default::default(), metadata: Default::default() })
    }

    pub fn into_data(self) -> Vec<u8> {
        Arc::unwrap_or_clone(self.data)
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn format(&self) -> Format {
        self.headers.format
    }

    pub fn file_header_offset(&self) -> usize {
        self.headers.file_header_offset
    }

    pub fn optional_header_offset(&self) -> usize {
        self.headers.optional_header_offset
    }

    pub fn section_table_offset(&self) -> usize {
        self.headers.section_table_offset
    }

    pub fn size_of_headers(&self) -> u32 {
        self.headers.size_of_headers
    }

    pub fn pointer_size(&self) -> usize {
        match self.headers.format {
            Format::Pe32 => 4,
            Format::Pe64 => 8,
        }
    }

    pub fn machine(&self) -> u16 {
        self.headers.machine
    }

    pub fn time_date_stamp(&self) -> Result<u32, Error> {
        self.read_u32(self.headers.file_header_offset + 4)
    }

    pub fn image_base(&self) -> Result<u64, Error> {
        match self.headers.format {
            Format::Pe32 => Ok(self.read_u32(self.headers.optional_header_offset + 28)? as u64),
            Format::Pe64 => self.read_u64(self.headers.optional_header_offset + 24),
        }
    }

    pub fn image_size(&self) -> Result<u32, Error> {
        self.read_u32(self.headers.optional_header_offset + 56)
    }

    pub fn entry_point(&self) -> Result<u32, Error> {
        self.read_u32(self.headers.optional_header_offset + 16)
    }

    pub fn mapped_to_file_image(&self) -> Result<Vec<u8>, Error> {
        self.mapped_to_file_image_with_options(MappedToFileImageOptions::default())
    }

    pub fn mapped_to_file_image_with_options(
        &self,
        options: MappedToFileImageOptions,
    ) -> Result<Vec<u8>, Error> {
        let sections = self.sections()?;
        let first_raw_offset = align_up(self.headers.size_of_headers, self.headers.file_alignment, "file alignment")?;
        let mut output = vec![0u8; first_raw_offset as usize];
        let headers = self.slice(0, self.headers.size_of_headers as usize)?;
        output[..headers.len()].copy_from_slice(headers);

        if let Some(image_base) = options.image_base {
            write_image_base_at(&mut output, self.headers, image_base)?;
        }
        if let Some(image_size) = options.image_size {
            write_u32_at(&mut output, self.headers.optional_header_offset + 56, image_size)?;
        }
        if let Some(entry_point) = options.entry_point {
            write_u32_at(&mut output, self.headers.optional_header_offset + 16, entry_point)?;
        }
        write_u32_at(&mut output, self.headers.optional_header_offset + 64, 0)?;
        if self.headers.number_of_rva_and_sizes > IMAGE_DIRECTORY_ENTRY_SECURITY as u32 {
            let security_directory_offset = self.data_directory_offset(IMAGE_DIRECTORY_ENTRY_SECURITY)?;
            write_u32_at(&mut output, security_directory_offset, 0)?;
            write_u32_at(&mut output, security_directory_offset + 4, 0)?;
        }

        let mut next_packed_raw_offset = first_raw_offset;
        for (index, section) in sections.iter().enumerate() {
            let copy_size = if section.virtual_size != 0 {
                section.virtual_size
            } else {
                section.raw_size
            };
            let raw_size = align_up(copy_size, self.headers.file_alignment, "file alignment")?;
            let section_header_offset = self.headers.section_table_offset + index * SECTION_HEADER_SIZE;
            let pointer_to_raw_data = match options.section_raw_layout {
                _ if raw_size == 0 => 0,
                SectionRawLayout::Packed => next_packed_raw_offset,
                SectionRawLayout::MappedOffsets => section.virtual_address,
            };

            write_u32_at(&mut output, section_header_offset + 16, raw_size)?;
            write_u32_at(&mut output, section_header_offset + 20, pointer_to_raw_data)?;

            if raw_size != 0 {
                let raw_end = pointer_to_raw_data
                    .checked_add(raw_size)
                    .ok_or(Error::Overflow("placing section raw data"))?;
                output.resize(raw_end as usize, 0);

                let source_offset = section.virtual_address as usize;
                let source_size = copy_size as usize;
                let source = self.slice(source_offset, source_size)?;
                let destination = pointer_to_raw_data as usize;
                output[destination..destination + source.len()].copy_from_slice(source);

                if options.section_raw_layout == SectionRawLayout::Packed {
                    next_packed_raw_offset = raw_end;
                }
            }
        }

        Ok(output)
    }

    pub fn sanitize_headers_with_options(&self, options: SanitizeHeadersOptions) -> Result<Vec<u8>, Error> {
        let mut image = self.clone();

        image.sanitize_headers_in_place(options)?;
        Ok(image.into_data())
    }

    pub fn sanitize_headers_in_place(&mut self, options: SanitizeHeadersOptions) -> Result<(), Error> {
        if options.clear_checksum {
            self.write_u32(self.headers.optional_header_offset + 64, 0)?;
        }
        if options.clear_security_directory {
            self.clear_data_directory_if_present(IMAGE_DIRECTORY_ENTRY_SECURITY)?;
        }
        if options.clear_bound_import_directory {
            self.clear_data_directory_if_present(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)?;
        }
        if options.clear_delay_import_directory {
            self.clear_data_directory_if_present(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;
        }
        if options.raw_sections_from_virtual {
            self.set_section_raw_headers_from_virtual()?;
        }

        Ok(())
    }

    pub fn copy_headers_from_trusted(
        &self,
        trusted_data: &[u8],
        options: TrustedHeadersOptions,
    ) -> Result<Vec<u8>, Error> {
        let mut image = self.clone();

        image.copy_headers_from_trusted_in_place(trusted_data, options)?;
        Ok(image.into_data())
    }

    pub fn copy_headers_from_trusted_in_place(
        &mut self,
        trusted_data: &[u8],
        options: TrustedHeadersOptions,
    ) -> Result<(), Error> {
        let trusted = Self::parse(trusted_data.to_vec())?;
        self.validate_trusted_headers(&trusted)?;

        if trusted.headers.size_of_headers > self.headers.size_of_headers {
            return Err(Error::TrustedHeadersTooLarge {
                current: self.headers.size_of_headers,
                trusted: trusted.headers.size_of_headers,
            });
        }

        let image_base = if options.keep_image_base {
            Some(self.image_base()?)
        } else {
            None
        };
        let image_size = if options.keep_image_size {
            Some(self.image_size()?)
        } else {
            None
        };
        let entry_point = if options.keep_entry_point {
            Some(self.entry_point()?)
        } else {
            None
        };
        let section_raw_layout = if options.keep_section_raw_layout && !options.raw_sections_from_virtual {
            Some(
                self.sections()?
                    .into_iter()
                    .map(|section| (section.raw_size, section.raw_offset))
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        self.write_bytes(0, trusted.slice(0, trusted.headers.size_of_headers as usize)?)?;
        self.headers = Headers::parse(&self.data)?;

        if let Some(image_base) = image_base {
            write_image_base_at(Arc::make_mut(&mut self.data).as_mut_slice(), self.headers, image_base)?;
        }
        if let Some(image_size) = image_size {
            self.write_u32(self.headers.optional_header_offset + 56, image_size)?;
        }
        if let Some(entry_point) = entry_point {
            self.write_u32(self.headers.optional_header_offset + 16, entry_point)?;
        }
        if options.raw_sections_from_virtual {
            self.set_section_raw_headers_from_virtual()?;
        } else if let Some(section_raw_layout) = section_raw_layout {
            self.restore_section_raw_headers(&section_raw_layout)?;
        }

        self.headers = Headers::parse(&self.data)?;
        Ok(())
    }

    pub fn data_directory(&self, index: usize) -> Result<DataDirectory, Error> {
        if index as u32 >= self.headers.number_of_rva_and_sizes {
            return Err(Error::DataDirectoryMissing { index });
        }

        let offset = self.data_directory_offset(index)?;
        Ok(DataDirectory {
            virtual_address: self.read_u32(offset)?,
            size: self.read_u32(offset + 4)?,
        })
    }

    pub fn set_data_directory(
        &mut self,
        index: usize,
        virtual_address: u32,
        size: u32,
    ) -> Result<(), Error> {
        if index as u32 >= self.headers.number_of_rva_and_sizes {
            return Err(Error::DataDirectoryMissing { index });
        }

        let offset = self.data_directory_offset(index)?;
        self.write_u32(offset, virtual_address)?;
        self.write_u32(offset + 4, size)
    }

    pub fn clear_data_directory_if_present(&mut self, index: usize) -> Result<(), Error> {
        if index as u32 >= self.headers.number_of_rva_and_sizes {
            return Ok(());
        }

        self.set_data_directory(index, 0, 0)
    }

    pub fn read_u16(&self, offset: usize) -> Result<u16, Error> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.slice(offset, 2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.slice(offset, 4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&self, offset: usize) -> Result<u64, Error> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.slice(offset, 8)?);
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_u16_rva(&self, rva: u32) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.read_rva(rva, 2)?.try_into().unwrap()))
    }

    pub fn read_u32_rva(&self, rva: u32) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_rva(rva, 4)?.try_into().unwrap()))
    }

    pub fn read_cstr_rva(&self, rva: u32) -> Result<String, Error> {
        let available = match self.layout {
            Layout::File => self.file_range(rva)?.1,
            Layout::Mapped => self.data.len().saturating_sub(rva as usize),
        };
        let mut data = Vec::new();
        for index in 0..available.min(65536) {
            let next = rva.checked_add(index as u32).ok_or(Error::Overflow("reading string RVA"))?;
            let value = self.read_rva(next, 1)?[0];
            if value == 0 { return Ok(String::from_utf8_lossy(&data).into_owned()); }
            data.push(value);
        }
        Err(Error::UnterminatedCString { rva })
    }

    pub fn read_bytes_rva(&self, rva: u32, size: usize) -> Result<Vec<u8>, Error> {
        Ok(self.read_file_rva(rva, size)?.to_vec())
    }

    pub fn read_mapped_bytes_rva(&self, rva: u32, size: usize) -> Result<Vec<u8>, Error> {
        Ok(self.read_mapped_rva(rva, size)?.to_vec())
    }

    pub fn overlay_range(&self) -> Result<Option<OverlayRange>, Error> {
        let offset = self.file_data_end()?;
        if offset >= self.data.len() {
            return Ok(None);
        }

        Ok(Some(OverlayRange {
            offset,
            size: self.data.len() - offset,
        }))
    }

    pub fn overlay(&self) -> Result<Option<&[u8]>, Error> {
        let Some(range) = self.overlay_range()? else {
            return Ok(None);
        };

        Ok(Some(self.slice(range.offset, range.size)?))
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize, Error> {
        let (offset, _) = self.file_range(rva)?;
        self.slice(offset, 1)?;
        Ok(offset)
    }

    pub fn rva_to_mapped_offset(&self, rva: u32) -> Result<usize, Error> {
        self.read_mapped_rva(rva, 1)?;
        Ok(rva as usize)
    }

    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.slice(offset, bytes.len())?;
        Arc::make_mut(&mut self.data)[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.sections = Default::default();
        self.metadata = Default::default();
        Ok(())
    }

    pub fn write_u32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        self.write_bytes(offset, &value.to_le_bytes())
    }

    pub fn write_u16(&mut self, offset: usize, value: u16) -> Result<(), Error> {
        self.write_bytes(offset, &value.to_le_bytes())
    }

    pub fn write_bytes_rva(&mut self, rva: u32, bytes: &[u8]) -> Result<(), Error> {
        self.read_file_rva(rva, bytes.len())?;
        let offset = self.rva_to_file_offset(rva)?;
        self.write_bytes(offset, bytes)
    }

    pub fn write_u32_rva(&mut self, rva: u32, value: u32) -> Result<(), Error> {
        self.write_bytes_rva(rva, &value.to_le_bytes())
    }

    pub fn write_pointer_rva(&mut self, rva: u32, pointer_size: usize, value: u64) -> Result<(), Error> {
        let offset = self.rva_to_file_offset(rva)?;
        self.write_pointer(offset, pointer_size, value)
    }

    pub fn append_section(&mut self, name: &str, virtual_size: usize) -> Result<AddedSection, Error> {
        self.append_section_with_characteristics(
            name,
            virtual_size,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        )
    }

    pub fn append_section_with_characteristics(
        &mut self,
        name: &str,
        virtual_size: usize,
        characteristics: u32,
    ) -> Result<AddedSection, Error> {
        let mut image = self.clone();
        image.reserve_section_header()?;
        let section = image.append_section_inner(name, virtual_size, characteristics)?;
        *self = image;
        Ok(section)
    }

    fn append_section_inner(&mut self, name: &str, virtual_size: usize, characteristics: u32) -> Result<AddedSection, Error> {
        if name.as_bytes().len() > 8 {
            return Err(Error::SectionNameTooLong(name.to_string()));
        }

        let virtual_size_u32 = u32::try_from(virtual_size)
            .map_err(|_| Error::Overflow("converting section size to u32"))?;
        let sections = self.sections()?;
        let max_raw_end = sections
            .iter()
            .map(|section| section.raw_offset.saturating_add(section.raw_size))
            .max()
            .unwrap_or(self.headers.size_of_headers);
        let max_virtual_end = sections
            .iter()
            .map(|section| {
                let span = section.virtual_size.max(section.raw_size);
                section.virtual_address.saturating_add(span)
            })
            .max()
            .unwrap_or(self.headers.size_of_headers);

        let current_len = u32::try_from(self.data.len())
            .map_err(|_| Error::Overflow("converting image length to u32"))?;
        let raw_offset = align_up(max_raw_end.max(current_len), self.headers.file_alignment, "file alignment")?;
        let raw_size = align_up(virtual_size_u32, self.headers.file_alignment, "file alignment")?;
        let virtual_address = align_up(max_virtual_end, self.headers.section_alignment, "section alignment")?;
        let image_end = align_up(
            virtual_address
                .checked_add(virtual_size_u32)
                .ok_or(Error::Overflow("updating SizeOfImage"))?,
            self.headers.section_alignment,
            "section alignment",
        )?;

        let section_header_offset = self.headers.section_table_offset
            + self.headers.number_of_sections as usize * SECTION_HEADER_SIZE;
        if section_header_offset + SECTION_HEADER_SIZE > self.headers.size_of_headers as usize {
            return Err(Error::SectionHeaderSpace);
        }

        let new_len = raw_offset
            .checked_add(raw_size)
            .ok_or(Error::Overflow("resizing PE image"))?;
        Arc::make_mut(&mut self.data).resize(new_len as usize, 0);

        let mut section_name = [0u8; 8];
        section_name[..name.as_bytes().len()].copy_from_slice(name.as_bytes());

        self.write_bytes(section_header_offset, &[0; SECTION_HEADER_SIZE])?;
        self.write_bytes(section_header_offset, &section_name)?;
        self.write_u32(section_header_offset + 8, virtual_size_u32)?;
        self.write_u32(section_header_offset + 12, virtual_address)?;
        self.write_u32(section_header_offset + 16, raw_size)?;
        self.write_u32(section_header_offset + 20, raw_offset)?;
        self.write_u32(section_header_offset + 36, characteristics)?;

        let section_count = self.headers
            .number_of_sections
            .checked_add(1)
            .ok_or(Error::Overflow("updating section count"))?;
        self.write_u16(self.headers.file_header_offset + 2, section_count)?;
        self.write_u32(self.headers.optional_header_offset + 56, image_end)?;
        self.write_u32(self.headers.optional_header_offset + 64, 0)?;

        let size_of_initialized_data = self.read_u32(self.headers.optional_header_offset + 8)?;
        self.write_u32(
            self.headers.optional_header_offset + 8,
            size_of_initialized_data.saturating_add(raw_size),
        )?;

        self.headers.number_of_sections = section_count;
        Ok(AddedSection {
            virtual_address,
            raw_offset: raw_offset as usize,
        })
    }

    pub fn write_pointer(
        &mut self,
        offset: usize,
        pointer_size: usize,
        value: u64,
    ) -> Result<(), Error> {
        match pointer_size {
            4 => {
                let value = u32::try_from(value)
                    .map_err(|_| Error::Overflow("writing 32-bit PE pointer"))?;
                self.write_bytes(offset, &value.to_le_bytes())
            }
            8 => self.write_bytes(offset, &value.to_le_bytes()),
            _ => Err(Error::Overflow("writing PE pointer with unsupported size")),
        }
    }

    pub fn sections(&self) -> Result<Vec<SectionInfo>, Error> {
        self.section_view().map(<[SectionInfo]>::to_vec)
    }

    pub fn section_view(&self) -> Result<&[SectionInfo], Error> {
        self.sections.get_or_init(|| self.parse_sections()).as_deref().map_err(Clone::clone)
    }

    fn parse_sections(&self) -> Result<Vec<SectionInfo>, Error> {
        let mut sections = Vec::with_capacity(self.headers.number_of_sections as usize);

        for index in 0..self.headers.number_of_sections as usize {
            let offset = self.headers.section_table_offset + index * SECTION_HEADER_SIZE;
            sections.push(SectionInfo {
                name: read_section_name(self.slice(offset, 8)?),
                virtual_size: self.read_u32(offset + 8)?,
                virtual_address: self.read_u32(offset + 12)?,
                raw_size: self.read_u32(offset + 16)?,
                raw_offset: self.read_u32(offset + 20)?,
                characteristics: self.read_u32(offset + 36)?,
            });
        }

        Ok(sections)
    }

    fn data_directory_offset(&self, index: usize) -> Result<usize, Error> {
        let base = match self.headers.format {
            Format::Pe32 => self.headers.optional_header_offset + 96,
            Format::Pe64 => self.headers.optional_header_offset + 112,
        };
        let offset = base
            .checked_add(index.checked_mul(8).ok_or(Error::Overflow("locating data directory"))?)
            .ok_or(Error::Overflow("locating data directory"))?;

        self.slice(offset, 8)?;
        Ok(offset)
    }

    fn set_section_raw_headers_from_virtual(&mut self) -> Result<(), Error> {
        for (index, section) in self.sections()?.iter().enumerate() {
            let raw_size = if section.virtual_size != 0 {
                section.virtual_size
            } else {
                section.raw_size
            };
            let raw_offset = if raw_size == 0 {
                0
            } else {
                section.virtual_address
            };
            let section_header_offset = self.headers.section_table_offset + index * SECTION_HEADER_SIZE;

            self.write_u32(section_header_offset + 16, raw_size)?;
            self.write_u32(section_header_offset + 20, raw_offset)?;
        }

        Ok(())
    }

    fn restore_section_raw_headers(&mut self, raw_layout: &[(u32, u32)]) -> Result<(), Error> {
        if raw_layout.len() != self.headers.number_of_sections as usize {
            return Err(Error::TrustedHeaderMismatch {
                field: "section count",
                current: raw_layout.len() as u64,
                trusted: self.headers.number_of_sections as u64,
            });
        }

        for (index, (raw_size, raw_offset)) in raw_layout.iter().copied().enumerate() {
            let section_header_offset = self.headers.section_table_offset + index * SECTION_HEADER_SIZE;

            self.write_u32(section_header_offset + 16, raw_size)?;
            self.write_u32(section_header_offset + 20, raw_offset)?;
        }

        Ok(())
    }

    fn validate_trusted_headers(&self, trusted: &Self) -> Result<(), Error> {
        self.validate_same_machine_and_format(trusted)?;
        ensure_trusted_header_match(
            "section count",
            self.headers.number_of_sections as u64,
            trusted.headers.number_of_sections as u64,
        )
    }

    fn validate_same_machine_and_format(&self, source: &Self) -> Result<(), Error> {
        ensure_trusted_header_match(
            "machine",
            self.headers.machine as u64,
            source.headers.machine as u64,
        )?;
        ensure_trusted_header_match(
            "format",
            format_code(self.headers.format),
            format_code(source.headers.format),
        )
    }

    fn slice(&self, offset: usize, size: usize) -> Result<&[u8], Error> {
        let end = offset
            .checked_add(size)
            .ok_or(Error::Overflow("checking PE range"))?;

        self.data
            .get(offset..end)
            .ok_or(Error::OutOfBounds { offset, size })
    }

    fn file_data_end(&self) -> Result<usize, Error> {
        let mut end = self.headers.size_of_headers as usize;

        for section in self.sections()? {
            if section.raw_size == 0 {
                continue;
            }

            let section_end = checked_add_usize(
                section.raw_offset as usize,
                section.raw_size as usize,
                "sizing PE section raw data",
            )?;
            self.slice(section.raw_offset as usize, section.raw_size as usize)?;
            end = end.max(section_end);
        }

        Ok(end)
    }
}

impl Headers {
    fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 0x40 {
            return Err(Error::TooSmall("DOS header"));
        }
        if read_u16(data, 0)? != IMAGE_DOS_SIGNATURE {
            return Err(Error::InvalidDosSignature);
        }

        let nt_header_offset = read_u32(data, 0x3c)? as usize;
        if read_u32(data, nt_header_offset)? != IMAGE_NT_SIGNATURE {
            return Err(Error::InvalidPeSignature);
        }

        let file_header_offset = nt_header_offset + 4;
        let number_of_sections = read_u16(data, file_header_offset + 2)?;
        let optional_header_size = read_u16(data, file_header_offset + 16)? as usize;
        let optional_header_offset = file_header_offset + IMAGE_FILE_HEADER_SIZE;
        checked_range(data, optional_header_offset, optional_header_size)?;

        let format = match read_u16(data, optional_header_offset)? {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Format::Pe32,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Format::Pe64,
            magic => return Err(Error::UnsupportedOptionalHeaderMagic(magic)),
        };
        let section_table_offset = optional_header_offset + optional_header_size;
        checked_range(
            data,
            section_table_offset,
            number_of_sections as usize * SECTION_HEADER_SIZE,
        )?;

        let number_of_rva_and_sizes_offset = match format {
            Format::Pe32 => optional_header_offset + 92,
            Format::Pe64 => optional_header_offset + 108,
        };

        Ok(Self {
            file_header_offset,
            optional_header_offset,
            section_table_offset,
            machine: read_u16(data, file_header_offset)?,
            number_of_sections,
            number_of_rva_and_sizes: read_u32(data, number_of_rva_and_sizes_offset)?,
            format,
            section_alignment: read_u32(data, optional_header_offset + 32)?,
            file_alignment: read_u32(data, optional_header_offset + 36)?,
            size_of_headers: read_u32(data, optional_header_offset + 60)?,
        })
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, Error> {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(checked_range(data, offset, 2)?);
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, Error> {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(checked_range(data, offset, 4)?);
    Ok(u32::from_le_bytes(bytes))
}

fn write_u16_at(data: &mut [u8], offset: usize, value: u16) -> Result<(), Error> {
    let end = offset
        .checked_add(2)
        .ok_or(Error::Overflow("writing PE u16 value"))?;
    let bytes = data
        .get_mut(offset..end)
        .ok_or(Error::OutOfBounds { offset, size: 2 })?;

    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32_at(data: &mut [u8], offset: usize, value: u32) -> Result<(), Error> {
    let end = offset
        .checked_add(4)
        .ok_or(Error::Overflow("writing PE u32 value"))?;
    let bytes = data
        .get_mut(offset..end)
        .ok_or(Error::OutOfBounds { offset, size: 4 })?;

    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64_at(data: &mut [u8], offset: usize, value: u64) -> Result<(), Error> {
    let end = offset
        .checked_add(8)
        .ok_or(Error::Overflow("writing PE u64 value"))?;
    let bytes = data
        .get_mut(offset..end)
        .ok_or(Error::OutOfBounds { offset, size: 8 })?;

    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_image_base_at(data: &mut [u8], headers: Headers, image_base: u64) -> Result<(), Error> {
    match headers.format {
        Format::Pe32 => {
            let image_base = u32::try_from(image_base)
                .map_err(|_| Error::Overflow("writing 32-bit PE image base"))?;
            write_u32_at(data, headers.optional_header_offset + 28, image_base)
        }
        Format::Pe64 => write_u64_at(data, headers.optional_header_offset + 24, image_base),
    }
}

fn ensure_trusted_header_match(
    field: &'static str,
    current: u64,
    trusted: u64,
) -> Result<(), Error> {
    if current == trusted {
        return Ok(());
    }

    Err(Error::TrustedHeaderMismatch {
        field,
        current,
        trusted,
    })
}

fn format_code(format: Format) -> u64 {
    match format {
        Format::Pe32 => 32,
        Format::Pe64 => 64,
    }
}

fn read_section_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn checked_range(data: &[u8], offset: usize, size: usize) -> Result<&[u8], Error> {
    let end = offset
        .checked_add(size)
        .ok_or(Error::Overflow("checking PE range"))?;

    data.get(offset..end)
        .ok_or(Error::OutOfBounds { offset, size })
}

fn checked_add_usize(left: usize, right: usize, context: &'static str) -> Result<usize, Error> {
    left.checked_add(right).ok_or(Error::Overflow(context))
}

fn checked_mul_usize(left: usize, right: usize, context: &'static str) -> Result<usize, Error> {
    left.checked_mul(right).ok_or(Error::Overflow(context))
}

fn checked_u16(value: usize, context: &'static str) -> Result<u16, Error> {
    u16::try_from(value).map_err(|_| Error::Overflow(context))
}

fn checked_u32(value: usize, context: &'static str) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::Overflow(context))
}

fn align_up(value: u32, alignment: u32, name: &'static str) -> Result<u32, Error> {
    if alignment == 0 {
        return Err(Error::ZeroAlignment(name));
    }

    let addend = alignment - 1;
    value
        .checked_add(addend)
        .map(|value| value / alignment * alignment)
        .ok_or(Error::Overflow("aligning PE value"))
}

const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_FILE_HEADER_SIZE: usize = 20;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
const IMAGE_RESOURCE_DIRECTORY_SIZE: usize = 16;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_SIZE: usize = 8;
const IMAGE_RESOURCE_DATA_ENTRY_SIZE: usize = 16;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_NAME_IS_STRING: u32 = 0x8000_0000;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY: u32 = 0x8000_0000;
const IMAGE_RESOURCE_DIRECTORY_ENTRY_OFFSET_MASK: u32 = 0x7fff_ffff;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[cfg(test)]
mod contracts;

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn mapped_pe32_image() -> Vec<u8> {
        let mut data = vec![0u8; 0x3000];
        let nt_header_offset = 0x80usize;
        let file_header_offset = nt_header_offset + 4;
        let optional_header_offset = file_header_offset + IMAGE_FILE_HEADER_SIZE;
        let section_table_offset = optional_header_offset + 0xe0;

        data[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        data[0x3c..0x40].copy_from_slice(&(nt_header_offset as u32).to_le_bytes());
        data[nt_header_offset..nt_header_offset + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        data[file_header_offset..file_header_offset + 2].copy_from_slice(&0x14cu16.to_le_bytes());
        data[file_header_offset + 2..file_header_offset + 4].copy_from_slice(&1u16.to_le_bytes());
        data[file_header_offset + 16..file_header_offset + 18].copy_from_slice(&0xe0u16.to_le_bytes());
        data[optional_header_offset..optional_header_offset + 2].copy_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes());
        data[optional_header_offset + 28..optional_header_offset + 32].copy_from_slice(&0x400000u32.to_le_bytes());
        data[optional_header_offset + 16..optional_header_offset + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        data[optional_header_offset + 32..optional_header_offset + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        data[optional_header_offset + 36..optional_header_offset + 40].copy_from_slice(&0x200u32.to_le_bytes());
        data[optional_header_offset + 56..optional_header_offset + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        data[optional_header_offset + 60..optional_header_offset + 64].copy_from_slice(&0x200u32.to_le_bytes());
        data[optional_header_offset + 64..optional_header_offset + 68].copy_from_slice(&0x12345678u32.to_le_bytes());
        data[optional_header_offset + 92..optional_header_offset + 96].copy_from_slice(&16u32.to_le_bytes());
        data[optional_header_offset + 128..optional_header_offset + 132].copy_from_slice(&0x1234u32.to_le_bytes());
        data[optional_header_offset + 132..optional_header_offset + 136].copy_from_slice(&0x5678u32.to_le_bytes());
        data[optional_header_offset + 184..optional_header_offset + 188].copy_from_slice(&0x2345u32.to_le_bytes());
        data[optional_header_offset + 188..optional_header_offset + 192].copy_from_slice(&0x6789u32.to_le_bytes());
        data[optional_header_offset + 200..optional_header_offset + 204].copy_from_slice(&0x3456u32.to_le_bytes());
        data[optional_header_offset + 204..optional_header_offset + 208].copy_from_slice(&0x789au32.to_le_bytes());

        data[section_table_offset..section_table_offset + 5].copy_from_slice(b".text");
        data[section_table_offset + 8..section_table_offset + 12].copy_from_slice(&3u32.to_le_bytes());
        data[section_table_offset + 12..section_table_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[section_table_offset + 16..section_table_offset + 20].copy_from_slice(&0u32.to_le_bytes());
        data[section_table_offset + 20..section_table_offset + 24].copy_from_slice(&0u32.to_le_bytes());
        data[0x1000..0x1003].copy_from_slice(&[1, 2, 3]);

        data
    }

    fn trusted_pe32_image() -> Vec<u8> {
        let mut data = mapped_pe32_image();
        let optional_header_offset = 0x98usize;
        let section_table_offset = optional_header_offset + 0xe0;

        data[optional_header_offset + 16..optional_header_offset + 20].copy_from_slice(&0x2222u32.to_le_bytes());
        data[optional_header_offset + 28..optional_header_offset + 32].copy_from_slice(&0x700000u32.to_le_bytes());
        data[optional_header_offset + 56..optional_header_offset + 60].copy_from_slice(&0x9000u32.to_le_bytes());
        data[optional_header_offset + 64..optional_header_offset + 68].copy_from_slice(&0xfeedfaceu32.to_le_bytes());
        data[section_table_offset..section_table_offset + 8].copy_from_slice(b".code\0\0\0");
        data[section_table_offset + 16..section_table_offset + 20].copy_from_slice(&0x400u32.to_le_bytes());
        data[section_table_offset + 20..section_table_offset + 24].copy_from_slice(&0x800u32.to_le_bytes());
        data[section_table_offset + 36..section_table_offset + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        data
    }

    pub(super) fn trusted_pe32_image_with_resource() -> Vec<u8> {
        let mut data = trusted_pe32_image();
        let optional_header_offset = 0x98usize;
        let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let resource_rva = 0x1000u32;
        let resource_size = 44u32;
        let resource_raw_offset = 0x800usize;

        data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
        data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
        write_test_resource_directory(&mut data, resource_raw_offset, resource_rva);

        data
    }

    pub(super) fn mapped_pe32_image_with_resource() -> Vec<u8> {
        let mut data = mapped_pe32_image();
        let optional_header_offset = 0x98usize;
        let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let resource_rva = 0x1000u32;
        let resource_size = 44u32;

        data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
        data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
        write_test_resource_directory(&mut data, resource_rva as usize, resource_rva);

        data
    }

    fn trusted_pe32_image_with_nested_resource() -> Vec<u8> {
        let mut data = trusted_pe32_image();
        let optional_header_offset = 0x98usize;
        let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let resource_rva = 0x1000u32;
        let resource_size = 92u32;
        let resource_raw_offset = 0x800usize;

        data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
        data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&resource_size.to_le_bytes());
        write_test_nested_resource_directory(&mut data, resource_raw_offset, resource_rva);

        data
    }

    fn trusted_pe32_image_with_resource_blob(resource: &[u8]) -> Vec<u8> {
        let mut data = trusted_pe32_image();
        let optional_header_offset = 0x98usize;
        let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let resource_rva = 0x1000u32;
        let resource_raw_offset = 0x800usize;
        let mut resource = resource.to_vec();

        rebase_resource_directory_data_rvas(&mut resource, 0, resource_rva).unwrap();
        data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
        data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&(resource.len() as u32).to_le_bytes());
        data[resource_raw_offset..resource_raw_offset + resource.len()].copy_from_slice(&resource);

        data
    }

    fn mapped_pe32_image_with_resource_blob(resource: &[u8]) -> Vec<u8> {
        let mut data = mapped_pe32_image();
        let optional_header_offset = 0x98usize;
        let resource_directory_offset = optional_header_offset + 96 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        let resource_rva = 0x1000u32;
        let mut resource = resource.to_vec();

        rebase_resource_directory_data_rvas(&mut resource, 0, resource_rva).unwrap();
        data[resource_directory_offset..resource_directory_offset + 4].copy_from_slice(&resource_rva.to_le_bytes());
        data[resource_directory_offset + 4..resource_directory_offset + 8].copy_from_slice(&(resource.len() as u32).to_le_bytes());
        data[resource_rva as usize..resource_rva as usize + resource.len()].copy_from_slice(&resource);

        data
    }

    fn write_test_resource_directory(data: &mut [u8], offset: usize, resource_rva: u32) {
        let resource = &mut data[offset..offset + 44];
        resource[14..16].copy_from_slice(&1u16.to_le_bytes());
        resource[16..20].copy_from_slice(&1u32.to_le_bytes());
        resource[20..24].copy_from_slice(&24u32.to_le_bytes());
        resource[24..28].copy_from_slice(&(resource_rva + 40).to_le_bytes());
        resource[28..32].copy_from_slice(&4u32.to_le_bytes());
        resource[40..44].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    fn write_test_nested_resource_directory(data: &mut [u8], offset: usize, resource_rva: u32) {
        let resource = &mut data[offset..offset + 92];
        resource[14..16].copy_from_slice(&1u16.to_le_bytes());
        resource[16..20].copy_from_slice(&16u32.to_le_bytes());
        resource[20..24].copy_from_slice(&(IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY | 24).to_le_bytes());
        resource[38..40].copy_from_slice(&1u16.to_le_bytes());
        resource[40..44].copy_from_slice(&1u32.to_le_bytes());
        resource[44..48].copy_from_slice(&(IMAGE_RESOURCE_DIRECTORY_ENTRY_DATA_IS_DIRECTORY | 48).to_le_bytes());
        resource[62..64].copy_from_slice(&1u16.to_le_bytes());
        resource[64..68].copy_from_slice(&1033u32.to_le_bytes());
        resource[68..72].copy_from_slice(&72u32.to_le_bytes());
        resource[72..76].copy_from_slice(&(resource_rva + 88).to_le_bytes());
        resource[76..80].copy_from_slice(&4u32.to_le_bytes());
        resource[80..84].copy_from_slice(&1200u32.to_le_bytes());
        resource[88..92].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    fn test_resource_leaf(path: &[u32], payload: &[u8]) -> ResourceDataLeaf {
        ResourceDataLeaf {
            path: path
                .iter()
                .map(|id| ResourcePathEntry {
                    name: None,
                    id: Some(*id),
                })
                .collect(),
            data: payload.to_vec(),
            code_page: 1200,
            reserved: 0,
        }
    }

    fn resource_path_ids(entry: &ResourceDataEntry) -> Vec<u32> {
        entry.path
            .iter()
            .map(|entry| entry.id.unwrap())
            .collect()
    }

    #[test]
    fn mapped_to_file_image_can_stamp_live_image_base_and_size() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let options = MappedToFileImageOptions {
            image_base: Some(0x500000),
            image_size: Some(0x5000),
            entry_point: Some(0x1234),
            section_raw_layout: SectionRawLayout::Packed,
        };
        let file_image = image.mapped_to_file_image_with_options(options).unwrap();
        let optional_header_offset = 0x98;
        let section_table_offset = optional_header_offset + 0xe0;

        assert_eq!(read_u32(&file_image, optional_header_offset + 28).unwrap(), 0x500000);
        assert_eq!(read_u32(&file_image, optional_header_offset + 16).unwrap(), 0x1234);
        assert_eq!(read_u32(&file_image, optional_header_offset + 56).unwrap(), 0x5000);
        assert_eq!(read_u32(&file_image, optional_header_offset + 64).unwrap(), 0);
        assert_eq!(read_u32(&file_image, optional_header_offset + 128).unwrap(), 0);
        assert_eq!(read_u32(&file_image, optional_header_offset + 132).unwrap(), 0);
        assert_eq!(read_u32(&file_image, section_table_offset + 16).unwrap(), 0x200);
        assert_eq!(read_u32(&file_image, section_table_offset + 20).unwrap(), 0x200);
        assert_eq!(&file_image[0x200..0x203], &[1, 2, 3]);
    }

    #[test]
    fn mapped_to_file_image_can_preserve_mapped_section_offsets() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let options = MappedToFileImageOptions {
            section_raw_layout: SectionRawLayout::MappedOffsets,
            ..Default::default()
        };
        let file_image = image.mapped_to_file_image_with_options(options).unwrap();
        let optional_header_offset = 0x98;
        let section_table_offset = optional_header_offset + 0xe0;

        assert_eq!(read_u32(&file_image, section_table_offset + 16).unwrap(), 0x200);
        assert_eq!(read_u32(&file_image, section_table_offset + 20).unwrap(), 0x1000);
        assert_eq!(&file_image[0x1000..0x1003], &[1, 2, 3]);
    }

    #[test]
    fn sanitize_headers_can_clear_selected_directories() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let options = SanitizeHeadersOptions {
            clear_checksum: true,
            clear_security_directory: true,
            clear_bound_import_directory: true,
            clear_delay_import_directory: false,
            raw_sections_from_virtual: false,
        };
        let sanitized = image.sanitize_headers_with_options(options).unwrap();
        let optional_header_offset = 0x98;

        assert_eq!(read_u32(&sanitized, optional_header_offset + 64).unwrap(), 0);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 128).unwrap(), 0);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 132).unwrap(), 0);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 184).unwrap(), 0);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 188).unwrap(), 0);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 200).unwrap(), 0x3456);
        assert_eq!(read_u32(&sanitized, optional_header_offset + 204).unwrap(), 0x789a);
    }

    #[test]
    fn sanitize_headers_can_make_section_raw_headers_virtual() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let options = SanitizeHeadersOptions {
            raw_sections_from_virtual: true,
            ..Default::default()
        };
        let sanitized = image.sanitize_headers_with_options(options).unwrap();
        let section_table_offset = 0x98 + 0xe0;

        assert_eq!(read_u32(&sanitized, section_table_offset + 16).unwrap(), 3);
        assert_eq!(read_u32(&sanitized, section_table_offset + 20).unwrap(), 0x1000);
    }

    #[test]
    fn copy_headers_from_trusted_preserves_live_dump_fields_by_default() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let file_image = image
            .mapped_to_file_image_with_options(MappedToFileImageOptions {
                image_base: Some(0x500000),
                image_size: Some(0x5000),
                entry_point: Some(0x1234),
                section_raw_layout: SectionRawLayout::Packed,
            })
            .unwrap();
        let image = Image::parse(file_image).unwrap();
        let fixed = image
            .copy_headers_from_trusted(&trusted_pe32_image(), TrustedHeadersOptions::default())
            .unwrap();
        let optional_header_offset = 0x98usize;
        let section_table_offset = optional_header_offset + 0xe0;

        assert_eq!(read_u32(&fixed, optional_header_offset + 16).unwrap(), 0x1234);
        assert_eq!(read_u32(&fixed, optional_header_offset + 28).unwrap(), 0x500000);
        assert_eq!(read_u32(&fixed, optional_header_offset + 56).unwrap(), 0x5000);
        assert_eq!(read_u32(&fixed, optional_header_offset + 64).unwrap(), 0xfeedface);
        assert_eq!(&fixed[section_table_offset..section_table_offset + 5], b".code");
        assert_eq!(read_u32(&fixed, section_table_offset + 16).unwrap(), 0x200);
        assert_eq!(read_u32(&fixed, section_table_offset + 20).unwrap(), 0x200);
        assert_eq!(read_u32(&fixed, section_table_offset + 36).unwrap(), 0x60000020);
    }

    #[test]
    fn copy_headers_from_trusted_can_normalize_raw_sections_to_virtual_layout() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let file_image = image.mapped_to_file_image().unwrap();
        let image = Image::parse(file_image).unwrap();
        let fixed = image
            .copy_headers_from_trusted(
                &trusted_pe32_image(),
                TrustedHeadersOptions {
                    keep_section_raw_layout: false,
                    raw_sections_from_virtual: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let section_table_offset = 0x98usize + 0xe0;

        assert_eq!(read_u32(&fixed, section_table_offset + 16).unwrap(), 3);
        assert_eq!(read_u32(&fixed, section_table_offset + 20).unwrap(), 0x1000);
    }

    #[test]
    fn copy_headers_from_trusted_rejects_different_machine() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let mut trusted = trusted_pe32_image();
        trusted[0x84..0x86].copy_from_slice(&0xaa64u16.to_le_bytes());

        assert!(matches!(
            image.copy_headers_from_trusted(&trusted, TrustedHeadersOptions::default()),
            Err(Error::TrustedHeaderMismatch {
                field: "machine",
                current: 0x14c,
                trusted: 0xaa64,
            })
        ));
    }

    #[test]
    fn copy_resource_directory_from_file_appends_resource_section() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let file_image = image.mapped_to_file_image().unwrap();
        let image = Image::parse(file_image).unwrap();
        let fixed = image
            .copy_resource_directory_from_file(&trusted_pe32_image_with_resource(), ".rsrc")
            .unwrap();
        let fixed_image = Image::parse(fixed).unwrap();
        let directory = fixed_image.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE).unwrap();
        let sections = fixed_image.sections().unwrap();

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[1].name, ".rsrc");
        assert_eq!(sections[1].characteristics, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
        assert_eq!(directory.virtual_address, sections[1].virtual_address);
        assert_eq!(directory.size, 44);

        let resource_data = fixed_image.read_bytes_rva(directory.virtual_address, directory.size as usize).unwrap();
        assert_eq!(read_u32(&resource_data, 24).unwrap(), directory.virtual_address + 40);
        assert_eq!(&resource_data[40..44], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn copy_resource_directory_from_mapped_image_appends_resource_section() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let file_image = image.mapped_to_file_image().unwrap();
        let image = Image::parse(file_image).unwrap();
        let fixed = image
            .copy_resource_directory_from_mapped_image(&mapped_pe32_image_with_resource(), ".rsrc")
            .unwrap();
        let fixed_image = Image::parse(fixed).unwrap();
        let directory = fixed_image.data_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE).unwrap();
        let sections = fixed_image.sections().unwrap();

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[1].name, ".rsrc");
        assert_eq!(directory.virtual_address, sections[1].virtual_address);

        let resource_data = fixed_image.read_bytes_rva(directory.virtual_address, directory.size as usize).unwrap();
        assert_eq!(read_u32(&resource_data, 24).unwrap(), directory.virtual_address + 40);
        assert_eq!(&resource_data[40..44], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn resource_directory_info_counts_file_resource_tree() {
        let image = Image::parse(trusted_pe32_image_with_resource()).unwrap();
        let info = image.resource_directory_info().unwrap();

        assert_eq!(
            info,
            ResourceDirectoryInfo {
                virtual_address: 0x1000,
                size: 44,
                directory_count: 1,
                named_entry_count: 0,
                id_entry_count: 1,
                data_entry_count: 1,
                data_size: 4,
                max_depth: 0,
            },
        );
    }

    #[test]
    fn mapped_resource_directory_info_counts_mapped_resource_tree() {
        let image = Image::parse(mapped_pe32_image_with_resource()).unwrap();
        let info = image.mapped_resource_directory_info().unwrap();

        assert_eq!(
            info,
            ResourceDirectoryInfo {
                virtual_address: 0x1000,
                size: 44,
                directory_count: 1,
                named_entry_count: 0,
                id_entry_count: 1,
                data_entry_count: 1,
                data_size: 4,
                max_depth: 0,
            },
        );
    }

    #[test]
    fn resource_data_entries_report_leaf_paths() {
        let image = Image::parse(trusted_pe32_image_with_nested_resource()).unwrap();
        let entries = image.resource_data_entries().unwrap();

        assert_eq!(
            entries,
            vec![ResourceDataEntry {
                path: vec![
                    ResourcePathEntry { name: None, id: Some(16) },
                    ResourcePathEntry { name: None, id: Some(1) },
                    ResourcePathEntry { name: None, id: Some(1033) },
                ],
                data_rva: 0x1058,
                size: 4,
                code_page: 1200,
                reserved: 0,
            }],
        );
    }

    #[test]
    fn copy_merged_resource_directory_merges_file_and_mapped_leaves() {
        let target = Image::parse(mapped_pe32_image()).unwrap();
        let target = Image::parse(target.mapped_to_file_image().unwrap()).unwrap();
        let file_resource = build_resource_directory_data(&[
            test_resource_leaf(&[16, 1, 1033], b"file"),
            test_resource_leaf(&[24, 1, 1033], b"file-only"),
        ])
        .unwrap();
        let mapped_resource = build_resource_directory_data(&[
            test_resource_leaf(&[14, 2, 1033], b"mapped-only"),
            test_resource_leaf(&[16, 1, 1033], b"mapped"),
        ])
        .unwrap();
        let file_source = trusted_pe32_image_with_resource_blob(&file_resource);
        let mapped_source = mapped_pe32_image_with_resource_blob(&mapped_resource);
        let fixed = target
            .copy_merged_resource_directory_from_file_and_mapped_image(
                &file_source,
                &mapped_source,
                ".rsrc",
                ResourceMergePreference::Larger,
            )
            .unwrap();
        let fixed_image = Image::parse(fixed).unwrap();
        let entries = fixed_image.resource_data_entries().unwrap();
        let mut payloads = BTreeMap::new();

        for entry in entries {
            payloads.insert(
                resource_path_ids(&entry),
                fixed_image.read_bytes_rva(entry.data_rva, entry.size as usize).unwrap(),
            );
        }

        assert_eq!(payloads.get(&vec![14, 2, 1033]).map(Vec::as_slice), Some(b"mapped-only".as_slice()));
        assert_eq!(payloads.get(&vec![16, 1, 1033]).map(Vec::as_slice), Some(b"mapped".as_slice()));
        assert_eq!(payloads.get(&vec![24, 1, 1033]).map(Vec::as_slice), Some(b"file-only".as_slice()));
    }

    #[test]
    fn copy_resource_directory_from_file_rejects_empty_source_directory() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let file_image = image.mapped_to_file_image().unwrap();
        let image = Image::parse(file_image).unwrap();

        assert!(matches!(
            image.copy_resource_directory_from_file(&trusted_pe32_image(), ".rsrc"),
            Err(Error::DataDirectoryEmpty {
                index: IMAGE_DIRECTORY_ENTRY_RESOURCE,
            })
        ));
    }

    #[test]
    fn overlay_range_reports_data_after_section_raw_end() {
        let image = Image::parse(mapped_pe32_image()).unwrap();
        let mut file_image = image.mapped_to_file_image().unwrap();

        assert_eq!(Image::parse(file_image.clone()).unwrap().overlay_range().unwrap(), None);

        file_image.extend_from_slice(&[4, 5, 6]);
        let image = Image::parse(file_image).unwrap();

        assert_eq!(
            image.overlay_range().unwrap(),
            Some(OverlayRange {
                offset: 0x400,
                size: 3,
            }),
        );
        assert_eq!(image.overlay().unwrap(), Some(&[4, 5, 6][..]));
    }
}
