use super::{align_up, Error, Headers, Image, SECTION_HEADER_SIZE};
use crate::pe::format::{PE_DIRECTORY_ENTRY_DEBUG, PE_DIRECTORY_ENTRY_SECURITY};

impl Image {
    pub(super) fn reserve_section_header(&mut self) -> Result<(), Error> {
        let table_end = self.headers.section_table_offset
            .checked_add(self.headers.number_of_sections as usize * SECTION_HEADER_SIZE)
            .ok_or(Error::Overflow("sizing PE section table"))?;
        let slot_end = table_end.checked_add(SECTION_HEADER_SIZE).ok_or(Error::Overflow("sizing PE section header slot"))?;
        let old_size = self.headers.size_of_headers;
        let directory_owns_slot = (0..self.headers.number_of_rva_and_sizes.min(16) as usize)
            .filter(|index| *index != PE_DIRECTORY_ENTRY_SECURITY)
            .filter_map(|index| self.data_directory(index).ok())
            .any(|directory| !directory.is_empty() && (directory.virtual_address as usize) < slot_end
                && (directory.virtual_address as u64 + directory.size as u64) > table_end as u64);
        if !directory_owns_slot && slot_end <= old_size as usize && self.slice(table_end, SECTION_HEADER_SIZE)?.iter().all(|byte| *byte == 0) {
            return Ok(());
        }

        let sections = self.sections()?;
        if sections.iter().any(|section| section.raw_size != 0 && section.raw_offset < old_size) {
            return Err(Error::SectionHeaderSpace);
        }
        let nt_start = self.headers.file_header_offset.checked_sub(4).ok_or(Error::InvalidPeSignature)?;
        let nt_data = self.data.get(nt_start..table_end).ok_or(Error::SectionHeaderSpace)?.to_vec();
        let required = (old_size as usize).checked_add(nt_data.len()).and_then(|size| size.checked_add(SECTION_HEADER_SIZE))
            .ok_or(Error::Overflow("growing PE headers"))?;
        let new_size = align_up(u32::try_from(required).map_err(|_| Error::Overflow("growing PE headers"))?, self.headers.file_alignment, "file alignment")?;
        let first_section = sections.iter().filter(|section| section.virtual_size != 0 || section.raw_size != 0)
            .map(|section| section.virtual_address).min().ok_or(Error::SectionHeaderSpace)?;
        if new_size > first_section { return Err(Error::SectionHeaderSpace); }
        self.slice(0, old_size as usize)?;
        let growth = new_size - old_size;
        let new_len = self.data.len().checked_add(growth as usize).ok_or(Error::Overflow("growing PE file"))?;
        if new_len > u32::MAX as usize { return Err(Error::Overflow("growing PE file")); }

        // Move the NT headers instead of overwriting data directories stored after the section table.
        // Existing header RVAs stay intact; only the section/file payload moves on disk.
        std::sync::Arc::make_mut(&mut self.data).splice(old_size as usize..old_size as usize, std::iter::repeat_n(0, growth as usize));
        self.write_bytes(old_size as usize, &nt_data)?;
        self.write_u32(0x3c, old_size)?;
        self.headers = Headers::parse(&self.data)?;
        self.write_u32(self.headers.optional_header_offset + 60, new_size)?;
        self.headers.size_of_headers = new_size;

        let shift = |offset: u32| -> Result<u32, Error> {
            if offset == 0 || offset < old_size { return Ok(offset); }
            offset.checked_add(growth).ok_or(Error::Overflow("updating PE file offset"))
        };
        for (index, section) in sections.iter().enumerate() {
            let header = self.headers.section_table_offset + index * SECTION_HEADER_SIZE;
            self.write_u32(header + 20, shift(section.raw_offset)?)?;
            for field in [24, 28] {
                self.write_u32(header + field, shift(self.read_u32(header + field)?)?)?;
            }
        }
        let symbol_pointer = self.headers.file_header_offset + 8;
        self.write_u32(symbol_pointer, shift(self.read_u32(symbol_pointer)?)?)?;
        if let Ok(directory) = self.data_directory(PE_DIRECTORY_ENTRY_SECURITY) {
            self.set_data_directory(PE_DIRECTORY_ENTRY_SECURITY, shift(directory.virtual_address)?, directory.size)?;
        }
        if let Ok(directory) = self.data_directory(PE_DIRECTORY_ENTRY_DEBUG) && !directory.is_empty() {
            if directory.size % 28 != 0 { return Err(Error::TooSmall("complete debug directory entries")); }
            for index in 0..directory.size / 28 {
                let rva = directory.virtual_address.checked_add(index * 28).ok_or(Error::Overflow("walking debug directory"))?;
                let offset = self.rva_to_file_offset(rva)?;
                self.slice(offset, 28)?;
                self.write_u32(offset + 24, shift(self.read_u32(offset + 24)?)?)?;
            }
        }
        self.write_u32(self.headers.optional_header_offset + 64, 0)?;
        Ok(())
    }
}
