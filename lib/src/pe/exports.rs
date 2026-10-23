use crate::pe::image::{DataDirectory, Error as ImageError, Image};

use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("PE image does not contain an export directory")]
    MissingExportDirectory,
    #[error("numeric overflow while {0}")]
    Overflow(&'static str),
}

#[derive(Clone, Debug)]
pub struct ExportSymbol {
    pub module_name: String,
    pub name: Option<String>,
    pub names: Vec<String>,
    pub ordinal: u32,
    pub rva: u32,
    pub address: u64,
    pub forwarder: Option<String>,
}

impl ExportSymbol {
    pub fn matches_name(&self, name: &str) -> bool {
        self.names.iter().any(|symbol_name| symbol_name.eq_ignore_ascii_case(name))
    }
}

#[derive(Clone, Debug)]
pub struct ExportTable {
    pub module_name: String,
    pub image_base: u64,
    pub image_size: u32,
    pub time_date_stamp: Option<u32>,
    pub symbols: Vec<ExportSymbol>,
}

impl ExportTable {
    pub fn parse(
        image: &[u8],
        image_base: Option<u64>,
        module_name: Option<String>,
    ) -> Result<Self, ExportError> {
        let image = Image::parse(image.to_vec())?;
        let mut table = Self::from_image(&image, module_name)?;
        if let Some(base) = image_base {
            for symbol in &mut table.symbols {
                symbol.address = base.checked_add(symbol.rva as u64).ok_or(ExportError::Overflow("computing export address"))?;
            }
            table.image_base = base;
        }
        Ok(table)
    }

    pub fn from_image(image: &Image, module_name: Option<String>) -> Result<Self, ExportError> {
        let image_base = image.address_base()?;
        let image_size = image.image_size()?;
        let directory = image.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)?;

        if directory.virtual_address == 0 || directory.size == 0 {
            return Err(ExportError::MissingExportDirectory);
        }

        image.read_rva(directory.virtual_address, 40)?;
        let export_offset = match image.layout() {
            crate::pe::image::Layout::File => image.rva_to_file_offset(directory.virtual_address)?,
            crate::pe::image::Layout::Mapped => image.rva_to_mapped_offset(directory.virtual_address)?,
        };
        let module_name = match module_name {
            Some(module_name) => module_name,
            None => image.read_cstr_rva(image.read_u32(export_offset + 12)?)?,
        };
        let ordinal_base = image.read_u32(export_offset + 16)?;
        let number_of_functions = image.read_u32(export_offset + 20)? as usize;
        let number_of_names = image.read_u32(export_offset + 24)? as usize;
        let address_of_functions = image.read_u32(export_offset + 28)?;
        let address_of_names = image.read_u32(export_offset + 32)?;
        let address_of_name_ordinals = image.read_u32(export_offset + 36)?;
        let name_map = read_export_names(&image, number_of_names, address_of_names, address_of_name_ordinals)?;
        let mut symbols = Vec::new();

        for index in 0..number_of_functions {
            let function_rva = image.read_u32_rva(table_rva(address_of_functions, index, 4, "reading export functions")?)?;
            if function_rva == 0 {
                continue;
            }

            let ordinal = ordinal_base
                .checked_add(index as u32)
                .ok_or(ExportError::Overflow("computing export ordinal"))?;
            let address = image_base
                .checked_add(function_rva as u64)
                .ok_or(ExportError::Overflow("computing export address"))?;
            let forwarder = if is_forwarder_rva(function_rva, directory) {
                Some(image.read_cstr_rva(function_rva)?)
            } else {
                None
            };

            let names = name_map.get(&index).cloned().unwrap_or_default();

            symbols.push(ExportSymbol {
                module_name: module_name.clone(),
                name: names.first().cloned(),
                names,
                ordinal,
                rva: function_rva,
                address,
                forwarder,
            });
        }

        symbols.sort_by_key(|symbol| (symbol.address, symbol.ordinal));

        Ok(Self {
            module_name,
            image_base,
            image_size,
            time_date_stamp: Some(image.time_date_stamp()?),
            symbols,
        })
    }

    pub fn resolve_va(&self, address: u64) -> Option<ExportSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.address == address)
            .min_by_key(|symbol| export_symbol_rank(symbol))
            .cloned()
    }

    pub fn resolve_all_va(&self, address: u64) -> Vec<ExportSymbol> {
        self.symbols
            .iter()
            .filter(|symbol| symbol.address == address)
            .cloned()
            .collect()
    }

    pub fn resolve_name(&self, name: &str) -> Option<ExportSymbol> {
        self.symbols
            .iter()
            .find(|symbol| symbol.matches_name(name))
            .cloned()
    }

    pub fn resolve_ordinal(&self, ordinal: u32) -> Option<ExportSymbol> {
        self.symbols
            .iter()
            .find(|symbol| symbol.ordinal == ordinal)
            .cloned()
    }

    pub fn resolve_nearest_va(&self, address: u64) -> Option<ExportSymbol> {
        if !self.contains_va(address) {
            return None;
        }

        let nearest_address = self
            .symbols
            .iter()
            .filter(|symbol| symbol.address <= address && symbol.forwarder.is_none())
            .map(|symbol| symbol.address)
            .max()?;

        self.symbols
            .iter()
            .filter(|symbol| symbol.address == nearest_address && symbol.forwarder.is_none())
            .min_by_key(|symbol| export_symbol_rank(symbol))
            .cloned()
    }

    pub fn contains_va(&self, address: u64) -> bool {
        let image_end = self.image_base.saturating_add(self.image_size as u64);
        address >= self.image_base && address < image_end
    }

    pub fn matches_module_name(&self, module_name: &str) -> bool {
        module_key(&self.module_name) == module_key(module_name)
    }
}

fn export_symbol_rank(symbol: &ExportSymbol) -> (bool, bool, u32) {
    (symbol.forwarder.is_some(), symbol.name.is_none(), symbol.ordinal)
}

fn read_export_names(
    image: &Image,
    number_of_names: usize,
    address_of_names: u32,
    address_of_name_ordinals: u32,
) -> Result<BTreeMap<usize, Vec<String>>, ExportError> {
    let mut names: BTreeMap<usize, Vec<String>> = BTreeMap::new();

    for index in 0..number_of_names {
        let name_rva = image.read_u32_rva(table_rva(address_of_names, index, 4, "reading export names")?)?;
        let ordinal_rva = table_rva(address_of_name_ordinals, index, 2, "reading export ordinals")?;
        let function_index = image.read_u16_rva(ordinal_rva)? as usize;
        let name = image.read_cstr_rva(name_rva)?;

        names.entry(function_index).or_default().push(name);
    }

    Ok(names)
}

fn table_rva(
    base: u32,
    index: usize,
    stride: u32,
    operation: &'static str,
) -> Result<u32, ExportError> {
    let index = u32::try_from(index)
        .map_err(|_| ExportError::Overflow(operation))?;
    let delta = index
        .checked_mul(stride)
        .ok_or(ExportError::Overflow(operation))?;

    base.checked_add(delta).ok_or(ExportError::Overflow(operation))
}

fn is_forwarder_rva(rva: u32, directory: DataDirectory) -> bool {
    rva >= directory.virtual_address && rva < directory.virtual_address.saturating_add(directory.size)
}

pub(crate) fn module_key(name: &str) -> String {
    let name = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();

    if name.ends_with(".dll") {
        name
    } else {
        format!("{name}.dll")
    }
}

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_preserves_multiple_export_names_for_one_function() {
        let table = ExportTable::parse(&export_alias_pe(), None, None).unwrap();
        let symbol = table.resolve_va(0x400300).unwrap();

        assert_eq!(table.module_name, "alias.dll");
        assert_eq!(table.symbols.len(), 1);
        assert_eq!(symbol.name.as_deref(), Some("AliasA"));
        assert_eq!(symbol.names, vec!["AliasA".to_string(), "AliasB".to_string()]);
        assert_eq!(table.resolve_name("AliasB").unwrap().ordinal, 1);
        assert_eq!(table.resolve_all_va(0x400300).len(), 1);
    }

    #[test]
    fn resolve_va_prefers_named_symbol_for_duplicate_address() {
        let table = ExportTable {
            module_name: "dup.dll".to_string(),
            image_base: 0x1000,
            image_size: 0x100,
            time_date_stamp: None,
            symbols: vec![
                ExportSymbol {
                    module_name: "dup.dll".to_string(),
                    name: None,
                    names: Vec::new(),
                    ordinal: 1,
                    rva: 0x20,
                    address: 0x1020,
                    forwarder: None,
                },
                ExportSymbol {
                    module_name: "dup.dll".to_string(),
                    name: Some("NamedAlias".to_string()),
                    names: vec!["NamedAlias".to_string()],
                    ordinal: 2,
                    rva: 0x20,
                    address: 0x1020,
                    forwarder: None,
                },
            ],
        };

        let symbol = table.resolve_va(0x1020).unwrap();
        assert_eq!(symbol.name.as_deref(), Some("NamedAlias"));
        assert_eq!(table.resolve_nearest_va(0x1024).unwrap().name.as_deref(), Some("NamedAlias"));
        assert_eq!(table.resolve_all_va(0x1020).len(), 2);
    }

    fn export_alias_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x600];
        let nt_header_offset = 0x80usize;
        let file_header_offset = nt_header_offset + 4;
        let optional_header_offset = file_header_offset + 20;
        let section_table_offset = optional_header_offset + 0xe0;
        let data_directory_offset = optional_header_offset + 96;

        write_u16(&mut data, 0, 0x5a4d);
        write_u32(&mut data, 0x3c, nt_header_offset as u32);
        write_u32(&mut data, nt_header_offset, 0x0000_4550);
        write_u16(&mut data, file_header_offset, 0x014c);
        write_u16(&mut data, file_header_offset + 2, 1);
        write_u16(&mut data, file_header_offset + 16, 0xe0);
        write_u16(&mut data, optional_header_offset, 0x10b);
        write_u32(&mut data, optional_header_offset + 28, 0x400000);
        write_u32(&mut data, optional_header_offset + 32, 0x200);
        write_u32(&mut data, optional_header_offset + 36, 0x200);
        write_u32(&mut data, optional_header_offset + 56, 0x1000);
        write_u32(&mut data, optional_header_offset + 60, 0x200);
        write_u32(&mut data, optional_header_offset + 92, 16);
        write_u32(&mut data, data_directory_offset, 0x200);
        write_u32(&mut data, data_directory_offset + 4, 0x100);

        data[section_table_offset..section_table_offset + 6].copy_from_slice(b".edata");
        write_u32(&mut data, section_table_offset + 8, 0x400);
        write_u32(&mut data, section_table_offset + 12, 0x200);
        write_u32(&mut data, section_table_offset + 16, 0x400);
        write_u32(&mut data, section_table_offset + 20, 0x200);

        write_u32(&mut data, 0x200 + 12, 0x250);
        write_u32(&mut data, 0x200 + 16, 1);
        write_u32(&mut data, 0x200 + 20, 1);
        write_u32(&mut data, 0x200 + 24, 2);
        write_u32(&mut data, 0x200 + 28, 0x260);
        write_u32(&mut data, 0x200 + 32, 0x270);
        write_u32(&mut data, 0x200 + 36, 0x280);

        write_u32(&mut data, 0x260, 0x300);
        write_u32(&mut data, 0x270, 0x290);
        write_u32(&mut data, 0x274, 0x2a0);
        write_u16(&mut data, 0x280, 0);
        write_u16(&mut data, 0x282, 0);
        write_cstr(&mut data, 0x250, b"alias.dll");
        write_cstr(&mut data, 0x290, b"AliasA");
        write_cstr(&mut data, 0x2a0, b"AliasB");

        data
    }

    fn write_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_cstr(data: &mut [u8], offset: usize, value: &[u8]) {
        data[offset..offset + value.len()].copy_from_slice(value);
        data[offset + value.len()] = 0;
    }
}
