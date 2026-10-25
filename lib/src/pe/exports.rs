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
#[path = "tests/exports.rs"]
mod tests;
