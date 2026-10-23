use super::DiagnosticsError;
use crate::pe::exports::ExportTable;
use crate::pe::format;
use crate::pe::image::{Error as ImageError, Image, SanitizeHeadersOptions};

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportPrologueHash {
    pub names: Vec<String>,
    pub rva: u32,
    pub hash: u64,
    pub size: usize,
}

pub fn normalized_header_hash(data: &[u8]) -> Result<u64, DiagnosticsError> {
    let image = Image::parse(data.to_vec())?;
    let mut normalized = image.sanitize_headers_with_options(SanitizeHeadersOptions {
        clear_checksum: true,
        clear_security_directory: true,
        clear_bound_import_directory: true,
        clear_delay_import_directory: true,
        raw_sections_from_virtual: false,
    })?;
    let normalized_image = Image::parse(normalized.clone())?;
    let header_size = normalized_image.size_of_headers() as usize;
    let header_size = header_size.min(normalized.len());

    zero_u32(&mut normalized, normalized_image.file_header_offset() + 4)?;
    Ok(fnv1a64(&normalized[..header_size]))
}

pub fn export_prologue_hashes(
    image_data: &[u8],
    image_base: Option<u64>,
    module_name: Option<String>,
    prologue_size: usize,
) -> Result<Vec<ExportPrologueHash>, DiagnosticsError> {
    let image = Image::parse(image_data.to_vec())?;
    let table = ExportTable::parse(image_data, image_base, module_name)
        .map_err(|error| match error {
            crate::pe::exports::ExportError::Image(error) => DiagnosticsError::Image(error),
            crate::pe::exports::ExportError::Overflow(operation) => DiagnosticsError::Overflow(operation),
            crate::pe::exports::ExportError::MissingExportDirectory => {
                DiagnosticsError::Image(ImageError::DataDirectoryEmpty {
                    index: format::PE_DIRECTORY_ENTRY_EXPORT,
                })
            }
        })?;
    let mut hashes = BTreeMap::<u32, ExportPrologueHash>::new();

    for symbol in table.symbols.iter().filter(|symbol| symbol.forwarder.is_none()) {
        let prologue = match image.read_bytes_rva(symbol.rva, prologue_size) {
            Ok(prologue) => prologue,
            Err(_) => continue,
        };
        let name = symbol
            .name
            .clone()
            .unwrap_or_else(|| format!("ordinal_{}", symbol.ordinal));

        hashes
            .entry(symbol.rva)
            .and_modify(|entry| {
                if !entry.names.contains(&name) {
                    entry.names.push(name.clone());
                }
            })
            .or_insert_with(|| ExportPrologueHash {
                names: vec![name],
                rva: symbol.rva,
                hash: fnv1a64(&prologue),
                size: prologue.len(),
            });
    }

    let mut hashes = hashes.into_values().collect::<Vec<_>>();
    for item in &mut hashes {
        item.names.sort();
    }

    Ok(hashes)
}

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;

    for byte in data {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    hash
}

fn zero_u32(data: &mut [u8], offset: usize) -> Result<(), DiagnosticsError> {
    let Some(bytes) = data.get_mut(offset..offset + 4) else {
        return Err(DiagnosticsError::Image(ImageError::OutOfBounds { offset, size: 4 }));
    };

    bytes.fill(0);
    Ok(())
}
