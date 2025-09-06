use crate::prelude::*;

use io::Write;
use scroll::Pread;

use pdb::{FallibleIterator, PDB, SymbolData, TypeData};
use minidump::format::{CV_INFO_PDB70, CvSignature};
use exe::{PtrPE, PE, Buffer, headers};


#[derive(thiserror::Error, Debug)]
pub enum PdbError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("PDB parsing error: {0}")]
    Pdb(#[from] pdb::Error),
    #[error("Symbol '{0}' not found")]
    SymbolNotFound(String),
    #[error("Field '{field}' not found in class '{class}'")]
    FieldNotFound { class: String, field: String },
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = result::Result<T, PdbError>;

#[derive(Debug)]
pub struct Pdb<'s> {
    pdb: PDB<'s, fs::File>
}

impl<'a> Pdb<'a> {
    pub fn init(pdb_filepath: &str) -> Result<Self> {
        let file = fs::File::open(pdb_filepath)?;

        let pdb = match PDB::open(file) {
            Ok(p) => p,
            Err(e) => return Err(PdbError::Pdb(e)),
        };

        Ok(Self {
            pdb
        })
    }

    pub fn get_symbol_rva(&mut self, symbol_name: &str) -> Result<usize> {

        let address_map = self.pdb.address_map()?;

        if let Ok(symbol_table) = self.pdb.global_symbols() {
            let mut symbols = symbol_table.iter();
            while let Some(symbol) = symbols.next()? {
                if let Ok(SymbolData::Public(data)) = symbol.parse() {
                    if data.name.to_string().as_ref() == symbol_name {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            return Ok(rva.0 as usize);
                        }
                    }
                }
                if let Ok(SymbolData::Data(data)) = symbol.parse() {
                    if data.name.to_string().as_ref() == symbol_name {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            return Ok(rva.0 as usize);
                        }
                    }
                }
            }
        }

        if let Ok(dbi) = self.pdb.debug_information() {
            let mut modules = dbi.modules()?;
            while let Some(module) = modules.next()? {
                if let Some(module_info) = self.pdb.module_info(&module)? {
                    let mut symbols = module_info.symbols()?;
                    while let Some(symbol) = symbols.next()? {
                        match symbol.parse() {
                            Ok(SymbolData::Procedure(data))
                                if data.name.to_string().as_ref() == symbol_name =>
                            {
                                if let Some(rva) = data.offset.to_rva(&address_map) {
                                    return Ok(rva.0 as usize);
                                }
                            }
                            Ok(SymbolData::Data(data))
                                if data.name.to_string().as_ref() == symbol_name =>
                            {
                                if let Some(rva) = data.offset.to_rva(&address_map) {
                                    return Ok(rva.0 as usize);
                                }
                            }
                            _ => continue,
                        }
                    }
                }
            }
        }

        Err(PdbError::SymbolNotFound(symbol_name.to_string()))
    }

    pub fn get_field_offset(&mut self, class_name: &str, field_name: &str) -> Result<usize> {

        let type_information = self.pdb.type_information()?;
        let mut type_iter = type_information.iter();

        let mut class_fields_index = None;
        let mut type_finder = type_information.finder();

        while let Some(typ) = type_iter.next()? {
            type_finder.update(&type_iter);
            match typ.parse().ok() {
                Some(TypeData::Class(class_data)) => {
                    if class_data.name.to_string().as_ref() == class_name
                        && !class_data.properties.forward_reference()
                    {
                        class_fields_index = class_data.fields;
                        break;
                    }
                }
                _ => continue,
            }
        }

        let fields_index = class_fields_index.ok_or_else(|| PdbError::FieldNotFound {
            class: class_name.to_string(),
            field: field_name.to_string(),
        })?;

        let field_list_type = type_finder.find(fields_index)?;
        match field_list_type.parse()? {
            TypeData::FieldList(field_list) => {
                for field in &field_list.fields {
                    if let TypeData::Member(member) = field {
                        if member.name.to_string().as_ref() == field_name {
                            return Ok(member.offset as usize);
                        }
                    }
                }
            }
            _ => return Err(PdbError::InvalidData("Expected field list".to_string())),
        }

        Err(PdbError::FieldNotFound {
            class: class_name.to_string(),
            field: field_name.to_string(),
        })
    }
}

pub fn download_pdb(pe: &PtrPE, folder_path: &str) -> std::result::Result<String, exe::Error> {
    unsafe {
        static SYMBOL_SERVER: &str = "https://msdl.microsoft.com/download/symbols/";

        let debug_directory = pe.get_data_directory(headers::ImageDirectoryEntry::Debug)?;
        if debug_directory.virtual_address.0 == 0 {
            return Err(exe::Error::SectionNotFound);
        }

        let mut debug_directory_offset_current = pe.rva_to_offset(debug_directory.virtual_address)?.0 as usize;

        loop {
            let debug_dir: &headers::ImageDebugDirectory = pe.get_ref(debug_directory_offset_current)?;
            if debug_dir.size_of_data == 0 {
                break;
            }

            if headers::ImageDebugType::from_u32(debug_dir.type_) != headers::ImageDebugType::CodeView {
                debug_directory_offset_current += size_of::<headers::ImageDebugDirectory>();
                continue;
            }

            let cv_info_offset = pe.rva_to_offset(debug_dir.address_of_raw_data)?;

            let cv_info: CV_INFO_PDB70 = pe.get_buffer().as_slice().pread_with(cv_info_offset.0 as usize, scroll::LE).unwrap();
            if cv_info.cv_signature != CvSignature::Pdb70 as u32  {
                debug_directory_offset_current += size_of::<headers::ImageDebugDirectory>();
                continue;
            }

            let pdb_filename = CStr::from_ptr(cv_info.pdb_file_name.as_ptr() as _).to_string_lossy();
            let pdb_extention_path = format!("{}/{:#}{}/{}", pdb_filename, cv_info.signature, cv_info.age, pdb_filename);
            let pdb_filepath = format!("{}/{}", folder_path, pdb_filename);
            let url = format!("{}{}", SYMBOL_SERVER, pdb_extention_path);

            log::info!("PDB URL: {}", url);
            log::info!("downloading, it can take a while...");

            let response = reqwest::blocking::get(&url).map_err(|e| {
                log::error!("unable to download PDB: {}", e);
                exe::Error::IoError(std::io::ErrorKind::NetworkUnreachable.into())
            })?;

            if !response.status().is_success() {
                log::error!("unable to download PDB, HTTP status: {}", response.status());
                return Err(exe::Error::IoError(std::io::ErrorKind::NetworkUnreachable.into()));
            }

            let mut file = fs::File::create(&pdb_filepath).map_err(|e| {
                log::error!("unable to create PDB file: {}", e);
                exe::Error::IoError(std::io::ErrorKind::Other.into())
            })?;

            file.write_all(&response.bytes().map_err(|e| {
                log::error!("unable to read response body: {}", e);
                exe::Error::IoError(std::io::ErrorKind::Other.into())
            })?).map_err(|e| {
                log::error!("unable to write to PDB file: {}", e);
                exe::Error::IoError(std::io::ErrorKind::Other.into())
            })?;

            return Ok(pdb_filepath);
        }

        Err(exe::Error::SectionNotFound)
    }
}
