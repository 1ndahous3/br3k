use super::anomalies::image_anomalies_from_image;
use super::{fnv1a64, DiagnosticsError, ImageAnomaly};
use crate::pe::format;
use crate::pe::image::{DataDirectory, Format, Image, SectionInfo};
use crate::pe::tls as pe_tls;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityDirectoryInfo {
    pub present: bool,
    pub file_offset: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RichHeaderInfo {
    pub present: bool,
    pub offset: usize,
    pub size: usize,
    pub key: u32,
    pub hash: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadConfigInfo {
    pub present: bool,
    pub rva: u32,
    pub size: u32,
    pub structure_size: Option<u32>,
    pub time_date_stamp: Option<u32>,
    pub major_version: Option<u16>,
    pub minor_version: Option<u16>,
    pub dependent_load_flags: Option<u16>,
    pub process_heap_flags: Option<u32>,
    pub security_cookie: Option<u64>,
    pub se_handler_table: Option<u64>,
    pub se_handler_count: Option<u64>,
    pub guard_cf_check_function_pointer: Option<u64>,
    pub guard_cf_dispatch_function_pointer: Option<u64>,
    pub guard_cf_function_table: Option<u64>,
    pub guard_cf_function_count: Option<u64>,
    pub guard_flags: Option<u32>,
    pub code_integrity: Option<LoadConfigCodeIntegrityInfo>,
    pub guard_address_taken_iat_entry_table: Option<u64>,
    pub guard_address_taken_iat_entry_count: Option<u64>,
    pub guard_long_jump_target_table: Option<u64>,
    pub guard_long_jump_target_count: Option<u64>,
    pub dynamic_value_reloc_table: Option<u64>,
    pub chpe_metadata_pointer: Option<u64>,
    pub guard_rf_failure_routine: Option<u64>,
    pub guard_rf_failure_routine_function_pointer: Option<u64>,
    pub dynamic_value_reloc_table_offset: Option<u32>,
    pub dynamic_value_reloc_table_section: Option<u16>,
    pub guard_rf_verify_stack_pointer_function_pointer: Option<u64>,
    pub hot_patch_table_offset: Option<u32>,
    pub enclave_configuration_pointer: Option<u64>,
    pub volatile_metadata_pointer: Option<u64>,
    pub guard_eh_continuation_table: Option<u64>,
    pub guard_eh_continuation_count: Option<u64>,
    pub guard_xfg_check_function_pointer: Option<u64>,
    pub guard_xfg_dispatch_function_pointer: Option<u64>,
    pub guard_xfg_table_dispatch_function_pointer: Option<u64>,
    pub cast_guard_os_determined_failure_mode: Option<u64>,
    pub guard_memcpy_function_pointer: Option<u64>,
}

impl LoadConfigInfo {
    pub fn guard_flag_names(&self) -> Vec<&'static str> {
        guard_flag_names(self.guard_flags.unwrap_or(0))
    }

    pub fn guard_cf_instrumented(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_CF_INSTRUMENTED)
    }

    pub fn guard_cf_function_table_present(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)
            || nonzero_u64(self.guard_cf_function_table)
            || nonzero_u64(self.guard_cf_function_count)
    }

    pub fn guard_cf_function_table_entry_size(&self) -> Option<u32> {
        self.guard_flags.map(|guard_flags| {
            4 + ((guard_flags & format::IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
                >> format::IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT)
        })
    }

    pub fn guard_rf_enabled(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_RF_INSTRUMENTED)
            || self.has_guard_flag(format::IMAGE_GUARD_RF_ENABLE)
            || self.has_guard_flag(format::IMAGE_GUARD_RF_STRICT)
            || nonzero_u64(self.guard_rf_failure_routine)
            || nonzero_u64(self.guard_rf_failure_routine_function_pointer)
            || nonzero_u64(self.guard_rf_verify_stack_pointer_function_pointer)
    }

    pub fn has_xfg(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_XFG_ENABLED)
            || nonzero_u64(self.guard_xfg_check_function_pointer)
            || nonzero_u64(self.guard_xfg_dispatch_function_pointer)
            || nonzero_u64(self.guard_xfg_table_dispatch_function_pointer)
            || nonzero_u64(self.cast_guard_os_determined_failure_mode)
    }

    pub fn has_cast_guard(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_CASTGUARD_PRESENT)
            || nonzero_u64(self.cast_guard_os_determined_failure_mode)
    }

    pub fn has_guard_memcpy(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_MEMCPY_PRESENT)
            || nonzero_u64(self.guard_memcpy_function_pointer)
    }

    pub fn has_chpe_metadata(&self) -> bool {
        nonzero_u64(self.chpe_metadata_pointer)
    }

    pub fn has_dynamic_value_relocations(&self) -> bool {
        nonzero_u64(self.dynamic_value_reloc_table)
            || nonzero_u32(self.dynamic_value_reloc_table_offset)
            || nonzero_u16(self.dynamic_value_reloc_table_section)
    }

    pub fn has_hotpatch_table(&self) -> bool {
        nonzero_u32(self.hot_patch_table_offset)
    }

    pub fn has_enclave_config(&self) -> bool {
        nonzero_u64(self.enclave_configuration_pointer)
    }

    pub fn has_volatile_metadata(&self) -> bool {
        nonzero_u64(self.volatile_metadata_pointer)
    }

    pub fn has_guard_eh_continuations(&self) -> bool {
        self.has_guard_flag(format::IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT)
            || nonzero_u64(self.guard_eh_continuation_table)
            || nonzero_u64(self.guard_eh_continuation_count)
    }

    fn has_guard_flag(&self, flag: u32) -> bool {
        self.guard_flags
            .map(|guard_flags| guard_flags & flag != 0)
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadConfigCodeIntegrityInfo {
    pub flags: u16,
    pub catalog: u16,
    pub catalog_offset: u32,
    pub reserved: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataDirectoryInfo {
    pub present: bool,
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsDirectoryInfo {
    pub present: bool,
    pub rva: u32,
    pub size: u32,
    pub callbacks: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DotNetDirectoryInfo {
    pub present: bool,
    pub rva: u32,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackerHint {
    pub name: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataSummary {
    pub security: SecurityDirectoryInfo,
    pub rich_header: RichHeaderInfo,
    pub load_config: LoadConfigInfo,
    pub base_relocations: DataDirectoryInfo,
    pub tls: TlsDirectoryInfo,
    pub delay_imports: DataDirectoryInfo,
    pub bound_imports: DataDirectoryInfo,
    pub dotnet: DotNetDirectoryInfo,
    pub packer_hints: Vec<PackerHint>,
    pub anomalies: Vec<ImageAnomaly>,
}

pub fn metadata_summary(
    data: &[u8],
    mapped_layout: bool,
) -> Result<MetadataSummary, DiagnosticsError> {
    let image = Image::parse(data.to_vec())?;
    inspect_image_layout(&image, mapped_layout)
}

pub fn inspect_image(image: &Image) -> Result<MetadataSummary, DiagnosticsError> {
    inspect_image_layout(image, image.layout() == crate::pe::image::Layout::Mapped)
}

fn inspect_image_layout(image: &Image, mapped_layout: bool) -> Result<MetadataSummary, DiagnosticsError> {
    let sections = image.sections()?;

    Ok(MetadataSummary {
        security: security_directory_info(&image),
        rich_header: rich_header_info(image.data()),
        load_config: load_config_info(&image, mapped_layout),
        base_relocations: directory_info(&image, format::PE_DIRECTORY_ENTRY_BASERELOC),
        tls: tls_directory_info(&image, mapped_layout),
        delay_imports: directory_info(&image, format::PE_DIRECTORY_ENTRY_DELAY_IMPORT),
        bound_imports: directory_info(&image, format::PE_DIRECTORY_ENTRY_BOUND_IMPORT),
        dotnet: dotnet_directory_info(&image),
        packer_hints: packer_hints(&image, &sections)?,
        anomalies: image_anomalies_from_image(&image, &sections, mapped_layout)?,
    })
}

fn security_directory_info(image: &Image) -> SecurityDirectoryInfo {
    let directory = image
        .data_directory(format::PE_DIRECTORY_ENTRY_SECURITY)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });

    SecurityDirectoryInfo {
        present: !directory.is_empty(),
        file_offset: directory.virtual_address,
        size: directory.size,
    }
}

fn rich_header_info(data: &[u8]) -> RichHeaderInfo {
    let Some(rich_offset) = find_bytes(data, b"Rich") else {
        return RichHeaderInfo {
            present: false,
            offset: 0,
            size: 0,
            key: 0,
            hash: 0,
        };
    };
    let Some(key_bytes) = data.get(rich_offset + 4..rich_offset + 8) else {
        return RichHeaderInfo {
            present: false,
            offset: 0,
            size: 0,
            key: 0,
            hash: 0,
        };
    };

    let key = u32::from_le_bytes(key_bytes.try_into().unwrap());
    let dans = u32::from_le_bytes(*b"DanS") ^ key;
    let start = data[..rich_offset]
        .chunks_exact(4)
        .enumerate()
        .rev()
        .find_map(|(index, chunk)| {
            let value = u32::from_le_bytes(chunk.try_into().ok()?);
            (value == dans).then_some(index * 4)
        })
        .unwrap_or(0);
    let size = rich_offset + 8 - start;

    RichHeaderInfo {
        present: true,
        offset: start,
        size,
        key,
        hash: fnv1a64(&data[start..rich_offset + 8]),
    }
}

pub(crate) fn load_config_info(image: &Image, mapped_layout: bool) -> LoadConfigInfo {
    let directory = image
        .data_directory(format::PE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    if directory.is_empty() {
        return empty_load_config_info();
    }

    let directory_data = if mapped_layout {
        image.read_mapped_bytes_rva(directory.virtual_address, directory.size as usize)
    } else {
        image.read_bytes_rva(directory.virtual_address, directory.size as usize)
    };

    let Ok(data) = directory_data else {
        return LoadConfigInfo {
            present: true,
            rva: directory.virtual_address,
            size: directory.size,
            ..empty_load_config_info()
        };
    };

    let reader = LoadConfigReader::new(&data, image.format());

    LoadConfigInfo {
        present: true,
        rva: directory.virtual_address,
        size: directory.size,
        structure_size: reader.structure_size,
        time_date_stamp: reader.u32_at_offset(0x04),
        major_version: reader.u16_at_offset(0x08),
        minor_version: reader.u16_at_offset(0x0a),
        dependent_load_flags: reader.u16_at(0x36, 0x4e),
        process_heap_flags: reader.u32_at(0x2c, 0x48),
        security_cookie: reader.ptr_at(0x3c, 0x58),
        se_handler_table: reader.ptr_at(0x40, 0x60),
        se_handler_count: reader.ptr_at(0x44, 0x68),
        guard_cf_check_function_pointer: reader.ptr_at(0x48, 0x70),
        guard_cf_dispatch_function_pointer: reader.ptr_at(0x4c, 0x78),
        guard_cf_function_table: reader.ptr_at(0x50, 0x80),
        guard_cf_function_count: reader.ptr_at(0x54, 0x88),
        guard_flags: reader.u32_at(0x58, 0x90),
        code_integrity: reader.code_integrity(),
        guard_address_taken_iat_entry_table: reader.ptr_at(0x68, 0xa0),
        guard_address_taken_iat_entry_count: reader.ptr_at(0x6c, 0xa8),
        guard_long_jump_target_table: reader.ptr_at(0x70, 0xb0),
        guard_long_jump_target_count: reader.ptr_at(0x74, 0xb8),
        dynamic_value_reloc_table: reader.ptr_at(0x78, 0xc0),
        chpe_metadata_pointer: reader.ptr_at(0x7c, 0xc8),
        guard_rf_failure_routine: reader.ptr_at(0x80, 0xd0),
        guard_rf_failure_routine_function_pointer: reader.ptr_at(0x84, 0xd8),
        dynamic_value_reloc_table_offset: reader.u32_at(0x88, 0xe0),
        dynamic_value_reloc_table_section: reader.u16_at(0x8c, 0xe4),
        guard_rf_verify_stack_pointer_function_pointer: reader.ptr_at(0x90, 0xe8),
        hot_patch_table_offset: reader.u32_at(0x94, 0xf0),
        enclave_configuration_pointer: reader.ptr_at(0x9c, 0xf8),
        volatile_metadata_pointer: reader.ptr_at(0xa0, 0x100),
        guard_eh_continuation_table: reader.ptr_at(0xa4, 0x108),
        guard_eh_continuation_count: reader.ptr_at(0xa8, 0x110),
        guard_xfg_check_function_pointer: reader.ptr_at(0xac, 0x118),
        guard_xfg_dispatch_function_pointer: reader.ptr_at(0xb0, 0x120),
        guard_xfg_table_dispatch_function_pointer: reader.ptr_at(0xb4, 0x128),
        cast_guard_os_determined_failure_mode: reader.ptr_at(0xb8, 0x130),
        guard_memcpy_function_pointer: reader.ptr_at(0xbc, 0x138),
    }
}

fn empty_load_config_info() -> LoadConfigInfo {
    LoadConfigInfo {
        present: false,
        rva: 0,
        size: 0,
        structure_size: None,
        time_date_stamp: None,
        major_version: None,
        minor_version: None,
        dependent_load_flags: None,
        process_heap_flags: None,
        security_cookie: None,
        se_handler_table: None,
        se_handler_count: None,
        guard_cf_check_function_pointer: None,
        guard_cf_dispatch_function_pointer: None,
        guard_cf_function_table: None,
        guard_cf_function_count: None,
        guard_flags: None,
        code_integrity: None,
        guard_address_taken_iat_entry_table: None,
        guard_address_taken_iat_entry_count: None,
        guard_long_jump_target_table: None,
        guard_long_jump_target_count: None,
        dynamic_value_reloc_table: None,
        chpe_metadata_pointer: None,
        guard_rf_failure_routine: None,
        guard_rf_failure_routine_function_pointer: None,
        dynamic_value_reloc_table_offset: None,
        dynamic_value_reloc_table_section: None,
        guard_rf_verify_stack_pointer_function_pointer: None,
        hot_patch_table_offset: None,
        enclave_configuration_pointer: None,
        volatile_metadata_pointer: None,
        guard_eh_continuation_table: None,
        guard_eh_continuation_count: None,
        guard_xfg_check_function_pointer: None,
        guard_xfg_dispatch_function_pointer: None,
        guard_xfg_table_dispatch_function_pointer: None,
        cast_guard_os_determined_failure_mode: None,
        guard_memcpy_function_pointer: None,
    }
}

struct LoadConfigReader<'a> {
    data: &'a [u8],
    format: Format,
    available: usize,
    structure_size: Option<u32>,
}

impl<'a> LoadConfigReader<'a> {
    fn new(data: &'a [u8], format: Format) -> Self {
        let structure_size = data.get(..4).and_then(read_u32);
        let available = structure_size
            .map(|size| data.len().min(size as usize))
            .unwrap_or(data.len());

        Self {
            data,
            format,
            available,
            structure_size,
        }
    }

    fn u16_at(&self, pe32_offset: usize, pe64_offset: usize) -> Option<u16> {
        match self.format {
            Format::Pe32 => self.u16_at_offset(pe32_offset),
            Format::Pe64 => self.u16_at_offset(pe64_offset),
        }
    }

    fn u32_at(&self, pe32_offset: usize, pe64_offset: usize) -> Option<u32> {
        match self.format {
            Format::Pe32 => self.u32_at_offset(pe32_offset),
            Format::Pe64 => self.u32_at_offset(pe64_offset),
        }
    }

    fn ptr_at(&self, pe32_offset: usize, pe64_offset: usize) -> Option<u64> {
        match self.format {
            Format::Pe32 => self.u32_at_offset(pe32_offset).map(u64::from),
            Format::Pe64 => self.u64_at_offset(pe64_offset),
        }
    }

    fn code_integrity(&self) -> Option<LoadConfigCodeIntegrityInfo> {
        let offset = match self.format {
            Format::Pe32 => 0x5c,
            Format::Pe64 => 0x94,
        };

        Some(LoadConfigCodeIntegrityInfo {
            flags: self.u16_at_offset(offset)?,
            catalog: self.u16_at_offset(offset + 2)?,
            catalog_offset: self.u32_at_offset(offset + 4)?,
            reserved: self.u32_at_offset(offset + 8)?,
        })
    }

    fn u16_at_offset(&self, offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(offset, 2)?.try_into().ok()?))
    }

    fn u32_at_offset(&self, offset: usize) -> Option<u32> {
        read_u32(self.bytes(offset, 4)?)
    }

    fn u64_at_offset(&self, offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(offset, 8)?.try_into().ok()?))
    }

    fn bytes(&self, offset: usize, size: usize) -> Option<&[u8]> {
        let end = offset.checked_add(size)?;
        if end > self.available {
            return None;
        }

        self.data.get(offset..end)
    }
}

fn guard_flag_names(guard_flags: u32) -> Vec<&'static str> {
    [
        (format::IMAGE_GUARD_CF_INSTRUMENTED, "CFInstrumented"),
        (format::IMAGE_GUARD_CFW_INSTRUMENTED, "CFWInstrumented"),
        (format::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, "CFFunctionTable"),
        (format::IMAGE_GUARD_SECURITY_COOKIE_UNUSED, "SecurityCookieUnused"),
        (format::IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, "ProtectDelayloadIat"),
        (format::IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION, "DelayloadIatOwnSection"),
        (format::IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT, "CFExportSuppressionInfo"),
        (format::IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, "CFExportSuppressionEnabled"),
        (format::IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT, "CFLongJumpTable"),
        (format::IMAGE_GUARD_RF_INSTRUMENTED, "RFInstrumented"),
        (format::IMAGE_GUARD_RF_ENABLE, "RFEnabled"),
        (format::IMAGE_GUARD_RF_STRICT, "RFStrict"),
        (format::IMAGE_GUARD_RETPOLINE_PRESENT, "Retpoline"),
        (format::IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, "EHContinuationTable"),
        (format::IMAGE_GUARD_XFG_ENABLED, "XFGEnabled"),
        (format::IMAGE_GUARD_CASTGUARD_PRESENT, "CastGuard"),
        (format::IMAGE_GUARD_MEMCPY_PRESENT, "GuardMemcpy"),
    ]
    .into_iter()
    .filter_map(|(flag, name)| (guard_flags & flag != 0).then_some(name))
    .collect()
}

fn nonzero_u16(value: Option<u16>) -> bool {
    value.map(|value| value != 0).unwrap_or(false)
}

fn nonzero_u32(value: Option<u32>) -> bool {
    value.map(|value| value != 0).unwrap_or(false)
}

fn nonzero_u64(value: Option<u64>) -> bool {
    value.map(|value| value != 0).unwrap_or(false)
}

fn directory_info(image: &Image, index: usize) -> DataDirectoryInfo {
    let directory = image
        .data_directory(index)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });

    DataDirectoryInfo {
        present: !directory.is_empty(),
        rva: directory.virtual_address,
        size: directory.size,
    }
}

fn tls_directory_info(image: &Image, mapped_layout: bool) -> TlsDirectoryInfo {
    let directory = image
        .data_directory(format::PE_DIRECTORY_ENTRY_TLS)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    if directory.is_empty() {
        return TlsDirectoryInfo {
            present: false,
            rva: 0,
            size: 0,
            callbacks: Vec::new(),
        };
    }

    let callbacks = match mapped_layout {
        true => pe_tls::tls_directory_with_layout(image, pe_tls::TlsLayout::MappedImage),
        false => pe_tls::tls_directory_with_layout(image, pe_tls::TlsLayout::File),
    }
        .ok()
        .flatten()
        .map(|tls| {
            tls.callbacks
                .into_iter()
                .map(|callback| callback.address)
                .collect()
        })
        .unwrap_or_default();

    TlsDirectoryInfo {
        present: true,
        rva: directory.virtual_address,
        size: directory.size,
        callbacks,
    }
}

fn dotnet_directory_info(image: &Image) -> DotNetDirectoryInfo {
    let directory = image
        .data_directory(format::PE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });

    DotNetDirectoryInfo {
        present: !directory.is_empty(),
        rva: directory.virtual_address,
        size: directory.size,
    }
}

fn packer_hints(image: &Image, sections: &[SectionInfo]) -> Result<Vec<PackerHint>, DiagnosticsError> {
    let mut hints = Vec::new();

    if sections
        .iter()
        .any(|section| section.name.eq_ignore_ascii_case("UPX0"))
        && sections
            .iter()
            .any(|section| section.name.eq_ignore_ascii_case("UPX1"))
    {
        hints.push(PackerHint {
            name: "UPX-like sections".to_string(),
            reason: "both UPX0 and UPX1 section names are present".to_string(),
        });
    }

    if sections
        .iter()
        .any(|section| format::section_is_executable(section) && section.characteristics & format::IMAGE_SCN_MEM_WRITE != 0)
    {
        hints.push(PackerHint {
            name: "writable executable section".to_string(),
            reason: "at least one section is marked executable and writable".to_string(),
        });
    }

    let imports = image
        .data_directory(format::PE_DIRECTORY_ENTRY_IMPORT)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    let iat = image
        .data_directory(format::PE_DIRECTORY_ENTRY_IAT)
        .unwrap_or(DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    if imports.is_empty() && iat.is_empty() {
        hints.push(PackerHint {
            name: "missing import directories".to_string(),
            reason: "Import and IAT directories are empty".to_string(),
        });
    }

    let entry_point = image.entry_point()?;
    if entry_point != 0 && !sections.iter().any(|section| {
        let size = format::section_size(section);
        entry_point >= section.virtual_address && entry_point < section.virtual_address.saturating_add(size)
    }) {
        hints.push(PackerHint {
            name: "entry point outside sections".to_string(),
            reason: format!("entry point RVA 0x{entry_point:x} is not inside any section"),
        });
    }

    Ok(hints)
}

fn find_bytes(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return None;
    }

    data.windows(needle.len())
        .position(|window| window == needle)
}

fn read_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(data.try_into().ok()?))
}
