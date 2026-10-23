use super::DiagnosticsError;
use crate::pe::format;
use crate::pe::image::{DataDirectory, Image, SectionInfo};

use strum_macros::{FromRepr, IntoStaticStr, VariantArray};

/// Review priority of a PE metadata anomaly, not a malware classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImageAnomalySeverity {
    /// Informational structural observation.
    Info,
    /// Potential inconsistency or limitation.
    Warning,
    /// Pattern deserving closer inspection, with possible benign explanations.
    Suspicious,
}

/// PE header, section, or directory condition reported by structural inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, VariantArray, FromRepr, IntoStaticStr)]
#[repr(u32)]
pub enum ImageAnomalyKind {
    /// COFF machine value is not recognized by the inspector.
    UnknownMachine,
    /// COFF characteristics do not mark an executable image.
    NonExecutableImage,
    /// Section has no effective virtual or raw extent.
    SectionZeroSize,
    /// Section RVA and size overflow their numeric range.
    SectionVirtualRangeOverflow,
    /// Section virtual extent exceeds SizeOfImage.
    SectionVirtualOutsideImage,
    /// Virtual section ranges overlap.
    SectionVirtualOverlap,
    /// Section file offset and size overflow their numeric range.
    SectionRawRangeOverflow,
    /// Section raw bytes extend beyond the file buffer.
    SectionRawOutOfBounds,
    /// Section raw data begins inside the header area.
    SectionRawBeforeHeaders,
    /// Raw file ranges of sections overlap.
    SectionRawOverlap,
    /// Entry-point RVA is outside the section ranges.
    EntryPointOutsideSections,
    /// Section characteristics permit both execution and writing.
    ExecutableWritableSection,
    /// Image does not declare a normal import directory.
    MissingImportDirectory,
    /// Directory address and size overflow their numeric range.
    DataDirectoryRangeOverflow,
    /// Directory extent exceeds the virtual image.
    DataDirectoryOutsideImage,
    /// Directory range is not contained by the expected image sections.
    DataDirectoryOutsideSections,
    /// Bound-import metadata could not be parsed or validated.
    InvalidBoundImportDirectory,
}

impl ImageAnomalyKind {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

impl ImageAnomalySeverity {
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageAnomaly {
    pub kind: ImageAnomalyKind,
    pub severity: ImageAnomalySeverity,
    pub section_name: Option<String>,
    pub directory_index: Option<usize>,
    pub directory_name: Option<String>,
    pub rva: Option<u32>,
    pub size: Option<u32>,
    pub message: String,
}

pub fn image_anomalies(
    data: &[u8],
    mapped_layout: bool,
) -> Result<Vec<ImageAnomaly>, DiagnosticsError> {
    let image = Image::parse(data.to_vec())?;
    let sections = image.sections()?;

    image_anomalies_from_image(&image, &sections, mapped_layout)
}

pub(super) fn image_anomalies_from_image(
    image: &Image,
    sections: &[SectionInfo],
    mapped_layout: bool,
) -> Result<Vec<ImageAnomaly>, DiagnosticsError> {
    let mut anomalies = Vec::new();
    let image_size = image.image_size()?;
    let file_size = u32::try_from(image.data().len())
        .map_err(|_| DiagnosticsError::Overflow("converting PE file size"))?;
    let characteristics = image.read_u16(image.file_header_offset() + 18)?;

    if format::machine_name(image.machine()).is_none() {
        anomalies.push(image_anomaly(
            ImageAnomalyKind::UnknownMachine,
            ImageAnomalySeverity::Warning,
            format!("machine 0x{:x} is not recognized by br3k", image.machine()),
        ));
    }

    if characteristics & format::IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        anomalies.push(image_anomaly(
            ImageAnomalyKind::NonExecutableImage,
            ImageAnomalySeverity::Warning,
            "IMAGE_FILE_EXECUTABLE_IMAGE is not set".to_string(),
        ));
    }

    inspect_sections(image, sections, image_size, file_size, &mut anomalies);
    inspect_entry_point(image, sections, &mut anomalies)?;
    inspect_data_directories(image, sections, image_size, &mut anomalies)?;
    inspect_import_presence(image, &mut anomalies);
    inspect_bound_imports(image, mapped_layout, &mut anomalies);

    Ok(anomalies)
}

fn inspect_bound_imports(image: &Image, mapped_layout: bool, anomalies: &mut Vec<ImageAnomaly>) {
    let result = if mapped_layout { image.mapped_bound_imports() } else { image.bound_imports() };
    if let Err(error) = result {
        let mut anomaly = image_anomaly(
            ImageAnomalyKind::InvalidBoundImportDirectory,
            ImageAnomalySeverity::Warning,
            error.to_string(),
        );
        anomaly.directory_index = Some(format::PE_DIRECTORY_ENTRY_BOUND_IMPORT);
        anomaly.directory_name = Some(format::PE_DATA_DIRECTORY_NAMES[format::PE_DIRECTORY_ENTRY_BOUND_IMPORT].to_string());
        if let Ok(directory) = image.data_directory(format::PE_DIRECTORY_ENTRY_BOUND_IMPORT) {
            anomaly.rva = Some(directory.virtual_address);
            anomaly.size = Some(directory.size);
        }
        anomalies.push(anomaly);
    }
}

fn inspect_sections(
    image: &Image,
    sections: &[SectionInfo],
    image_size: u32,
    file_size: u32,
    anomalies: &mut Vec<ImageAnomaly>,
) {
    for section in sections {
        if section.virtual_size == 0 && section.raw_size == 0 {
            anomalies.push(section_anomaly(
                ImageAnomalyKind::SectionZeroSize,
                ImageAnomalySeverity::Warning,
                section,
                None,
                Some(0),
                "section has zero virtual and raw size".to_string(),
            ));
        }

        let section_size = format::section_size(section);
        match checked_range_u32(section.virtual_address, section_size) {
            Some((_, end)) if end > image_size as u64 => {
                anomalies.push(section_anomaly(
                    ImageAnomalyKind::SectionVirtualOutsideImage,
                    ImageAnomalySeverity::Suspicious,
                    section,
                    Some(section.virtual_address),
                    Some(section_size),
                    format!("section extends past SizeOfImage 0x{image_size:x}"),
                ));
            }
            None => {
                anomalies.push(section_anomaly(
                    ImageAnomalyKind::SectionVirtualRangeOverflow,
                    ImageAnomalySeverity::Suspicious,
                    section,
                    Some(section.virtual_address),
                    Some(section_size),
                    "section virtual range overflows u32".to_string(),
                ));
            }
            Some(_) => {}
        }

        if section.raw_size != 0 {
            match checked_range_u32(section.raw_offset, section.raw_size) {
                Some((start, end)) => {
                    if start < image.size_of_headers() as u64 {
                        anomalies.push(section_anomaly(
                            ImageAnomalyKind::SectionRawBeforeHeaders,
                            ImageAnomalySeverity::Warning,
                            section,
                            Some(section.raw_offset),
                            Some(section.raw_size),
                            "section raw data starts before SizeOfHeaders".to_string(),
                        ));
                    }
                    if end > file_size as u64 {
                        anomalies.push(section_anomaly(
                            ImageAnomalyKind::SectionRawOutOfBounds,
                            ImageAnomalySeverity::Suspicious,
                            section,
                            Some(section.raw_offset),
                            Some(section.raw_size),
                            format!("section raw data extends past file size 0x{file_size:x}"),
                        ));
                    }
                }
                None => {
                    anomalies.push(section_anomaly(
                        ImageAnomalyKind::SectionRawRangeOverflow,
                        ImageAnomalySeverity::Suspicious,
                        section,
                        Some(section.raw_offset),
                        Some(section.raw_size),
                        "section raw range overflows u32".to_string(),
                    ));
                }
            }
        }

        if format::section_is_executable(section)
            && section.characteristics & format::IMAGE_SCN_MEM_WRITE != 0
        {
            anomalies.push(section_anomaly(
                ImageAnomalyKind::ExecutableWritableSection,
                ImageAnomalySeverity::Suspicious,
                section,
                Some(section.virtual_address),
                Some(section_size),
                "section is executable and writable".to_string(),
            ));
        }
    }

    inspect_section_overlaps(sections, anomalies);
}

fn inspect_section_overlaps(
    sections: &[SectionInfo],
    anomalies: &mut Vec<ImageAnomaly>,
) {
    for (index, section) in sections.iter().enumerate() {
        for other in sections.iter().skip(index + 1) {
            if section_ranges_overlap(
                section.virtual_address,
                format::section_size(section),
                other.virtual_address,
                format::section_size(other),
            ) {
                anomalies.push(section_anomaly(
                    ImageAnomalyKind::SectionVirtualOverlap,
                    ImageAnomalySeverity::Suspicious,
                    section,
                    Some(section.virtual_address),
                    Some(format::section_size(section)),
                    format!("section virtual range overlaps {}", other.name),
                ));
            }

            if section.raw_size != 0
                && other.raw_size != 0
                && section_ranges_overlap(section.raw_offset, section.raw_size, other.raw_offset, other.raw_size)
            {
                anomalies.push(section_anomaly(
                    ImageAnomalyKind::SectionRawOverlap,
                    ImageAnomalySeverity::Suspicious,
                    section,
                    Some(section.raw_offset),
                    Some(section.raw_size),
                    format!("section raw range overlaps {}", other.name),
                ));
            }
        }
    }
}

fn inspect_entry_point(
    image: &Image,
    sections: &[SectionInfo],
    anomalies: &mut Vec<ImageAnomaly>,
) -> Result<(), DiagnosticsError> {
    let entry_point = image.entry_point()?;
    if entry_point != 0 && section_for_rva(sections, entry_point).is_none() {
        anomalies.push(image_anomaly_with_location(
            ImageAnomalyKind::EntryPointOutsideSections,
            ImageAnomalySeverity::Suspicious,
            Some(entry_point),
            None,
            format!("entry point RVA 0x{entry_point:x} is not inside any section"),
        ));
    }

    Ok(())
}

fn inspect_data_directories(
    image: &Image,
    sections: &[SectionInfo],
    image_size: u32,
    anomalies: &mut Vec<ImageAnomaly>,
) -> Result<(), DiagnosticsError> {
    for (index, name) in format::PE_DATA_DIRECTORY_NAMES.iter().enumerate() {
        let Ok(directory) = image.data_directory(index) else {
            continue;
        };
        if directory.is_empty() || index == format::PE_DIRECTORY_ENTRY_SECURITY {
            continue;
        }

        let Some((_, end)) = checked_range_u32(directory.virtual_address, directory.size) else {
            anomalies.push(directory_anomaly(
                ImageAnomalyKind::DataDirectoryRangeOverflow,
                ImageAnomalySeverity::Suspicious,
                index,
                *name,
                directory,
                "data directory range overflows u32".to_string(),
            ));
            continue;
        };
        if end > image_size as u64 {
            anomalies.push(directory_anomaly(
                ImageAnomalyKind::DataDirectoryOutsideImage,
                ImageAnomalySeverity::Suspicious,
                index,
                *name,
                directory,
                format!("data directory extends past SizeOfImage 0x{image_size:x}"),
            ));
        }
        if directory.virtual_address >= image.size_of_headers()
            && !range_inside_sections(sections, directory.virtual_address, directory.size)
        {
            anomalies.push(directory_anomaly(
                ImageAnomalyKind::DataDirectoryOutsideSections,
                ImageAnomalySeverity::Warning,
                index,
                *name,
                directory,
                "data directory is not covered by any section".to_string(),
            ));
        }
    }

    Ok(())
}

fn inspect_import_presence(
    image: &Image,
    anomalies: &mut Vec<ImageAnomaly>,
) {
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
        anomalies.push(image_anomaly(
            ImageAnomalyKind::MissingImportDirectory,
            ImageAnomalySeverity::Suspicious,
            "Import and IAT directories are empty".to_string(),
        ));
    }
}

fn image_anomaly(
    kind: ImageAnomalyKind,
    severity: ImageAnomalySeverity,
    message: String,
) -> ImageAnomaly {
    image_anomaly_with_location(kind, severity, None, None, message)
}

fn image_anomaly_with_location(
    kind: ImageAnomalyKind,
    severity: ImageAnomalySeverity,
    rva: Option<u32>,
    size: Option<u32>,
    message: String,
) -> ImageAnomaly {
    ImageAnomaly {
        kind,
        severity,
        section_name: None,
        directory_index: None,
        directory_name: None,
        rva,
        size,
        message,
    }
}

fn section_anomaly(
    kind: ImageAnomalyKind,
    severity: ImageAnomalySeverity,
    section: &SectionInfo,
    rva: Option<u32>,
    size: Option<u32>,
    message: String,
) -> ImageAnomaly {
    ImageAnomaly {
        kind,
        severity,
        section_name: Some(section.name.clone()),
        directory_index: None,
        directory_name: None,
        rva,
        size,
        message,
    }
}

fn directory_anomaly(
    kind: ImageAnomalyKind,
    severity: ImageAnomalySeverity,
    index: usize,
    name: &str,
    directory: DataDirectory,
    message: String,
) -> ImageAnomaly {
    ImageAnomaly {
        kind,
        severity,
        section_name: None,
        directory_index: Some(index),
        directory_name: Some(name.to_string()),
        rva: Some(directory.virtual_address),
        size: Some(directory.size),
        message,
    }
}

fn checked_range_u32(
    start: u32,
    size: u32,
) -> Option<(u64, u64)> {
    let end = start.checked_add(size)?;
    Some((start as u64, end as u64))
}

fn section_ranges_overlap(
    lhs_start: u32,
    lhs_size: u32,
    rhs_start: u32,
    rhs_size: u32,
) -> bool {
    let Some((lhs_start, lhs_end)) = checked_range_u32(lhs_start, lhs_size) else {
        return false;
    };
    let Some((rhs_start, rhs_end)) = checked_range_u32(rhs_start, rhs_size) else {
        return false;
    };

    lhs_start < rhs_end && rhs_start < lhs_end
}

fn range_inside_sections(
    sections: &[SectionInfo],
    rva: u32,
    size: u32,
) -> bool {
    let Some((start, end)) = checked_range_u32(rva, size) else {
        return false;
    };

    sections.iter().any(|section| {
        let Some((section_start, section_end)) = checked_range_u32(
            section.virtual_address,
            format::section_size(section),
        ) else {
            return false;
        };

        start >= section_start && end <= section_end
    })
}

fn section_for_rva(
    sections: &[SectionInfo],
    rva: u32,
) -> Option<&SectionInfo> {
    sections
        .iter()
        .find(|section| {
            let Some((start, end)) = checked_range_u32(
                section.virtual_address,
                format::section_size(section),
            ) else {
                return false;
            };

            rva as u64 >= start && (rva as u64) < end
        })
}
