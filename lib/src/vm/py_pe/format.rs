use crate::vm::prelude::*;

use crate::pe::image::SectionInfo;
use crate::pe::format as raw_format;
use crate::pe::format::HeaderArtifactKind;
use crate::vm::py_pe::image::{section_info_to_py, PeSection};

#[derive(FromArgs)]
pub struct SectionNameArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(any)]
    offset: usize,
}

#[derive(FromArgs)]
pub struct ParseSectionHeaderArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(any)]
    offset: usize,
}

#[derive(FromArgs)]
pub struct ParseSectionTableArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(any)]
    offset: usize,
    #[pyarg(any, optional)]
    count: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct ParseFileHeaderArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(any)]
    offset: usize,
}

#[derive(FromArgs)]
pub struct ScanHeaderArtifactsArgs {
    #[pyarg(any)]
    data: PyRef<PyBytes>,
    #[pyarg(any)]
    chunk_base: u64,
    #[pyarg(any)]
    allocation_base: u64,
}

#[derive(FromArgs)]
pub struct ImageSizeFromSectionsArgs {
    #[pyarg(any)]
    sections: Vec<PyRef<PeSection>>,
    #[pyarg(any, optional)]
    fallback_size: OptionalArg<usize>,
}

#[derive(FromArgs)]
pub struct FirstExecutableSectionRvaArgs {
    #[pyarg(any)]
    sections: Vec<PyRef<PeSection>>,
}

#[derive(FromArgs)]
pub struct SynthesizeMappedImageArgs {
    #[pyarg(any)]
    raw_data: PyRef<PyBytes>,
    #[pyarg(any)]
    image_base: u64,
    #[pyarg(any)]
    sections: Vec<PyRef<PeSection>>,
    #[pyarg(named, optional)]
    machine: OptionalArg<PyObjectRef>,
    #[pyarg(named, optional)]
    is_dll: OptionalArg<bool>,
    #[pyarg(named, optional)]
    entry_point_rva: OptionalArg<u32>,
    #[pyarg(named, optional)]
    image_size: OptionalArg<u32>,
}

/// Parsed COFF/optional-header metadata and section records from an explicit buffer offset.
#[pyclass(module = "br3k.pe.headers", name = "FileHeader")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeFileHeader {
    machine: u16,
    machine_name: String,
    section_count: u16,
    optional_header_size: u16,
    optional_magic: u16,
    characteristics: u16,
    is_dll: bool,
    section_table_offset: usize,
    sections: PyListOf<PyRef<super::sections::PeSection>>,
}

#[pyclass]
impl PeFileHeader {
    /// COFF machine identifier from the parsed header.
    #[pygetset]
    fn machine(&self) -> u16 {
        self.machine
    }

    /// Architecture display name.
    #[pygetset]
    fn machine_name(&self) -> String {
        self.machine_name.clone()
    }

    /// Number of section records described by the result.
    #[pygetset]
    fn section_count(&self) -> u16 {
        self.section_count
    }

    /// Declared optional-header size in bytes.
    #[pygetset]
    fn optional_header_size(&self) -> u16 {
        self.optional_header_size
    }

    /// Optional-header magic distinguishing PE32 and PE32+.
    #[pygetset]
    fn optional_magic(&self) -> u16 {
        self.optional_magic
    }

    /// Raw COFF file characteristic flags.
    #[pygetset]
    fn characteristics(&self) -> u16 {
        self.characteristics
    }

    /// Whether the file-header DLL flag is set.
    #[pygetset]
    fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// Section-table byte offset in the supplied buffer or scanned allocation.
    #[pygetset]
    fn section_table_offset(&self) -> usize {
        self.section_table_offset
    }

    /// Cached section records; repeated access retains the Python list identity.
    #[pygetset]
    fn sections(&self) -> PyListOf<PyRef<super::sections::PeSection>> {
        self.sections.clone()
    }
}

/// PE-shaped header evidence found in a memory chunk, with allocation-relative offsets.
#[pyclass(module = "br3k.pe.headers", name = "Artifact")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHeaderArtifact {
    kind: HeaderArtifactKind,
    address: u64,
    offset: u64,
    score: u32,
    section_count: usize,
    sections: PyListOf<PyRef<super::sections::PeSection>>,
    machine: Option<u16>,
    machine_name: Option<String>,
    is_dll: Option<bool>,
    section_table_offset: Option<u64>,
    e_lfanew: Option<u32>,
}

#[pyclass]
impl PeHeaderArtifact {
    /// Typed classification of the surviving header evidence.
    #[pygetset]
    fn kind(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::format::HeaderArtifactKind>> {
        PyEnumValue::new(self.kind, vm)
    }

    /// Absolute virtual address of the detected artifact.
    #[pygetset]
    fn address(&self) -> u64 {
        self.address
    }

    /// Artifact offset in bytes from the scan's allocation base.
    #[pygetset]
    fn offset(&self) -> u64 {
        self.offset
    }

    /// Heuristic confidence score for the header-shaped evidence.
    #[pygetset]
    fn score(&self) -> u32 {
        self.score
    }

    /// Number of section records described by the result.
    #[pygetset]
    fn section_count(&self) -> usize {
        self.section_count
    }

    /// Cached section records; repeated access retains the Python list identity.
    #[pygetset]
    fn sections(&self) -> PyListOf<PyRef<super::sections::PeSection>> {
        self.sections.clone()
    }

    /// PE machine identifier; optional when no reliable file header was recovered.
    #[pygetset]
    fn machine(&self) -> Option<u16> {
        self.machine
    }

    /// Architecture display name; optional when the machine is unknown.
    #[pygetset]
    fn machine_name(&self) -> Option<String> {
        self.machine_name.clone()
    }

    /// Whether the file-header DLL flag is set; optional when the header is unavailable.
    #[pygetset]
    fn is_dll(&self) -> Option<bool> {
        self.is_dll
    }

    /// Section-table byte offset in the supplied buffer or scanned allocation.
    #[pygetset]
    fn section_table_offset(&self) -> Option<u64> {
        self.section_table_offset
    }

    /// Recovered DOS e_lfanew value, when available.
    #[pygetset]
    fn e_lfanew(&self) -> Option<u32> {
        self.e_lfanew
    }
}

/// Mapped image bytes with synthesized headers; reconstructed metadata is not original provenance.
#[pyclass(module = "br3k.pe.headers", name = "SyntheticImage")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSyntheticImage {
    data: PyRef<PyBytes>,
    image_base: u64,
    header_prefix: u32,
    entry_point: u32,
    image_size: u32,
}

#[pyclass]
impl PeSyntheticImage {
    /// Image base assigned to the synthesized mapped image.
    #[pygetset]
    fn image_base(&self) -> u64 { self.image_base }

    /// Prefix shift used when placing synthetic headers; currently zero for in-place synthesis.
    #[pygetset]
    fn header_prefix(&self) -> u32 { self.header_prefix }
    /// Synthesized image bytes in mapped layout.
    #[pygetset]
    fn data(&self) -> PyRef<PyBytes> {
        self.data.clone()
    }

    /// Entry-point RVA chosen during synthesis.
    #[pygetset]
    fn entry_point(&self) -> u32 {
        self.entry_point
    }

    /// Synthesized SizeOfImage in bytes.
    #[pygetset]
    fn image_size(&self) -> u32 {
        self.image_size
    }
}

/// Architecture display name; optional when the machine is unknown.
pub fn machine_name(machine: u16) -> String {
    raw_format::machine_name(machine)
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{machine:x}"))
}

pub fn machine_value(machine: PyStrRef, vm: &VirtualMachine) -> PyResult<u16> {
    raw_format::machine_value(&machine.to_string())
        .ok_or_else(|| vm.new_value_error(format!("Unsupported PE machine name: {machine}")))
}

pub fn data_directory_name(index: usize) -> Option<&'static str> {
    raw_format::PE_DATA_DIRECTORY_NAMES.get(index).copied()
}

pub fn section_name(args: SectionNameArgs) -> Option<String> {
    raw_format::section_name(args.data.as_bytes(), args.offset)
}

pub fn parse_section_header(args: ParseSectionHeaderArgs, vm: &VirtualMachine) -> Option<PyRef<super::sections::PeSection>> {
    raw_format::parse_section_header(args.data.as_bytes(), args.offset)
        .map(|section| section_info_to_py(section, vm))
}

pub fn parse_section_table(args: ParseSectionTableArgs, vm: &VirtualMachine) -> Option<PyListOf<PyRef<super::sections::PeSection>>> {
    raw_format::parse_section_table(args.data.as_bytes(), args.offset, args.count.present())
        .map(|sections| sections_to_py(sections, vm))
}

pub fn parse_file_header(args: ParseFileHeaderArgs, vm: &VirtualMachine) -> Option<PyRef<PeFileHeader>> {
    raw_format::parse_file_header(args.data.as_bytes(), args.offset)
        .map(|header| file_header_to_py(header, vm))
}

pub fn scan_header_artifacts(args: ScanHeaderArtifactsArgs, vm: &VirtualMachine) -> PyListOf<PyRef<PeHeaderArtifact>> {
    let artifacts = raw_format::scan_header_artifacts(args.data.as_bytes(), args.chunk_base, args.allocation_base)
        .into_iter()
        .map(|artifact| header_artifact_to_py(artifact, vm))
        .collect::<Vec<_>>();

    PyListOf::new(artifacts, vm)
}

pub fn image_size_from_sections(args: ImageSizeFromSectionsArgs, vm: &VirtualMachine) -> PyResult<u32> {
    let sections = sections_from_py(&args.sections);

    raw_format::image_size_from_sections(&sections, args.fallback_size.unwrap_or(0))
        .map_err(map_to_py_value_error(vm, "Unable to compute PE image size from sections"))
}

pub fn first_executable_section_rva(args: FirstExecutableSectionRvaArgs) -> u32 {
    let sections = sections_from_py(&args.sections);

    raw_format::first_executable_section_rva(&sections)
}

pub fn synthesize_mapped_image(args: SynthesizeMappedImageArgs, vm: &VirtualMachine) -> PyResult<PyRef<PeSyntheticImage>> {
    let sections = sections_from_py(&args.sections);
    let machine = machine_hint(args.machine, vm)?;
    let image = raw_format::synthesize_mapped_image(
        args.raw_data.as_bytes(),
        args.image_base,
        &sections,
        machine.as_deref(),
        args.is_dll.unwrap_or(true),
        args.entry_point_rva.present(),
        args.image_size.present(),
    )
    .map_err(map_to_py_value_error(vm, "Unable to synthesize mapped PE image"))?;

    Ok(synthetic_image_to_py(image, vm))
}

pub fn file_header_to_py(header: raw_format::FileHeaderInfo, vm: &VirtualMachine) -> PyRef<PeFileHeader> {
    PeFileHeader {
        machine: header.machine,
        machine_name: header.machine_name.to_string(),
        section_count: header.section_count,
        optional_header_size: header.optional_header_size,
        optional_magic: header.optional_magic,
        characteristics: header.characteristics,
        is_dll: header.is_dll,
        section_table_offset: header.section_table_offset,
        sections: sections_to_py(header.sections, vm),
    }
    .into_ref(&vm.ctx)
}

pub fn header_artifact_to_py(artifact: raw_format::HeaderArtifact, vm: &VirtualMachine) -> PyRef<PeHeaderArtifact> {
    let sections = sections_to_py(artifact.sections.clone(), vm);

    PeHeaderArtifact {
        kind: artifact.kind,
        address: artifact.address,
        offset: artifact.offset,
        score: artifact.score,
        section_count: artifact.sections.len(),
        sections,
        machine: artifact.machine,
        machine_name: artifact.machine_name.map(str::to_string),
        is_dll: artifact.is_dll,
        section_table_offset: artifact.section_table_offset,
        e_lfanew: artifact.e_lfanew,
    }
    .into_ref(&vm.ctx)
}

pub(crate) fn synthetic_image_to_py(image: raw_format::SyntheticImage, vm: &VirtualMachine) -> PyRef<PeSyntheticImage> {
    PeSyntheticImage {
        data: vm.ctx.new_bytes(image.data),
        image_base: image.image_base,
        header_prefix: image.header_prefix,
        entry_point: image.entry_point,
        image_size: image.image_size,
    }
    .into_ref(&vm.ctx)
}

fn sections_to_py(sections: Vec<SectionInfo>, vm: &VirtualMachine) -> PyListOf<PyRef<super::sections::PeSection>> {
    let sections = sections
        .into_iter()
        .map(|section| section_info_to_py(section, vm))
        .collect::<Vec<_>>();

    PyListOf::new(sections, vm)
}

fn sections_from_py(sections: &[PyRef<PeSection>]) -> Vec<SectionInfo> {
    sections
        .iter()
        .map(|section| section.to_section_info())
        .collect()
}

fn machine_hint(machine: OptionalArg<PyObjectRef>, vm: &VirtualMachine) -> PyResult<Option<String>> {
    let Some(machine) = machine.present() else {
        return Ok(None);
    };
    if vm.is_none(&machine) {
        return Ok(None);
    }
    if let Ok(machine) = PyStrRef::try_from_object(vm, machine.clone()) {
        return Ok(Some(machine.to_string()));
    }
    if let Ok(machine) = u16::try_from_object(vm, machine) {
        return raw_format::machine_name(machine)
            .map(|name| Some(name.to_string()))
            .ok_or_else(|| vm.new_value_error(format!("Unsupported PE machine value: 0x{machine:x}")));
    }

    Err(vm.new_type_error("PE machine hint must be a string, integer, or None".to_string()))
}
