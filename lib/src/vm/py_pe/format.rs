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
#[py_api]
#[pyclass(module = "br3k.pe.headers", name = "FileHeader")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeFileHeader {
    /// COFF machine identifier from the parsed header.
    #[pymember]
    machine: u16,
    /// Architecture display name.
    #[pymember]
    machine_name: PyStrRef,
    /// Number of section records described by the result.
    #[pymember]
    section_count: u16,
    /// Declared optional-header size in bytes.
    #[pymember]
    optional_header_size: u16,
    /// Optional-header magic distinguishing PE32 and PE32+.
    #[pymember]
    optional_magic: u16,
    /// Raw COFF file characteristic flags.
    #[pymember]
    characteristics: u16,
    /// Whether the file-header DLL flag is set.
    #[pymember]
    is_dll: bool,
    /// Section-table byte offset in the supplied buffer or scanned allocation.
    #[pymember]
    section_table_offset: PyRef<PyInt>,
    /// Cached section records; repeated access retains the Python list identity.
    #[pyi(ty = "list[br3k.pe.headers.Section]")]
    #[pymember]
    sections: PyListRef,
}

#[pyclass]
impl PeFileHeader {}

/// PE-shaped header evidence found in a memory chunk, with allocation-relative offsets.
#[py_api]
#[pyclass(module = "br3k.pe.headers", name = "Artifact")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeHeaderArtifact {
    kind: HeaderArtifactKind,
    /// Absolute virtual address of the detected artifact.
    #[pymember]
    address: u64,
    /// Artifact offset in bytes from the scan's allocation base.
    #[pymember]
    offset: u64,
    /// Heuristic confidence score for the header-shaped evidence.
    #[pymember]
    score: u32,
    /// Number of section records described by the result.
    #[pymember]
    section_count: PyRef<PyInt>,
    /// Cached section records; repeated access retains the Python list identity.
    #[pyi(ty = "list[br3k.pe.headers.Section]")]
    #[pymember]
    sections: PyListRef,
    /// PE machine identifier; optional when no reliable file header was recovered.
    #[pymember]
    machine: Option<PyRef<PyInt>>,
    /// Architecture display name; optional when the machine is unknown.
    #[pymember]
    machine_name: Option<PyStrRef>,
    /// Whether the file-header DLL flag is set; optional when the header is unavailable.
    #[pymember]
    is_dll: Option<PyRef<PyBool>>,
    /// Section-table byte offset in the supplied buffer or scanned allocation.
    #[pymember]
    section_table_offset: Option<PyRef<PyInt>>,
    /// Recovered DOS e_lfanew value, when available.
    #[pymember]
    e_lfanew: Option<PyRef<PyInt>>,
}

#[pyclass]
impl PeHeaderArtifact {
    /// Typed classification of the surviving header evidence.
    #[pygetset]
    fn kind(zelf: &Py<Self>, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::format::HeaderArtifactKind>> {
        PyEnumValue::new(zelf.kind, vm)
    }
}

/// Mapped image bytes with synthesized headers; reconstructed metadata is not original provenance.
#[pyclass(module = "br3k.pe.headers", name = "SyntheticImage")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeSyntheticImage {
    /// Synthesized image bytes in mapped layout.
    #[pymember]
    data: PyRef<PyBytes>,
    /// Image base assigned to the synthesized mapped image.
    #[pymember]
    image_base: u64,
    /// Prefix shift used when placing synthetic headers; currently zero for in-place synthesis.
    #[pymember]
    header_prefix: u32,
    /// Entry-point RVA chosen during synthesis.
    #[pymember]
    entry_point: u32,
    /// Synthesized SizeOfImage in bytes.
    #[pymember]
    image_size: u32,
}

#[pyclass]
impl PeSyntheticImage {}

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
        machine_name: vm.ctx.new_str(header.machine_name),
        section_count: header.section_count,
        optional_header_size: header.optional_header_size,
        optional_magic: header.optional_magic,
        characteristics: header.characteristics,
        is_dll: header.is_dll,
        section_table_offset: vm.ctx.new_int(header.section_table_offset),
        sections: sections_to_py(header.sections, vm).into(),
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
        section_count: vm.ctx.new_int(artifact.sections.len()),
        sections: sections.into(),
        machine: artifact.machine.map(|value| vm.ctx.new_int(value)),
        machine_name: artifact.machine_name.map(|value| vm.ctx.new_str(value)),
        is_dll: artifact.is_dll.map(|value| vm.ctx.new_bool(value)),
        section_table_offset: artifact.section_table_offset.map(|value| vm.ctx.new_int(value)),
        e_lfanew: artifact.e_lfanew.map(|value| vm.ctx.new_int(value)),
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
