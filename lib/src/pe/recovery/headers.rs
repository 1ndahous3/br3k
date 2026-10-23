use crate::pe::{capture::Capture, format::{self, HeaderArtifactKind}, headers::{self, HeaderError}, image::{Image, MissingRange}};

#[derive(Clone, Debug)]
pub struct Recovery {
    pub image: Image,
    pub header_prefix: u32,
    pub section_source: headers::SectionSource,
    pub directories: Vec<headers::DirectoryRecovery>,
    pub synthetic: bool,
}

/// Reconstruct analysis headers from captured evidence, without reacquiring or rescanning a process.
pub fn recover(capture: &Capture, machine: &str) -> Result<Recovery, HeaderError> {
    let mut artifacts = format::scan_header_artifacts(&capture.data[..capture.data.len().min(0x10000)], capture.base, capture.base);
    artifacts.retain(|artifact| {
        let end = artifact.section_table_offset.map_or(artifact.offset + 24, |offset| offset + artifact.sections.len() as u64 * format::SECTION_HEADER_SIZE as u64);
        !capture.failures.iter().any(|failure| (failure.range.rva as u64) < end && artifact.offset < failure.range.rva as u64 + failure.range.size as u64)
    });
    let artifact = artifacts.iter().max_by_key(|artifact| artifact.score);
    let sections = artifact.map(|artifact| artifact.sections.as_slice()).unwrap_or_default();
    let source_offset = artifact.filter(|artifact| artifact.kind == HeaderArtifactKind::MzPe).map_or(0, |artifact| artifact.offset as usize);
    let source = capture.data.get(source_offset..).ok_or(HeaderError::RegionLayout("artifact outside capture"))?;
    let machine = artifact.and_then(|artifact| artifact.machine_name).unwrap_or(machine);
    let source_base = capture.base.checked_add(source_offset as u64).ok_or(HeaderError::RegionLayout("artifact address overflow"))?;
    let source_missing = capture.failures.iter().filter_map(|failure| {
        let start = (failure.range.rva as usize).max(source_offset);
        let end = failure.range.rva as usize + failure.range.size as usize;
        (end > start).then(|| MissingRange { rva: (start - source_offset) as u32, size: (end - start) as u32 })
    }).collect::<Vec<_>>();
    if source_offset != 0 && let Ok(image) = Image::from_mapped(source.to_vec(), source_base, source_missing) {
        return Ok(Recovery { image, header_prefix: 0, section_source: headers::SectionSource::Headers, directories: Vec::new(), synthetic: false });
    }
    let synthetic = if sections.is_empty() {
        headers::synthesize_from_regions(&capture.data, capture.base, &capture.regions, machine, true, None)?
    } else {
        format::synthesize_mapped_image(source, source_base, sections, Some(machine), true, Some(0), None)?
    };
    let mut image = Image::parse(synthetic.data)?;
    let mut directories = Vec::new();
    if synthetic.header_prefix == 0 {
        let offset = artifact.and_then(|artifact| match artifact.kind {
            HeaderArtifactKind::MzPe => artifact.e_lfanew.map(|offset| offset as usize + 4),
            HeaderArtifactKind::NtHeaders => Some(artifact.offset as usize + 4),
            HeaderArtifactKind::FileHeader => Some(artifact.offset as usize),
            HeaderArtifactKind::SectionTable => None,
        });
        if let Some(offset) = offset { directories = image.salvage_directories(source, offset)?; }
    }
    let mut missing = Vec::new();
    for failure in &capture.failures {
        let start = (failure.range.rva as usize).max(source_offset);
        let end = failure.range.rva as usize + failure.range.size as usize;
        if end <= start { continue; }
        let rva = u32::try_from(start - source_offset).ok().and_then(|rva| rva.checked_add(synthetic.header_prefix))
            .ok_or(HeaderError::RegionLayout("missing range overflow"))?;
        missing.push(MissingRange { rva, size: (end - start) as u32 });
    }
    let image = Image::from_mapped(image.into_data(), synthetic.image_base, missing)?;
    Ok(Recovery {
        image, header_prefix: synthetic.header_prefix, directories, synthetic: true,
        section_source: if sections.is_empty() { headers::SectionSource::MemoryRegions } else { headers::SectionSource::Headers },
    })
}
