use super::types::{
    ImportCodeReference, ImportCodeReferenceKind, ImportCodeTrace, ImportCodeTraceOptions, ImportError,
};
use super::util::{read_iat_pointer, validate_pointer_size};
use crate::pe::exports::ExportSymbol;
use crate::pe::embedded;
use crate::pe::image::{Image, SectionInfo};

use std::collections::{BTreeSet, VecDeque};
use std::ops::Range;

pub(super) trait ImportSymbolResolver {
    fn resolve_import_address(&self, address: u64) -> Result<Option<ExportSymbol>, ImportError>;
}

pub(super) struct MappedThunkResolver<'a, R> {
    image_data: &'a [u8],
    image_base: u64,
    machine: ImportCodeMachine,
    pointer_size: usize,
    max_depth: usize,
    direct_resolver: R,
    excluded: Vec<Range<usize>>,
}

impl<'a, R: ImportSymbolResolver> MappedThunkResolver<'a, R> {
    pub(super) fn new(
        image_data: &'a [u8],
        image_base: Option<u64>,
        pointer_size: usize,
        max_depth: usize,
        direct_resolver: R,
    ) -> Result<Self, ImportError> {
        validate_pointer_size(pointer_size)?;
        let image = Image::parse(image_data.to_vec())?;
        let image_base = match image_base {
            Some(image_base) => image_base,
            None => image.image_base()?,
        };
        let machine = ImportCodeMachine::from_pe_machine(image.machine())?;
        let excluded = embedded::mapped_exclusions(image_data);

        Ok(Self {
            image_data,
            image_base,
            machine,
            pointer_size,
            max_depth,
            direct_resolver,
            excluded,
        })
    }

    fn next_thunk_address(&self, address: u64) -> Result<Option<u64>, ImportError> {
        let Some((_, offset)) = mapped_address_to_offset(self.image_data, self.image_base, address) else {
            return Ok(None);
        };
        if embedded::intersects(&self.excluded, offset, 1) { return Ok(None); }

        match self.machine {
            ImportCodeMachine::X86 => x86_next_thunk_address(self.image_data, self.image_base, offset, address, self.pointer_size, false),
            ImportCodeMachine::X64 => x86_next_thunk_address(self.image_data, self.image_base, offset, address, self.pointer_size, true),
            ImportCodeMachine::Arm64 => arm64_next_thunk_address(self.image_data, self.image_base, offset, address),
        }
    }
}

impl<R: ImportSymbolResolver> ImportSymbolResolver for MappedThunkResolver<'_, R> {
    fn resolve_import_address(&self, address: u64) -> Result<Option<ExportSymbol>, ImportError> {
        let mut address = address;
        let mut visited = BTreeSet::new();

        for depth in 0..=self.max_depth {
            if let Some(symbol) = self.direct_resolver.resolve_import_address(address)? {
                return Ok(Some(symbol));
            }
            if depth == self.max_depth || !visited.insert(address) {
                return Ok(None);
            }

            let Some(next_address) = self.next_thunk_address(address)? else {
                return Ok(None);
            };
            address = next_address;
        }

        Ok(None)
    }
}

pub(super) fn scan_mapped_export_code_references_with_resolver<R: ImportSymbolResolver>(
    image_data: &[u8],
    image_base: Option<u64>,
    resolver: &R,
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let machine = ImportCodeMachine::from_pe_machine(image.machine())?;
    let pointer_size = image.pointer_size();
    let mut references = Vec::new();
    let excluded = embedded::mapped_exclusions(image_data);

    for section in image.sections()? {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let Some((section_rva, section_data)) = mapped_section_data(image_data, section)? else {
            continue;
        };

        let range = section_rva as usize..section_rva as usize + section_data.len();
        for range in embedded::included_ranges(range, &excluded) {
            scan_code_range(&mut references, image_data, range, image_base, pointer_size, machine, resolver)?;
        }
    }

    references.retain(|reference| reference.iat_rva.is_none_or(|rva| !embedded::intersects(&excluded, rva as usize, pointer_size)));
    sort_and_dedup_references(&mut references);

    Ok(references)
}

pub(super) fn scan_mapped_export_code_references_in_range_with_resolver<R: ImportSymbolResolver>(
    image_data: &[u8],
    image_base: Option<u64>,
    rva: u32,
    size: usize,
    resolver: &R,
) -> Result<Vec<ImportCodeReference>, ImportError> {
    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let machine = ImportCodeMachine::from_pe_machine(image.machine())?;
    let pointer_size = image.pointer_size();
    let start = rva as usize;

    if size == 0 || start >= image_data.len() {
        return Ok(Vec::new());
    }

    let end = start
        .checked_add(size)
        .ok_or(ImportError::Overflow("sizing mapped code scan range"))?
        .min(image_data.len());
    let mut references = Vec::new();
    let excluded = embedded::mapped_exclusions(image_data);
    for range in embedded::included_ranges(start..end, &excluded) {
        scan_code_range(&mut references, image_data, range, image_base, pointer_size, machine, resolver)?;
    }

    references.retain(|reference| reference.iat_rva.is_none_or(|rva| !embedded::intersects(&excluded, rva as usize, pointer_size)));
    sort_and_dedup_references(&mut references);
    Ok(references)
}

pub(super) fn trace_mapped_export_code_references_with_resolver<R: ImportSymbolResolver>(
    image_data: &[u8],
    image_base: Option<u64>,
    options: ImportCodeTraceOptions,
    resolver: &R,
) -> Result<ImportCodeTrace, ImportError> {
    if options.max_blocks == 0 || options.max_bytes == 0 {
        return Ok(ImportCodeTrace {
            references: Vec::new(),
            visited_blocks: 0,
            scanned_bytes: 0,
        });
    }

    let image = Image::parse(image_data.to_vec())?;
    let image_base = match image_base {
        Some(image_base) => image_base,
        None => image.image_base()?,
    };
    let machine = ImportCodeMachine::from_pe_machine(image.machine())?;
    let pointer_size = image.pointer_size();
    let sections = image.sections()?;
    let excluded = embedded::mapped_exclusions(image_data);
    let mut references = Vec::new();
    let mut queue = VecDeque::from([options.start_rva]);
    let mut visited = BTreeSet::new();
    let mut visited_blocks = 0usize;
    let mut scanned_bytes = 0usize;

    while let Some(block_rva) = queue.pop_front() {
        if visited_blocks >= options.max_blocks || scanned_bytes >= options.max_bytes || !visited.insert(block_rva) {
            continue;
        }

        if embedded::intersects(&excluded, block_rva as usize, 1) { continue; }
        let remaining = excluded.iter().filter(|range| range.start > block_rva as usize)
            .map(|range| range.start - block_rva as usize).min().unwrap_or(usize::MAX)
            .min(options.max_bytes - scanned_bytes);
        let Some(block) = trace_code_block(
            image_data,
            &sections,
            machine,
            block_rva,
            image_base,
            pointer_size,
            options.follow_calls,
            remaining,
        )? else {
            continue;
        };
        let start = block.rva as usize;
        let end = start
            .checked_add(block.size)
            .ok_or(ImportError::Overflow("sizing traced code block"))?;
        scan_code_range(&mut references, image_data, start..end, image_base, pointer_size, machine, resolver)?;

        scanned_bytes = scanned_bytes
            .checked_add(block.size)
            .ok_or(ImportError::Overflow("counting traced code bytes"))?;
        visited_blocks += 1;

        for next_rva in block.next_rvas {
            if visited.contains(&next_rva) || queue.contains(&next_rva) {
                continue;
            }

            queue.push_back(next_rva);
        }
    }

    sort_and_dedup_references(&mut references);

    references.retain(|reference| reference.iat_rva.is_none_or(|rva| !embedded::intersects(&excluded, rva as usize, pointer_size)));
    Ok(ImportCodeTrace {
        references,
        visited_blocks,
        scanned_bytes,
    })
}

fn scan_code_range<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    range: Range<usize>,
    image_base: u64,
    pointer_size: usize,
    machine: ImportCodeMachine,
    resolver: &R,
) -> Result<(), ImportError> {
    let rva = u32::try_from(range.start).map_err(|_| ImportError::Overflow("converting code range RVA"))?;
    let code = &image_data[range];
    match machine {
        ImportCodeMachine::X86 => scan_x86_code_references(references, image_data, code, rva, image_base, pointer_size, false, resolver),
        ImportCodeMachine::X64 => scan_x86_code_references(references, image_data, code, rva, image_base, pointer_size, true, resolver),
        ImportCodeMachine::Arm64 => scan_arm64_code_references(references, image_data, code, rva, image_base, resolver),
    }
}

struct TracedCodeBlock {
    rva: u32,
    size: usize,
    next_rvas: Vec<u32>,
}

fn trace_code_block(
    image_data: &[u8],
    sections: &[SectionInfo],
    machine: ImportCodeMachine,
    start_rva: u32,
    image_base: u64,
    pointer_size: usize,
    follow_calls: bool,
    max_bytes: usize,
) -> Result<Option<TracedCodeBlock>, ImportError> {
    match machine {
        ImportCodeMachine::X86 => trace_x86_code_block(image_data, sections, start_rva, image_base, pointer_size, false, follow_calls, max_bytes),
        ImportCodeMachine::X64 => trace_x86_code_block(image_data, sections, start_rva, image_base, pointer_size, true, follow_calls, max_bytes),
        ImportCodeMachine::Arm64 => trace_arm64_code_block(image_data, sections, start_rva, image_base, follow_calls, max_bytes),
    }
}

#[allow(clippy::too_many_arguments)]
fn trace_x86_code_block(
    image_data: &[u8],
    sections: &[SectionInfo],
    start_rva: u32,
    image_base: u64,
    _pointer_size: usize,
    is_x64: bool,
    follow_calls: bool,
    max_bytes: usize,
) -> Result<Option<TracedCodeBlock>, ImportError> {
    let Some((_, block)) = mapped_executable_section_data_containing_rva(image_data, sections, start_rva) else {
        return Ok(None);
    };
    let block = &block[..block.len().min(max_bytes)];
    let mut offset = 0usize;
    let mut next_rvas = Vec::new();

    while offset < block.len() {
        let instruction_rva = reference_rva(start_rva, offset)?;
        let instruction_va = image_base
            .checked_add(instruction_rva as u64)
            .ok_or(ImportError::Overflow("computing traced x86 instruction address"))?;

        if offset + 5 <= block.len() && block[offset] == 0xe8 {
            let target = x86_rel32_target(block, offset, instruction_va, is_x64)?;
            if follow_calls {
                push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            }
            offset += 5;
            continue;
        }

        if offset + 5 <= block.len() && block[offset] == 0xe9 {
            let target = x86_rel32_target(block, offset, instruction_va, is_x64)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            offset += 5;
            break;
        }

        if offset + 2 <= block.len() && block[offset] == 0xeb {
            let fallthrough = instruction_va
                .checked_add(2)
                .ok_or(ImportError::Overflow("computing traced x86 short jump fallthrough"))?;
            let target = add_x86_relative(fallthrough, block[offset + 1] as i8 as i64, is_x64, "computing traced x86 short jump target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            offset += 2;
            break;
        }

        if offset + 2 <= block.len() && (0x70..=0x7f).contains(&block[offset]) {
            let fallthrough = instruction_va
                .checked_add(2)
                .ok_or(ImportError::Overflow("computing traced x86 short conditional fallthrough"))?;
            let target = add_x86_relative(fallthrough, block[offset + 1] as i8 as i64, is_x64, "computing traced x86 short conditional target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, fallthrough)?;
            offset += 2;
            break;
        }

        if offset + 6 <= block.len() && block[offset] == 0x0f && (0x80..=0x8f).contains(&block[offset + 1]) {
            let fallthrough = instruction_va
                .checked_add(6)
                .ok_or(ImportError::Overflow("computing traced x86 near conditional fallthrough"))?;
            let target = add_x86_relative(
                fallthrough,
                read_i32(&block[offset + 2..offset + 6])? as i64,
                is_x64,
                "computing traced x86 near conditional target",
            )?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, fallthrough)?;
            offset += 6;
            break;
        }

        if matches!(block[offset], 0xc2 | 0xc3 | 0xca | 0xcb) {
            offset += if matches!(block[offset], 0xc2 | 0xca) && offset + 3 <= block.len() { 3 } else { 1 };
            break;
        }

        if offset + 2 <= block.len() && block[offset] == 0xff && block[offset + 1] == 0x25 {
            offset += 6.min(block.len() - offset);
            break;
        }

        offset += 1;
    }

    Ok(Some(TracedCodeBlock {
        rva: start_rva,
        size: offset,
        next_rvas,
    }))
}

fn trace_arm64_code_block(
    image_data: &[u8],
    sections: &[SectionInfo],
    start_rva: u32,
    image_base: u64,
    follow_calls: bool,
    max_bytes: usize,
) -> Result<Option<TracedCodeBlock>, ImportError> {
    let Some((_, block)) = mapped_executable_section_data_containing_rva(image_data, sections, start_rva) else {
        return Ok(None);
    };
    let block = &block[..block.len().min(max_bytes)];
    let mut offset = 0usize;
    let mut next_rvas = Vec::new();

    while offset + 4 <= block.len() {
        let instruction = read_u32(&block[offset..offset + 4])?;
        let instruction_rva = reference_rva(start_rva, offset)?;
        let instruction_va = image_base
            .checked_add(instruction_rva as u64)
            .ok_or(ImportError::Overflow("computing traced ARM64 instruction address"))?;

        if instruction & ARM64_BRANCH_OPCODE_MASK == ARM64_BL_OPCODE {
            let target = add_signed(instruction_va, arm64_branch_displacement(instruction), "computing traced ARM64 call target")?;
            if follow_calls {
                push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            }
            offset += 4;
            continue;
        }

        if instruction & ARM64_BRANCH_OPCODE_MASK == ARM64_B_OPCODE {
            let target = add_signed(instruction_va, arm64_branch_displacement(instruction), "computing traced ARM64 jump target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            offset += 4;
            break;
        }

        if instruction & ARM64_CONDITIONAL_BRANCH_MASK == ARM64_CONDITIONAL_BRANCH_OPCODE {
            let fallthrough = instruction_va
                .checked_add(4)
                .ok_or(ImportError::Overflow("computing traced ARM64 conditional fallthrough"))?;
            let target = add_signed(instruction_va, arm64_conditional_branch_displacement(instruction), "computing traced ARM64 conditional target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, fallthrough)?;
            offset += 4;
            break;
        }

        if instruction & ARM64_COMPARE_BRANCH_MASK == ARM64_COMPARE_BRANCH_OPCODE {
            let fallthrough = instruction_va
                .checked_add(4)
                .ok_or(ImportError::Overflow("computing traced ARM64 compare branch fallthrough"))?;
            let target = add_signed(instruction_va, arm64_conditional_branch_displacement(instruction), "computing traced ARM64 compare branch target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, fallthrough)?;
            offset += 4;
            break;
        }

        if instruction & ARM64_TEST_BRANCH_MASK == ARM64_TEST_BRANCH_OPCODE {
            let fallthrough = instruction_va
                .checked_add(4)
                .ok_or(ImportError::Overflow("computing traced ARM64 test branch fallthrough"))?;
            let target = add_signed(instruction_va, arm64_test_branch_displacement(instruction), "computing traced ARM64 test branch target")?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, target)?;
            push_executable_branch_target(&mut next_rvas, image_data, sections, image_base, fallthrough)?;
            offset += 4;
            break;
        }

        if instruction & ARM64_BRANCH_REGISTER_OPCODE_MASK == ARM64_BR_OPCODE {
            offset += 4;
            break;
        }

        if instruction & ARM64_RET_MASK == ARM64_RET_OPCODE {
            offset += 4;
            break;
        }

        offset += 4;
    }

    Ok(Some(TracedCodeBlock {
        rva: start_rva,
        size: offset,
        next_rvas,
    }))
}

fn x86_rel32_target(code: &[u8], offset: usize, instruction_va: u64, is_x64: bool) -> Result<u64, ImportError> {
    let instruction_end = instruction_va
        .checked_add(5)
        .ok_or(ImportError::Overflow("computing traced x86 branch end"))?;

    add_x86_relative(
        instruction_end,
        read_i32(&code[offset + 1..offset + 5])? as i64,
        is_x64,
        "computing traced x86 branch target",
    )
}

fn push_executable_branch_target(
    targets: &mut Vec<u32>,
    image_data: &[u8],
    sections: &[SectionInfo],
    image_base: u64,
    address: u64,
) -> Result<(), ImportError> {
    let Some(rva) = executable_address_to_rva(image_data, sections, image_base, address) else {
        return Ok(());
    };

    if !targets.contains(&rva) {
        targets.push(rva);
    }

    Ok(())
}

fn executable_address_to_rva(
    image_data: &[u8],
    sections: &[SectionInfo],
    image_base: u64,
    address: u64,
) -> Option<u32> {
    if address < image_base {
        return None;
    }

    let rva = u32::try_from(address - image_base).ok()?;
    mapped_executable_section_data_containing_rva(image_data, sections, rva)?;
    Some(rva)
}

fn mapped_executable_section_data_containing_rva<'a>(
    image_data: &'a [u8],
    sections: &[SectionInfo],
    rva: u32,
) -> Option<(u32, &'a [u8])> {
    let section = sections.iter().find(|section| {
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && section_contains_rva(section, rva).unwrap_or(false)
    })?;
    let section_end = section
        .virtual_address
        .checked_add(section.virtual_size.max(section.raw_size))?
        .min(u32::try_from(image_data.len()).ok()?);
    let start = rva as usize;
    let end = section_end as usize;
    if start >= end {
        return None;
    }

    Some((rva, &image_data[start..end]))
}

fn section_contains_rva(section: &SectionInfo, rva: u32) -> Result<bool, ImportError> {
    let size = section.virtual_size.max(section.raw_size);
    let end = section
        .virtual_address
        .checked_add(size)
        .ok_or(ImportError::Overflow("sizing executable section"))?;

    Ok(rva >= section.virtual_address && rva < end)
}

fn sort_and_dedup_references(references: &mut Vec<ImportCodeReference>) {
    references.sort_by(|left, right| {
        left.reference_rva
            .cmp(&right.reference_rva)
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
            .then_with(|| left.target_address.cmp(&right.target_address))
            .then_with(|| left.iat_rva.cmp(&right.iat_rva))
    });
    references.dedup_by(|left, right| {
        left.reference_rva == right.reference_rva
            && left.kind == right.kind
            && left.target_address == right.target_address
            && left.iat_rva == right.iat_rva
    });
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ImportCodeMachine {
    X86,
    X64,
    Arm64,
}

impl ImportCodeMachine {
    pub(super) fn from_pe_machine(machine: u16) -> Result<Self, ImportError> {
        match machine {
            IMAGE_FILE_MACHINE_I386 => Ok(Self::X86),
            IMAGE_FILE_MACHINE_AMD64 => Ok(Self::X64),
            IMAGE_FILE_MACHINE_ARM64 => Ok(Self::Arm64),
            machine => Err(ImportError::UnsupportedMachine(machine)),
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn scan_x86_code_references<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    section_rva: u32,
    image_base: u64,
    pointer_size: usize,
    is_x64: bool,
    resolver: &R,
) -> Result<(), ImportError> {
    let mut offset = 0usize;

    while offset < code.len() {
        if offset + 5 <= code.len() {
            match code[offset] {
                0xe8 => push_x86_relative_reference(
                    references,
                    code,
                    offset,
                    section_rva,
                    image_base,
                    ImportCodeReferenceKind::DirectCall,
                    is_x64,
                    resolver,
                )?,
                0xe9 => push_x86_relative_reference(
                    references,
                    code,
                    offset,
                    section_rva,
                    image_base,
                    ImportCodeReferenceKind::DirectJump,
                    is_x64,
                    resolver,
                )?,
                _ => {}
            }
        }

        if offset + 6 <= code.len() && code[offset] == 0xff {
            match code[offset + 1] {
                0x15 => push_x86_indirect_reference(
                    references,
                    image_data,
                    code,
                    offset,
                    section_rva,
                    image_base,
                    pointer_size,
                    is_x64,
                    ImportCodeReferenceKind::IndirectCall,
                    resolver,
                )?,
                0x25 => push_x86_indirect_reference(
                    references,
                    image_data,
                    code,
                    offset,
                    section_rva,
                    image_base,
                    pointer_size,
                    is_x64,
                    ImportCodeReferenceKind::IndirectJump,
                    resolver,
                )?,
                _ => {}
            }
        }

        try_push_x86_immediate_register_reference(
            references,
            code,
            offset,
            section_rva,
            is_x64,
            resolver,
        )?;
        try_push_x86_memory_register_reference(
            references,
            image_data,
            code,
            offset,
            section_rva,
            image_base,
            pointer_size,
            is_x64,
            resolver,
        )?;

        offset += 1;
    }

    Ok(())
}

fn push_x86_relative_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    kind: ImportCodeReferenceKind,
    is_x64: bool,
    resolver: &R,
) -> Result<(), ImportError> {
    let reference_rva = reference_rva(section_rva, offset)?;
    let instruction_end = image_base
        .checked_add(reference_rva as u64)
        .and_then(|address| address.checked_add(5))
        .ok_or(ImportError::Overflow("computing x86 branch reference address"))?;
    let displacement = read_i32(&code[offset + 1..offset + 5])? as i64;
    let target_address = add_x86_relative(instruction_end, displacement, is_x64, "computing x86 branch target")?;

    push_resolved_code_reference(references, reference_rva, kind, target_address, None, resolver)
}

#[allow(clippy::too_many_arguments)]
fn push_x86_indirect_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    pointer_size: usize,
    is_x64: bool,
    kind: ImportCodeReferenceKind,
    resolver: &R,
) -> Result<(), ImportError> {
    let reference_rva = reference_rva(section_rva, offset)?;
    let operand = read_i32(&code[offset + 2..offset + 6])?;
    let iat_address = if is_x64 {
        let instruction_end = image_base
            .checked_add(reference_rva as u64)
            .and_then(|address| address.checked_add(6))
            .ok_or(ImportError::Overflow("computing x64 indirect branch reference address"))?;
        add_signed(instruction_end, operand as i64, "computing x64 indirect branch target")?
    } else {
        u32::from_le_bytes(operand.to_le_bytes()) as u64
    };
    let Some((iat_rva, target_address)) = read_image_pointer(image_data, image_base, iat_address, pointer_size)? else {
        return Ok(());
    };

    push_resolved_code_reference(
        references,
        reference_rva,
        kind,
        target_address,
        Some(iat_rva),
        resolver,
    )
}

fn try_push_x86_immediate_register_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    code: &[u8],
    offset: usize,
    section_rva: u32,
    is_x64: bool,
    resolver: &R,
) -> Result<(), ImportError> {
    if let Some(load) = x86_immediate_register_target(code, offset, is_x64)? {
        if let Some(kind) = x86_immediate_register_branch_kind(code, offset + load.instruction_len, load.register, is_x64) {
            let reference_rva = reference_rva(section_rva, offset)?;
            push_resolved_code_reference(references, reference_rva, kind, load.address, None, resolver)?;
        }
    }

    if !is_x64 && offset + 6 <= code.len() && code[offset] == 0x68 && code[offset + 5] == 0xc3 {
        let reference_rva = reference_rva(section_rva, offset)?;
        let target_address = read_u32(&code[offset + 1..offset + 5])? as u64;
        push_resolved_code_reference(
            references,
            reference_rva,
            ImportCodeReferenceKind::ImmediateJump,
            target_address,
            None,
            resolver,
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn try_push_x86_memory_register_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    pointer_size: usize,
    is_x64: bool,
    resolver: &R,
) -> Result<(), ImportError> {
    let reference_rva = reference_rva(section_rva, offset)?;
    let reference_address = image_base
        .checked_add(reference_rva as u64)
        .ok_or(ImportError::Overflow("computing x86 memory-register reference address"))?;
    let Some(load) = x86_memory_register_target(code, offset, reference_address, is_x64)? else {
        return Ok(());
    };
    let Some(kind) = x86_indirect_register_branch_kind(code, offset + load.instruction_len, load.register, is_x64) else {
        return Ok(());
    };
    let Some((iat_rva, target_address)) = read_image_pointer(image_data, image_base, load.address, pointer_size)? else {
        return Ok(());
    };

    push_resolved_code_reference(references, reference_rva, kind, target_address, Some(iat_rva), resolver)
}

#[derive(Clone, Copy)]
struct X86RegisterTarget {
    register: u8,
    instruction_len: usize,
    address: u64,
}

fn x86_immediate_register_target(
    code: &[u8],
    offset: usize,
    is_x64: bool,
) -> Result<Option<X86RegisterTarget>, ImportError> {
    if is_x64 && offset + 10 <= code.len() && x64_rex_w(code[offset]) && (0xb8..=0xbf).contains(&code[offset + 1]) {
        let register = (code[offset + 1] - 0xb8) | ((code[offset] & 1) << 3);
        let address = read_u64(&code[offset + 2..offset + 10])?;
        return Ok(Some(X86RegisterTarget { register, instruction_len: 10, address }));
    }

    if !is_x64 && offset + 5 <= code.len() && (0xb8..=0xbf).contains(&code[offset]) {
        let register = code[offset] - 0xb8;
        let address = read_u32(&code[offset + 1..offset + 5])? as u64;
        return Ok(Some(X86RegisterTarget { register, instruction_len: 5, address }));
    }

    Ok(None)
}

fn x86_memory_register_target(
    code: &[u8],
    offset: usize,
    instruction_va: u64,
    is_x64: bool,
) -> Result<Option<X86RegisterTarget>, ImportError> {
    if is_x64 && offset + 7 <= code.len() && x64_rex_w(code[offset]) && code[offset + 1] == 0x8b {
        let rex = code[offset];
        let modrm = code[offset + 2];
        if modrm & 0xc7 == 0x05 {
            let register = ((modrm >> 3) & 0x07) | ((rex & 0x04) << 1);
            let instruction_end = instruction_va
                .checked_add(7)
                .ok_or(ImportError::Overflow("computing x64 memory-register instruction end"))?;
            let address = add_signed(
                instruction_end,
                read_i32(&code[offset + 3..offset + 7])? as i64,
                "computing x64 memory-register pointer address",
            )?;
            return Ok(Some(X86RegisterTarget { register, instruction_len: 7, address }));
        }
    }

    if !is_x64 && offset + 6 <= code.len() && code[offset] == 0x8b {
        let modrm = code[offset + 1];
        if modrm & 0xc7 == 0x05 {
            let register = (modrm >> 3) & 0x07;
            let address = read_u32(&code[offset + 2..offset + 6])? as u64;
            return Ok(Some(X86RegisterTarget { register, instruction_len: 6, address }));
        }
    }

    if !is_x64 && offset + 5 <= code.len() && code[offset] == 0xa1 {
        let address = read_u32(&code[offset + 1..offset + 5])? as u64;
        return Ok(Some(X86RegisterTarget { register: 0, instruction_len: 5, address }));
    }

    Ok(None)
}

fn x64_rex_w(byte: u8) -> bool {
    (0x40..=0x4f).contains(&byte) && byte & 0x08 != 0
}

fn x86_immediate_register_branch_kind(
    code: &[u8],
    offset: usize,
    register: u8,
    is_x64: bool,
) -> Option<ImportCodeReferenceKind> {
    match x86_register_branch_operation_after_copies(code, offset, register, is_x64)? {
        2 => Some(ImportCodeReferenceKind::ImmediateCall),
        4 => Some(ImportCodeReferenceKind::ImmediateJump),
        _ => None,
    }
}

fn x86_indirect_register_branch_kind(
    code: &[u8],
    offset: usize,
    register: u8,
    is_x64: bool,
) -> Option<ImportCodeReferenceKind> {
    match x86_register_branch_operation_after_copies(code, offset, register, is_x64)? {
        2 => Some(ImportCodeReferenceKind::IndirectCall),
        4 => Some(ImportCodeReferenceKind::IndirectJump),
        _ => None,
    }
}

fn x86_register_branch_operation_after_copies(
    code: &[u8],
    mut offset: usize,
    mut register: u8,
    is_x64: bool,
) -> Option<u8> {
    for _ in 0..=X86_REGISTER_COPY_TRACE_LIMIT {
        if let Some(operation) = x86_register_branch_operation(code, offset, register, is_x64) {
            return Some(operation);
        }

        let copy = x86_register_copy(code, offset, is_x64)?;
        if copy.source != register {
            return None;
        }

        offset += copy.instruction_len;
        register = copy.destination;
    }

    None
}

#[derive(Clone, Copy)]
struct X86RegisterCopy {
    destination: u8,
    source: u8,
    instruction_len: usize,
}

fn x86_register_copy(
    code: &[u8],
    offset: usize,
    is_x64: bool,
) -> Option<X86RegisterCopy> {
    let mut rex = 0u8;
    let mut opcode_offset = offset;

    if is_x64 {
        if offset >= code.len() || !(0x40..=0x4f).contains(&code[offset]) {
            return None;
        }
        rex = code[offset];
        if rex & 0x08 == 0 {
            return None;
        }
        opcode_offset += 1;
    }

    if opcode_offset + 2 > code.len() || !matches!(code[opcode_offset], 0x89 | 0x8b) {
        return None;
    }

    let modrm = code[opcode_offset + 1];
    if modrm & 0xc0 != 0xc0 {
        return None;
    }

    let reg = ((modrm >> 3) & 0x07) | ((rex & 0x04) << 1);
    let rm = (modrm & 0x07) | ((rex & 0x01) << 3);
    let (destination, source) = if code[opcode_offset] == 0x8b { (reg, rm) } else { (rm, reg) };

    Some(X86RegisterCopy {
        destination,
        source,
        instruction_len: opcode_offset + 2 - offset,
    })
}

fn x86_register_branch_operation(
    code: &[u8],
    mut offset: usize,
    register: u8,
    is_x64: bool,
) -> Option<u8> {
    let mut branch_register_high = 0u8;

    if is_x64 && offset < code.len() && (0x40..=0x4f).contains(&code[offset]) {
        branch_register_high = (code[offset] & 1) << 3;
        offset += 1;
    }

    if offset + 2 > code.len() || code[offset] != 0xff {
        return None;
    }

    let modrm = code[offset + 1];
    if modrm & 0xc0 != 0xc0 {
        return None;
    }

    let branch_register = (modrm & 0x07) | branch_register_high;
    if branch_register != register {
        return None;
    }

    Some((modrm >> 3) & 0x07)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn scan_arm64_code_references<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    section_rva: u32,
    image_base: u64,
    resolver: &R,
) -> Result<(), ImportError> {
    let mut offset = 0usize;

    while offset + 4 <= code.len() {
        let instruction = read_u32(&code[offset..offset + 4])?;
        let kind = match instruction & ARM64_BRANCH_OPCODE_MASK {
            ARM64_BL_OPCODE => Some(ImportCodeReferenceKind::DirectCall),
            ARM64_B_OPCODE => Some(ImportCodeReferenceKind::DirectJump),
            _ => None,
        };

        if let Some(kind) = kind {
            let reference_rva = reference_rva(section_rva, offset)?;
            let reference_address = image_base
                .checked_add(reference_rva as u64)
                .ok_or(ImportError::Overflow("computing arm64 branch reference address"))?;
            let target_address = add_signed(
                reference_address,
                arm64_branch_displacement(instruction),
                "computing arm64 branch target",
            )?;

            push_resolved_code_reference(
                references,
                reference_rva,
                kind,
                target_address,
                None,
                resolver,
            )?;
        }

        try_push_arm64_ldr_literal_reference(
            references,
            image_data,
            code,
            offset,
            section_rva,
            image_base,
            resolver,
        )?;
        try_push_arm64_adrp_ldr_reference(
            references,
            image_data,
            code,
            offset,
            section_rva,
            image_base,
            resolver,
        )?;
        try_push_arm64_adr_reference(
            references,
            code,
            offset,
            section_rva,
            image_base,
            resolver,
        )?;
        try_push_arm64_adrp_add_reference(
            references,
            code,
            offset,
            section_rva,
            image_base,
            resolver,
        )?;

        offset += 4;
    }

    Ok(())
}

fn try_push_arm64_ldr_literal_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    resolver: &R,
) -> Result<(), ImportError> {
    if offset + 8 > code.len() {
        return Ok(());
    }

    let load_instruction = read_u32(&code[offset..offset + 4])?;
    if load_instruction & ARM64_LDR_LITERAL_64_MASK != ARM64_LDR_LITERAL_64_OPCODE {
        return Ok(());
    }

    let branch_instruction = read_u32(&code[offset + 4..offset + 8])?;
    let Some(kind) = arm64_branch_register_kind(branch_instruction) else {
        return Ok(());
    };

    let register = load_instruction & ARM64_REGISTER_MASK;
    if !arm64_branch_register_uses(branch_instruction, register) {
        return Ok(());
    }

    let reference_rva = reference_rva(section_rva, offset)?;
    let reference_address = image_base
        .checked_add(reference_rva as u64)
        .ok_or(ImportError::Overflow("computing arm64 literal reference address"))?;
    let iat_address = add_signed(
        reference_address,
        arm64_literal_displacement(load_instruction),
        "computing arm64 literal import pointer address",
    )?;
    let Some((iat_rva, target_address)) = read_image_pointer(image_data, image_base, iat_address, 8)? else {
        return Ok(());
    };

    push_resolved_code_reference(
        references,
        reference_rva,
        kind,
        target_address,
        Some(iat_rva),
        resolver,
    )
}

fn try_push_arm64_adrp_ldr_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    image_data: &[u8],
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    resolver: &R,
) -> Result<(), ImportError> {
    if offset + 12 > code.len() {
        return Ok(());
    }

    let adrp_instruction = read_u32(&code[offset..offset + 4])?;
    if adrp_instruction & ARM64_ADRP_MASK != ARM64_ADRP_OPCODE {
        return Ok(());
    }

    let load_instruction = read_u32(&code[offset + 4..offset + 8])?;
    if load_instruction & ARM64_LDR_UNSIGNED_64_MASK != ARM64_LDR_UNSIGNED_64_OPCODE {
        return Ok(());
    }

    let branch_instruction = read_u32(&code[offset + 8..offset + 12])?;
    let Some(kind) = arm64_branch_register_kind(branch_instruction) else {
        return Ok(());
    };

    let page_register = adrp_instruction & ARM64_REGISTER_MASK;
    let load_base_register = (load_instruction >> 5) & ARM64_REGISTER_MASK;
    let target_register = load_instruction & ARM64_REGISTER_MASK;
    if page_register != load_base_register || !arm64_branch_register_uses(branch_instruction, target_register) {
        return Ok(());
    }

    let reference_rva = reference_rva(section_rva, offset)?;
    let reference_address = image_base
        .checked_add(reference_rva as u64)
        .ok_or(ImportError::Overflow("computing arm64 page reference address"))?;
    let page_address = reference_address & !0xfff;
    let pointer_page = add_signed(
        page_address,
        arm64_adrp_page_displacement(adrp_instruction),
        "computing arm64 page import pointer address",
    )?;
    let iat_address = pointer_page
        .checked_add(arm64_ldr_unsigned_immediate_64(load_instruction) as u64)
        .ok_or(ImportError::Overflow("computing arm64 import pointer address"))?;
    let Some((iat_rva, target_address)) = read_image_pointer(image_data, image_base, iat_address, 8)? else {
        return Ok(());
    };

    push_resolved_code_reference(
        references,
        reference_rva,
        kind,
        target_address,
        Some(iat_rva),
        resolver,
    )
}

fn try_push_arm64_adr_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    resolver: &R,
) -> Result<(), ImportError> {
    if offset + 8 > code.len() {
        return Ok(());
    }

    let adr_instruction = read_u32(&code[offset..offset + 4])?;
    if adr_instruction & ARM64_ADR_MASK != ARM64_ADR_OPCODE {
        return Ok(());
    }

    let branch_instruction = read_u32(&code[offset + 4..offset + 8])?;
    let register = adr_instruction & ARM64_REGISTER_MASK;
    let Some(kind) = arm64_immediate_branch_register_kind(branch_instruction) else {
        return Ok(());
    };
    if !arm64_immediate_branch_register_uses(branch_instruction, register) {
        return Ok(());
    }

    let reference_rva = reference_rva(section_rva, offset)?;
    let reference_address = image_base
        .checked_add(reference_rva as u64)
        .ok_or(ImportError::Overflow("computing arm64 ADR reference address"))?;
    let target_address = add_signed(
        reference_address,
        arm64_adr_displacement(adr_instruction),
        "computing arm64 ADR import target address",
    )?;

    push_resolved_code_reference(references, reference_rva, kind, target_address, None, resolver)
}

fn try_push_arm64_adrp_add_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    code: &[u8],
    offset: usize,
    section_rva: u32,
    image_base: u64,
    resolver: &R,
) -> Result<(), ImportError> {
    if offset + 12 > code.len() {
        return Ok(());
    }

    let adrp_instruction = read_u32(&code[offset..offset + 4])?;
    if adrp_instruction & ARM64_ADRP_MASK != ARM64_ADRP_OPCODE {
        return Ok(());
    }

    let add_instruction = read_u32(&code[offset + 4..offset + 8])?;
    if add_instruction & ARM64_ADD_IMMEDIATE_64_MASK != ARM64_ADD_IMMEDIATE_64_OPCODE {
        return Ok(());
    }

    let branch_instruction = read_u32(&code[offset + 8..offset + 12])?;
    let page_register = adrp_instruction & ARM64_REGISTER_MASK;
    let add_base_register = (add_instruction >> 5) & ARM64_REGISTER_MASK;
    let target_register = add_instruction & ARM64_REGISTER_MASK;
    let Some(kind) = arm64_immediate_branch_register_kind(branch_instruction) else {
        return Ok(());
    };
    if page_register != add_base_register || !arm64_immediate_branch_register_uses(branch_instruction, target_register) {
        return Ok(());
    }

    let reference_rva = reference_rva(section_rva, offset)?;
    let reference_address = image_base
        .checked_add(reference_rva as u64)
        .ok_or(ImportError::Overflow("computing arm64 ADRP reference address"))?;
    let page_address = reference_address & !0xfff;
    let target_page = add_signed(
        page_address,
        arm64_adrp_page_displacement(adrp_instruction),
        "computing arm64 ADRP import target page",
    )?;
    let target_address = target_page
        .checked_add(arm64_add_immediate_64(add_instruction) as u64)
        .ok_or(ImportError::Overflow("computing arm64 ADRP/ADD import target address"))?;

    push_resolved_code_reference(references, reference_rva, kind, target_address, None, resolver)
}

fn push_resolved_code_reference<R: ImportSymbolResolver>(
    references: &mut Vec<ImportCodeReference>,
    reference_rva: u32,
    kind: ImportCodeReferenceKind,
    target_address: u64,
    iat_rva: Option<u32>,
    resolver: &R,
) -> Result<(), ImportError> {
    let Some(symbol) = resolver.resolve_import_address(target_address)? else {
        return Ok(());
    };

    references.push(ImportCodeReference {
        reference_rva,
        kind,
        target_address,
        export_address: symbol.address,
        iat_rva,
        module_name: symbol.module_name,
        name: symbol.name,
        ordinal: symbol.ordinal,
    });

    Ok(())
}

fn mapped_section_data(
    image_data: &[u8],
    section: SectionInfo,
) -> Result<Option<(u32, &[u8])>, ImportError> {
    let start = usize::try_from(section.virtual_address)
        .map_err(|_| ImportError::Overflow("converting section RVA to offset"))?;
    if start >= image_data.len() {
        return Ok(None);
    }

    let size = section.virtual_size.max(section.raw_size);
    let size = usize::try_from(size)
        .map_err(|_| ImportError::Overflow("converting section size to usize"))?;
    let end = start
        .checked_add(size)
        .ok_or(ImportError::Overflow("sizing mapped executable section"))?
        .min(image_data.len());

    Ok(Some((section.virtual_address, &image_data[start..end])))
}

fn reference_rva(section_rva: u32, offset: usize) -> Result<u32, ImportError> {
    let offset = u32::try_from(offset)
        .map_err(|_| ImportError::Overflow("converting code reference offset to RVA"))?;

    section_rva
        .checked_add(offset)
        .ok_or(ImportError::Overflow("computing code reference RVA"))
}

fn read_image_pointer(
    image_data: &[u8],
    image_base: u64,
    address: u64,
    pointer_size: usize,
) -> Result<Option<(u32, u64)>, ImportError> {
    if address < image_base {
        return Ok(None);
    }

    let rva = address - image_base;
    let Ok(rva) = u32::try_from(rva) else {
        return Ok(None);
    };
    let offset = rva as usize;
    if offset + pointer_size > image_data.len() {
        return Ok(None);
    }

    Ok(Some((rva, read_iat_pointer(&image_data[offset..offset + pointer_size], pointer_size)?)))
}

fn mapped_address_to_offset(image_data: &[u8], image_base: u64, address: u64) -> Option<(u32, usize)> {
    if address < image_base {
        return None;
    }

    let rva = u32::try_from(address - image_base).ok()?;
    let offset = rva as usize;
    if offset >= image_data.len() {
        return None;
    }

    Some((rva, offset))
}

fn x86_next_thunk_address(
    image_data: &[u8],
    image_base: u64,
    offset: usize,
    address: u64,
    pointer_size: usize,
    is_x64: bool,
) -> Result<Option<u64>, ImportError> {
    let code = &image_data[offset..];

    if code.len() >= 5 && matches!(code[0], 0xe8 | 0xe9) {
        let instruction_end = address
            .checked_add(5)
            .ok_or(ImportError::Overflow("computing x86 thunk branch address"))?;
        let displacement = read_i32(&code[1..5])? as i64;
        return Ok(Some(add_x86_relative(instruction_end, displacement, is_x64, "computing x86 thunk branch target")?));
    }

    if code.len() >= 6 && code[0] == 0xff && matches!(code[1], 0x15 | 0x25) {
        let operand = read_i32(&code[2..6])?;
        let pointer_address = if is_x64 {
            let instruction_end = address
                .checked_add(6)
                .ok_or(ImportError::Overflow("computing x64 thunk pointer address"))?;
            add_signed(instruction_end, operand as i64, "computing x64 thunk pointer target")?
        } else {
            u32::from_le_bytes(operand.to_le_bytes()) as u64
        };

        return Ok(read_image_pointer(image_data, image_base, pointer_address, pointer_size)?
            .map(|(_, target_address)| target_address));
    }

    if let Some(load) = x86_immediate_register_target(code, 0, is_x64)? {
        if x86_immediate_register_branch_kind(code, load.instruction_len, load.register, is_x64).is_some() {
            return Ok(Some(load.address));
        }
    }

    if let Some(load) = x86_memory_register_target(code, 0, address, is_x64)? {
        if x86_indirect_register_branch_kind(code, load.instruction_len, load.register, is_x64).is_some() {
            return Ok(read_image_pointer(image_data, image_base, load.address, pointer_size)?
                .map(|(_, target_address)| target_address));
        }
    }

    if !is_x64 && code.len() >= 6 && code[0] == 0x68 && code[5] == 0xc3 {
        return Ok(Some(read_u32(&code[1..5])? as u64));
    }

    Ok(None)
}

fn arm64_next_thunk_address(
    image_data: &[u8],
    image_base: u64,
    offset: usize,
    address: u64,
) -> Result<Option<u64>, ImportError> {
    let code = &image_data[offset..];
    if code.len() < 4 {
        return Ok(None);
    }

    let instruction = read_u32(&code[..4])?;
    if matches!(instruction & ARM64_BRANCH_OPCODE_MASK, ARM64_B_OPCODE | ARM64_BL_OPCODE) {
        return Ok(Some(add_signed(
            address,
            arm64_branch_displacement(instruction),
            "computing arm64 thunk branch target",
        )?));
    }

    if code.len() >= 8 && instruction & ARM64_LDR_LITERAL_64_MASK == ARM64_LDR_LITERAL_64_OPCODE {
        let register = instruction & ARM64_REGISTER_MASK;
        let next_instruction = read_u32(&code[4..8])?;
        if !arm64_branch_register_uses(next_instruction, register) {
            return Ok(None);
        }

        let pointer_address = add_signed(
            address,
            arm64_literal_displacement(instruction),
            "computing arm64 thunk literal address",
        )?;

        return Ok(read_image_pointer(image_data, image_base, pointer_address, 8)?
            .map(|(_, target_address)| target_address));
    }

    Ok(None)
}

fn read_i32(bytes: &[u8]) -> Result<i32, ImportError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ImportError::Overflow("reading i32 value"))?;

    Ok(i32::from_le_bytes(bytes))
}

fn read_u32(bytes: &[u8]) -> Result<u32, ImportError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ImportError::Overflow("reading u32 value"))?;

    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8]) -> Result<u64, ImportError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ImportError::Overflow("reading u64 value"))?;

    Ok(u64::from_le_bytes(bytes))
}

fn add_x86_relative(value: u64, delta: i64, is_x64: bool, operation: &'static str) -> Result<u64, ImportError> {
    if is_x64 { return add_signed(value, delta, operation); }
    // Legacy EIP arithmetic wraps at 32 bits, including branches across address zero.
    Ok((value as u32).wrapping_add(delta as u32) as u64)
}

fn add_signed(value: u64, delta: i64, operation: &'static str) -> Result<u64, ImportError> {
    if delta >= 0 {
        value.checked_add(delta as u64)
    } else {
        value.checked_sub(delta.unsigned_abs())
    }
    .ok_or(ImportError::Overflow(operation))
}

fn arm64_branch_displacement(instruction: u32) -> i64 {
    let imm26 = (instruction & ARM64_BRANCH_IMM26_MASK) as i32;
    ((imm26 << 6) >> 6) as i64 * 4
}

fn arm64_literal_displacement(instruction: u32) -> i64 {
    let imm19 = ((instruction & ARM64_LDR_LITERAL_IMM19_MASK) >> 5) as i32;
    ((imm19 << 13) >> 13) as i64 * 4
}

fn arm64_conditional_branch_displacement(instruction: u32) -> i64 {
    arm64_literal_displacement(instruction)
}

fn arm64_test_branch_displacement(instruction: u32) -> i64 {
    let imm14 = ((instruction & ARM64_TEST_BRANCH_IMM14_MASK) >> 5) as i32;
    ((imm14 << 18) >> 18) as i64 * 4
}

fn arm64_adr_displacement(instruction: u32) -> i64 {
    arm64_adr_immediate(instruction) as i64
}

fn arm64_adrp_page_displacement(instruction: u32) -> i64 {
    arm64_adr_immediate(instruction) as i64 * 0x1000
}

fn arm64_adr_immediate(instruction: u32) -> i32 {
    let immhi = (instruction >> 5) & 0x7ffff;
    let immlo = (instruction >> 29) & 0x3;
    let imm21 = ((immhi << 2) | immlo) as i32;

    (imm21 << 11) >> 11
}

fn arm64_ldr_unsigned_immediate_64(instruction: u32) -> u32 {
    ((instruction >> 10) & 0xfff) * 8
}

fn arm64_add_immediate_64(instruction: u32) -> u32 {
    (instruction >> 10) & 0xfff
}

fn arm64_branch_register_kind(instruction: u32) -> Option<ImportCodeReferenceKind> {
    match instruction & ARM64_BRANCH_REGISTER_OPCODE_MASK {
        ARM64_BR_OPCODE => Some(ImportCodeReferenceKind::IndirectJump),
        ARM64_BLR_OPCODE => Some(ImportCodeReferenceKind::IndirectCall),
        _ => None,
    }
}

fn arm64_branch_register_uses(instruction: u32, register: u32) -> bool {
    arm64_branch_register_kind(instruction).is_some() && ((instruction >> 5) & ARM64_REGISTER_MASK) == register
}

fn arm64_immediate_branch_register_kind(instruction: u32) -> Option<ImportCodeReferenceKind> {
    match instruction & ARM64_BRANCH_REGISTER_OPCODE_MASK {
        ARM64_BR_OPCODE => Some(ImportCodeReferenceKind::ImmediateJump),
        ARM64_BLR_OPCODE => Some(ImportCodeReferenceKind::ImmediateCall),
        _ => None,
    }
}

fn arm64_immediate_branch_register_uses(instruction: u32, register: u32) -> bool {
    arm64_immediate_branch_register_kind(instruction).is_some() && ((instruction >> 5) & ARM64_REGISTER_MASK) == register
}

pub(super) const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub(super) const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub(super) const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
pub(super) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const X86_REGISTER_COPY_TRACE_LIMIT: usize = 3;
const ARM64_ADR_OPCODE: u32 = 0x1000_0000;
const ARM64_ADR_MASK: u32 = 0x9f00_0000;
pub(super) const ARM64_ADRP_OPCODE: u32 = 0x9000_0000;
pub(super) const ARM64_ADRP_MASK: u32 = 0x9f00_0000;
const ARM64_ADD_IMMEDIATE_64_MASK: u32 = 0xffc0_0000;
const ARM64_ADD_IMMEDIATE_64_OPCODE: u32 = 0x9100_0000;
const ARM64_BRANCH_OPCODE_MASK: u32 = 0xfc00_0000;
pub(super) const ARM64_BRANCH_IMM26_MASK: u32 = 0x03ff_ffff;
pub(super) const ARM64_B_OPCODE: u32 = 0x1400_0000;
pub(super) const ARM64_BL_OPCODE: u32 = 0x9400_0000;
pub(super) const ARM64_LDR_LITERAL_64_MASK: u32 = 0xff00_0000;
pub(super) const ARM64_LDR_LITERAL_64_OPCODE: u32 = 0x5800_0000;
const ARM64_LDR_LITERAL_IMM19_MASK: u32 = 0x00ff_ffe0;
pub(super) const ARM64_LDR_UNSIGNED_64_MASK: u32 = 0xffc0_0000;
pub(super) const ARM64_LDR_UNSIGNED_64_OPCODE: u32 = 0xf940_0000;
const ARM64_BRANCH_REGISTER_OPCODE_MASK: u32 = 0xffff_fc1f;
pub(super) const ARM64_BR_OPCODE: u32 = 0xd61f_0000;
pub(super) const ARM64_BLR_OPCODE: u32 = 0xd63f_0000;
const ARM64_CONDITIONAL_BRANCH_MASK: u32 = 0xff00_0010;
const ARM64_CONDITIONAL_BRANCH_OPCODE: u32 = 0x5400_0000;
const ARM64_COMPARE_BRANCH_MASK: u32 = 0x7e00_0000;
const ARM64_COMPARE_BRANCH_OPCODE: u32 = 0x3400_0000;
const ARM64_TEST_BRANCH_MASK: u32 = 0x7e00_0000;
const ARM64_TEST_BRANCH_OPCODE: u32 = 0x3600_0000;
const ARM64_TEST_BRANCH_IMM14_MASK: u32 = 0x0007_ffe0;
const ARM64_RET_MASK: u32 = 0xffff_fc1f;
const ARM64_RET_OPCODE: u32 = 0xd65f_0000;
const ARM64_REGISTER_MASK: u32 = 0x1f;
