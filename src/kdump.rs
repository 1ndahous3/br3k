use crate::prelude::*;
use crate::pdb::Pdb;

use std::cmp::min;
use std::collections::VecDeque;

use kdmp_parser::{
    KernelDumpParser,
    Gpa, Gva, Gxa, Pxe,
    KdmpParserError, AddrTranslationError,
    PxeNotPresent
};

pub type Result<R> = std::result::Result<R, KdmpParserError>;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MI_VAD_TYPE {
    VadNone = 0,
    VadDevicePhysicalMemory = 1,
    VadImageMap = 2,
    VadAwe = 3,
    VadWriteWatch = 4,
    VadLargePages = 5,
    VadRotatePhysical = 6,
    VadLargePageSection = 7,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Default)]
pub struct KernelOffsets {
    pub MMVAD_STARTING_VPN: usize,
    pub MMVAD_ENDING_VPN: usize,
    pub MMVAD_U_VAD_FLAGS: usize,
    pub MMVAD_LEFT_CHILD: usize,
    pub MMVAD_RIGHT_CHILD: usize,
    pub EPROCESS_ACTIVE_PROCESS_LINKS: usize,
    pub EPROCESS_UNIQUE_PROCESS_ID: usize,
    pub EPROCESS_IMAGE_FILE_NAME: usize,
    pub EPROCESS_VAD_ROOT: usize,
    pub KPROCESS_DTB: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Process {
    pub dtb: u64,
    pub vad_root: u64, // _RTL_AVL_TREE.Root
    pub pid: u32,
    pub image_file_name: [u8; 16],
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct VadImage {
    pub va_start: u64,
    pub va_end: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LIST_ENTRY {
    Flink: u64,
    Blink: u64,
}

#[derive(Debug)]
pub struct KernelDump {
    pub kernel_offsets: KernelOffsets,
    pub parser: KernelDumpParser,
}

impl KernelDump {

    // TODO: implement directory_table_base option in read/translate methods in upstream

    /// Translate a [`Gva`] into a [`Gpa`].
    pub fn virt_translate(&self, gva: Gva, directory_table_base: usize) -> Result<Gpa> {
        // Aligning in case PCID bits are set (bits 11:0)
        let pml4_base = Gpa::from(directory_table_base as u64).page_align();
        let pml4e_gpa = Gpa::new(pml4_base.u64() + (gva.pml4e_idx() * 8));
        let pml4e = Pxe::from(self.parser.phys_read_struct::<u64>(pml4e_gpa)?);
        if !pml4e.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pml4e).into());
        }

        let pdpt_base = pml4e.pfn.gpa();
        let pdpte_gpa = Gpa::new(pdpt_base.u64() + (gva.pdpe_idx() * 8));
        let pdpte = Pxe::from(self.parser.phys_read_struct::<u64>(pdpte_gpa)?);
        if !pdpte.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pdpte).into());
        }

        // huge pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // directory; see Table 4-1
        let pd_base = pdpte.pfn.gpa();
        if pdpte.large_page() {
            return Ok(Gpa::new(pd_base.u64() + (gva.u64() & 0x3fff_ffff)));
        }

        let pde_gpa = Gpa::new(pd_base.u64() + (gva.pde_idx() * 8));
        let pde = Pxe::from(self.parser.phys_read_struct::<u64>(pde_gpa)?);
        if !pde.present() {
            return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pde).into());
        }

        // large pages:
        // 7 (PS) - Page size; must be 1 (otherwise, this entry references a page
        // table; see Table 4-18
        let pt_base = pde.pfn.gpa();
        if pde.large_page() {
            return Ok(Gpa::new(pt_base.u64() + (gva.u64() & 0x1f_ffff)));
        }

        let pte_gpa = Gpa::new(pt_base.u64() + (gva.pte_idx() * 8));
        let pte = Pxe::from(self.parser.phys_read_struct::<u64>(pte_gpa)?);
        if !pte.present() {
            // We'll allow reading from a transition PTE, so return an error only if it's
            // not one, otherwise we'll carry on.
            if !pte.transition() {
                return Err(AddrTranslationError::Virt(gva, PxeNotPresent::Pte).into());
            }
        }

        let page_base = pte.pfn.gpa();

        Ok(Gpa::new(page_base.u64() + gva.offset()))
    }

    pub fn virt_read(&self, gva: Gva, buf: &mut [u8], directory_table_base: usize) -> kdmp_parser::Result<usize> {
        // Amount of bytes left to read.
        let mut amount_left = buf.len();
        // Total amount of bytes that we have successfully read.
        let mut total_read = 0;
        // The current gva we are reading from.
        let mut addr = gva;
        // Let's try to read as much as the user wants.
        while amount_left > 0 {
            // We need to take care of reads that straddle different virtual memory pages.
            // So let's figure out the maximum amount of bytes we can read off this page.
            // Either, we read it until its end, or we stop if the user wants us to read
            // less.
            let left_in_page = (0x1_000 - addr.offset()) as usize;
            let amount_wanted = min(amount_left, left_in_page);
            // Figure out where we should read into.
            let slice = &mut buf[total_read..total_read + amount_wanted];
            // Translate the gva into a gpa..
            let gpa = self.virt_translate(addr, directory_table_base)?;
            // .. and read the physical memory!
            let amount_read = self.parser.phys_read(gpa, slice)?;
            // Update the total amount of read bytes and how much work we have left.
            total_read += amount_read;
            amount_left -= amount_read;
            // If we couldn't read as much as we wanted, we're done.
            if amount_read != amount_wanted {
                return Ok(total_read);
            }

            // We have more work to do, so let's move to the next page.
            addr = addr.next_aligned_page();
        }

        // Yay, we read as much bytes as the user wanted!
        Ok(total_read)
    }

    pub fn new(dump_filepath: &str, pdb: &mut Pdb) -> Result<Self> {
        let kernel_offsets = KernelOffsets {
            // _MMVAD_SHORT
            MMVAD_STARTING_VPN: pdb
                .get_field_offset("_MMVAD_SHORT", "StartingVpn")
                .expect("Failed to get _MMVAD_SHORT::StartingVpn offset"),
            MMVAD_ENDING_VPN: pdb
                .get_field_offset("_MMVAD_SHORT", "EndingVpn")
                .expect("Failed to get _MMVAD_SHORT::EndingVpn offset"),
            MMVAD_U_VAD_FLAGS: pdb
                .get_field_offset("_MMVAD_SHORT", "u")
                .expect("Failed to get _MMVAD_SHORT::u.VadFlags offset"),
            // _MMVAD_SHORT::VadNode
            MMVAD_LEFT_CHILD: pdb
                .get_field_offset("_RTL_BALANCED_NODE", "Left")
                .expect("Failed to get _RTL_BALANCED_NODE::Left offset"),
            MMVAD_RIGHT_CHILD: pdb
                .get_field_offset("_RTL_BALANCED_NODE", "Right")
                .expect("Failed to get _RTL_BALANCED_NODE::Right offset"),
            // _EPROCESS
            EPROCESS_ACTIVE_PROCESS_LINKS: pdb
                .get_field_offset("_EPROCESS", "ActiveProcessLinks")
                .expect("Failed to get _EPROCESS::ActiveProcessLinks offset"),
            EPROCESS_UNIQUE_PROCESS_ID: pdb
                .get_field_offset("_EPROCESS", "UniqueProcessId")
                .expect("Failed to get _EPROCESS::UniqueProcessId offset"),
            EPROCESS_IMAGE_FILE_NAME: pdb
                .get_field_offset("_EPROCESS", "ImageFileName")
                .expect("Failed to get _EPROCESS::ImageFileName offset"),
            EPROCESS_VAD_ROOT: pdb
                .get_field_offset("_EPROCESS", "VadRoot")
                .expect("Failed to get _EPROCESS::VadRoot offset"),
            // _KPROCESS
            KPROCESS_DTB: pdb
                .get_field_offset("_KPROCESS", "DirectoryTableBase")
                .expect("Failed to get _KPROCESS::DirectoryTableBase offset"),
        };

        let parser = KernelDumpParser::new(dump_filepath)?;

        Ok(Self {
            kernel_offsets,
            parser,
        })
    }

    #[allow(dead_code)]
    pub fn get_process_image_maps(&self, va_vad_root: u64) -> Result<Vec<VadImage>> {
        let mut vads = VecDeque::new();
        if va_vad_root != 0 {
            vads.push_back(va_vad_root);
        }

        let mut vad_images = Vec::new();

        while let Some(va_vad_current) = vads.pop_front() {
            let vad_flags: u32 = match self
                .parser
                .virt_read_struct((self.kernel_offsets.MMVAD_U_VAD_FLAGS as u64).into())
            {
                Ok(flags) => flags,
                Err(_) => continue,
            };

            let vad_type = ((vad_flags >> 4) & 7) as u8; // TODO: get bit offset from pdb
            if vad_type != MI_VAD_TYPE::VadImageMap as u8 {
                continue;
            }

            let starting_vpn: u32 = match self.parser.virt_read_struct(
                (va_vad_current + self.kernel_offsets.MMVAD_STARTING_VPN as u64).into(),
            ) {
                Ok(value) => value,
                Err(_) => continue,
            };

            let ending_vpn: u32 = match self.parser.virt_read_struct(
                (va_vad_current + self.kernel_offsets.MMVAD_ENDING_VPN as u64).into(),
            ) {
                Ok(value) => value,
                Err(_) => continue,
            };

            vad_images.push({
                VadImage {
                    va_start: (starting_vpn as u64) << 12,
                    va_end: ((ending_vpn as u64) + 1) << 12,
                }
            });

            for child_offset in [
                self.kernel_offsets.MMVAD_LEFT_CHILD,
                self.kernel_offsets.MMVAD_RIGHT_CHILD,
            ] {
                let va_vad_leaf: u64 = match self
                    .parser
                    .virt_read_struct((va_vad_current + child_offset as u64).into())
                {
                    Ok(leaf) => leaf,
                    Err(_) => continue,
                };

                if va_vad_leaf != 0 {
                    vads.push_back(va_vad_leaf);
                }
            }
        }

        Ok(vad_images)
    }

    pub fn get_processes(&self) -> Result<Vec<Process>> {
        let mut processes = Vec::new();

        let header = self.parser.headers();
        let ps_active_process_head: LIST_ENTRY = self
            .parser
            .virt_read_struct(header.ps_active_process_head.into())?;

        let mut va_current_process = ps_active_process_head.Flink as u64;
        while va_current_process != header.ps_active_process_head {
            let mut process = Process::default();

            let va_eprocess =
                va_current_process - self.kernel_offsets.EPROCESS_ACTIVE_PROCESS_LINKS as u64;

            process.dtb = self
                .parser
                .virt_read_struct((va_eprocess + self.kernel_offsets.KPROCESS_DTB as u64).into())?;
            process.pid = self.parser.virt_read_struct(
                (va_eprocess + self.kernel_offsets.EPROCESS_UNIQUE_PROCESS_ID as u64).into(),
            )?;
            process.image_file_name = self.parser.virt_read_struct(
                (va_eprocess + self.kernel_offsets.EPROCESS_IMAGE_FILE_NAME as u64).into(),
            )?;
            process.vad_root = self.parser.virt_read_struct(
                (va_eprocess + self.kernel_offsets.EPROCESS_VAD_ROOT as u64).into(),
            )?;

            processes.push(process);

            let next_process: LIST_ENTRY =
                match self.parser.virt_read_struct(va_current_process.into()) {
                    Ok(entry) => entry,
                    Err(_) => {
                        log::error!(
                            "Failed to read process entry at VA: {:#x}",
                            va_current_process
                        );
                        return Ok(processes);
                    }
                };

            va_current_process = next_process.Flink as u64;
        }

        Ok(processes)
    }

    pub fn read_memory(&self, buf: &mut [u8], process: &Process, basic_addres: usize) -> Result<()> { 
        self.virt_read(Gva::from(basic_addres as u64), buf, process.dtb as usize)?;
        Ok(())
    }
}
