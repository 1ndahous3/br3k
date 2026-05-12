use crate::pdb::Pdb;

use std::collections::VecDeque;
use std::result::Result;

use kdmp_parser::{Gpa, Gva, KdmpParserError, KernelDumpParser};

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
    pub fn new(dump_filepath: &str, pdb: &mut Pdb) -> Result<Self, KdmpParserError> {
        let mut field_offset = |class_name: &str, field_name: &str, label: &str| -> usize {
            match pdb.get_field_offset(class_name, field_name) {
                Ok(offset) => offset,
                Err(_) => panic!("Failed to get {label} offset"),
            }
        };

        let kernel_offsets = KernelOffsets {
            // _MMVAD_SHORT
            MMVAD_STARTING_VPN: field_offset("_MMVAD_SHORT", "StartingVpn", "_MMVAD_SHORT::StartingVpn"),
            MMVAD_ENDING_VPN: field_offset("_MMVAD_SHORT", "EndingVpn", "_MMVAD_SHORT::EndingVpn"),
            MMVAD_U_VAD_FLAGS: field_offset("_MMVAD_SHORT", "u", "_MMVAD_SHORT::u.VadFlags"),
            // _MMVAD_SHORT::VadNode
            MMVAD_LEFT_CHILD: field_offset("_RTL_BALANCED_NODE", "Left", "_RTL_BALANCED_NODE::Left"),
            MMVAD_RIGHT_CHILD: field_offset("_RTL_BALANCED_NODE", "Right", "_RTL_BALANCED_NODE::Right"),
            // _EPROCESS
            EPROCESS_ACTIVE_PROCESS_LINKS: field_offset("_EPROCESS", "ActiveProcessLinks", "_EPROCESS::ActiveProcessLinks"),
            EPROCESS_UNIQUE_PROCESS_ID: field_offset("_EPROCESS", "UniqueProcessId", "_EPROCESS::UniqueProcessId"),
            EPROCESS_IMAGE_FILE_NAME: field_offset("_EPROCESS", "ImageFileName", "_EPROCESS::ImageFileName"),
            EPROCESS_VAD_ROOT: field_offset("_EPROCESS", "VadRoot", "_EPROCESS::VadRoot"),
            // _KPROCESS
            KPROCESS_DTB: field_offset("_KPROCESS", "DirectoryTableBase", "_KPROCESS::DirectoryTableBase"),
        };

        let parser = KernelDumpParser::new(dump_filepath)?;

        Ok(Self { kernel_offsets, parser })
    }

    #[allow(dead_code)]
    pub fn get_process_image_maps(&self, va_vad_root: u64) -> Result<Vec<VadImage>, KdmpParserError> {
        let mut vads = VecDeque::new();
        if va_vad_root != 0 {
            vads.push_back(va_vad_root);
        }

        let mut vad_images = Vec::new();

        while let Some(va_vad_current) = vads.pop_front() {
            let vad_flags_addr = self.kernel_offsets.MMVAD_U_VAD_FLAGS as u64;
            let vad_flags: u32 = match self.parser.virt_read_struct(vad_flags_addr.into()) {
                Ok(flags) => flags,
                Err(_) => continue,
            };

            let vad_type = ((vad_flags >> 4) & 7) as u8; // TODO: get bit offset from pdb
            if vad_type != MI_VAD_TYPE::VadImageMap as u8 {
                continue;
            }

            let starting_vpn_addr = va_vad_current + self.kernel_offsets.MMVAD_STARTING_VPN as u64;
            let starting_vpn: u32 = match self.parser.virt_read_struct(starting_vpn_addr.into()) {
                Ok(value) => value,
                Err(_) => continue,
            };

            let ending_vpn_addr = va_vad_current + self.kernel_offsets.MMVAD_ENDING_VPN as u64;
            let ending_vpn: u32 = match self.parser.virt_read_struct(ending_vpn_addr.into()) {
                Ok(value) => value,
                Err(_) => continue,
            };

            let va_start = (starting_vpn as u64) << 12;
            let va_end = ((ending_vpn as u64) + 1) << 12;
            vad_images.push(VadImage { va_start, va_end });

            for child_offset in [self.kernel_offsets.MMVAD_LEFT_CHILD, self.kernel_offsets.MMVAD_RIGHT_CHILD] {
                let va_vad_leaf: u64 = match self.parser.virt_read_struct((va_vad_current + child_offset as u64).into()) {
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

    pub fn get_processes(&self) -> Result<Vec<Process>, KdmpParserError> {
        let mut processes = Vec::new();

        let header = self.parser.headers();
        let ps_active_process_head: LIST_ENTRY = self.parser.virt_read_struct(header.ps_active_process_head.into())?;

        let mut va_current_process = ps_active_process_head.Flink;
        while va_current_process != header.ps_active_process_head {
            let mut process = Process::default();

            let va_eprocess = va_current_process - self.kernel_offsets.EPROCESS_ACTIVE_PROCESS_LINKS as u64;
            let dtb_addr = va_eprocess + self.kernel_offsets.KPROCESS_DTB as u64;
            let pid_addr = va_eprocess + self.kernel_offsets.EPROCESS_UNIQUE_PROCESS_ID as u64;
            let image_file_name_addr = va_eprocess + self.kernel_offsets.EPROCESS_IMAGE_FILE_NAME as u64;
            let vad_root_addr = va_eprocess + self.kernel_offsets.EPROCESS_VAD_ROOT as u64;

            process.dtb = self.parser.virt_read_struct(dtb_addr.into())?;
            process.pid = self.parser.virt_read_struct(pid_addr.into())?;
            process.image_file_name = self.parser.virt_read_struct(image_file_name_addr.into())?;
            process.vad_root = self.parser.virt_read_struct(vad_root_addr.into())?;

            processes.push(process);

            let next_process: LIST_ENTRY = match self.parser.virt_read_struct(va_current_process.into()) {
                Ok(entry) => entry,
                Err(_) => {
                    log::error!("Failed to read process entry at VA: {va_current_process:#x}");
                    return Ok(processes);
                }
            };

            va_current_process = next_process.Flink as u64;
        }

        Ok(processes)
    }

    pub fn read_memory(&self, buf: &mut [u8], process: &Process, basic_addres: usize) -> Result<(), KdmpParserError> {
        self.parser.virt_read_with_dtb(Gva::from(basic_addres as u64), buf, Gpa::from(process.dtb))?;
        Ok(())
    }
}
