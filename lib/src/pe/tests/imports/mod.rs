use super::*;
use super::code::{
    scan_arm64_code_references, scan_x86_code_references, ARM64_ADRP_OPCODE, ARM64_BLR_OPCODE,
    ARM64_BRANCH_IMM26_MASK, ARM64_BR_OPCODE, ARM64_B_OPCODE, ARM64_BL_OPCODE,
    ARM64_LDR_LITERAL_64_OPCODE, ARM64_LDR_UNSIGNED_64_OPCODE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use super::resolver::ImportAddressResolver;
use super::util::{
    ARM64_NOP, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_ORDINAL_FLAG32, IMAGE_SCN_MEM_EXECUTE,
};

mod fixtures;
use fixtures::*;

mod code_arm64;
mod code_x86;
mod iat_scan;
mod model;
mod rebuild;
mod resolve;
mod trace;
mod validation;
