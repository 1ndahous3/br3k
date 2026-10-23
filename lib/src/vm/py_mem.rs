use crate::vm::prelude::*;

/// Virtual-memory state/type/protection constants and display predicates.
///
/// These helpers interpret metadata; they do not read memory or query a process.
/// Use Process.memory_regions() for fresh metadata. Protection predicates alone
/// cannot establish that a read is safe or that a region contains executable code.
#[pymodule(name = "br3k.mem")]
pub mod mem {

    use crate::vm::prelude::*;

    use rustpython_vm::extend_module;

    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
        PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE,
        PAGE_WRITECOPY,
    };

    const PAGE_PROTECTION_BASE_MASK: u32 = 0xff;

    fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
        extend_module!(vm, module, {
            "MEM_COMMIT" => vm.ctx.new_int(MEM_COMMIT),
            "MEM_RESERVE" => vm.ctx.new_int(MEM_RESERVE),
            "MEM_PRIVATE" => vm.ctx.new_int(MEM_PRIVATE),
            "MEM_MAPPED" => vm.ctx.new_int(MEM_MAPPED),
            "MEM_IMAGE" => vm.ctx.new_int(MEM_IMAGE),
            "PAGE_NOACCESS" => vm.ctx.new_int(PAGE_NOACCESS),
            "PAGE_READONLY" => vm.ctx.new_int(PAGE_READONLY),
            "PAGE_READWRITE" => vm.ctx.new_int(PAGE_READWRITE),
            "PAGE_WRITECOPY" => vm.ctx.new_int(PAGE_WRITECOPY),
            "PAGE_EXECUTE" => vm.ctx.new_int(PAGE_EXECUTE),
            "PAGE_EXECUTE_READ" => vm.ctx.new_int(PAGE_EXECUTE_READ),
            "PAGE_EXECUTE_READWRITE" => vm.ctx.new_int(PAGE_EXECUTE_READWRITE),
            "PAGE_EXECUTE_WRITECOPY" => vm.ctx.new_int(PAGE_EXECUTE_WRITECOPY),
            "PAGE_GUARD" => vm.ctx.new_int(PAGE_GUARD),
            "PAGE_NOCACHE" => vm.ctx.new_int(PAGE_NOCACHE),
            "PAGE_WRITECOMBINE" => vm.ctx.new_int(PAGE_WRITECOMBINE),
        });

        Ok(())
    }

    /// Format a memory state as `MEM_COMMIT`, `MEM_RESERVE`, or a hexadecimal value.
    #[pyfunction]
    fn state_text(state: u32) -> String {
        if state == MEM_COMMIT {
            return "MEM_COMMIT".to_string();
        }
        if state == MEM_RESERVE {
            return "MEM_RESERVE".to_string();
        }

        format!("0x{state:x}")
    }

    /// Format a memory type as `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`, `none`, or hexadecimal.
    #[pyfunction(name = "type_text")]
    fn memory_type_text(memory_type: u32) -> String {
        match memory_type {
            MEM_IMAGE => "MEM_IMAGE".to_string(),
            MEM_MAPPED => "MEM_MAPPED".to_string(),
            MEM_PRIVATE => "MEM_PRIVATE".to_string(),
            0 => "none".to_string(),
            _ => format!("0x{memory_type:x}"),
        }
    }

    /// Extract the low-byte page-protection value, excluding modifier bits.
    #[pyfunction]
    fn protection_base(protect: u32) -> u32 {
        protect & PAGE_PROTECTION_BASE_MASK
    }

    /// Format base protection and GUARD/NOCACHE/WRITECOMBINE modifiers for display.
    #[pyfunction]
    fn protection_text(protect: u32) -> String {
        let mut flags = Vec::new();

        flags.push(match protection_base(protect) {
            PAGE_NOACCESS => "NOACCESS".to_string(),
            PAGE_READONLY => "R".to_string(),
            PAGE_READWRITE => "RW".to_string(),
            PAGE_WRITECOPY => "WC".to_string(),
            PAGE_EXECUTE => "X".to_string(),
            PAGE_EXECUTE_READ => "RX".to_string(),
            PAGE_EXECUTE_READWRITE => "RWX".to_string(),
            PAGE_EXECUTE_WRITECOPY => "XWC".to_string(),
            value => format!("0x{value:x}"),
        });

        if protect & PAGE_GUARD != 0 {
            flags.push("GUARD".to_string());
        }
        if protect & PAGE_NOCACHE != 0 {
            flags.push("NOCACHE".to_string());
        }
        if protect & PAGE_WRITECOMBINE != 0 {
            flags.push("WRITECOMBINE".to_string());
        }

        flags.join("|")
    }

    /// Test whether the base protection is executable, ignoring modifier bits.
    #[pyfunction]
    fn is_executable_protection(protect: u32) -> bool {
        matches!(
            protection_base(protect),
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        )
    }

    /// Return whether GUARD is clear and the base protection is not NOACCESS.
    ///
    /// This is a protection-only heuristic, not a memory read or a guarantee that
    /// an address is committed or accessible.
    #[pyfunction]
    fn is_readable_protection(protect: u32) -> bool {
        protect & PAGE_GUARD == 0 && protection_base(protect) != PAGE_NOACCESS
    }

    /// Test for executable read/write or executable copy-on-write base protection.
    #[pyfunction]
    fn is_writable_executable_protection(protect: u32) -> bool {
        matches!(protection_base(protect), PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    }
}
