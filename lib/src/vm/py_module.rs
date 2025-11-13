use crate::vm::prelude::*;


extern "C"
fn test_func(
    a1: u64, a2: u64, a3: u64, a4: u64,
    a5: u64, a6: u64, a7: u64, a8: u64
) -> u64 {
    log::info!("test_func({a1}, {a2}, {a3}, {a4}, {a5}, {a6}, {a7}, {a8})");
    10
}

#[pymodule]
pub mod br3k {

    use crate::prelude::*;
    use crate::vm::prelude::*;
    use crate::vm;
    use crate::sysapi_ctx;
    use crate::sysapi;
    use crate::fs;

    use crate::cast_pfn;
    use crate::pe_module;
    use crate::shellcode;
    use crate::slog_info;

    use sysapi_ctx::SysApiCtx as api_ctx;
    use vm::py_resource::{Handle, BufferView};
    use vm::py_proc::Process;

    // own builtin functions

    use rustpython_vm::function::{ArgIntoBool, FuncArgs, KwArgs, PosArgs};
    use rustpython_vm::py_io::Write;

    #[derive(Debug, Default, FromArgs)]
    pub struct PrintOptions {
        #[pyarg(named, default)]
        sep: Option<PyStrRef>,
        #[pyarg(named, default)]
        end: Option<PyStrRef>,
        #[pyarg(named, default = ArgIntoBool::FALSE)]
        flush: ArgIntoBool,
        #[pyarg(named, default)]
        file: Option<PyObjectRef>,
    }

    #[pyfunction]
    fn print(objects: PosArgs, options: PrintOptions, vm: &VirtualMachine) -> PyResult<()> {

        let sep = options
            .sep
            .and_then(|s| Some(s.to_string()))
            .unwrap_or(" ".to_string());

        let _ = options.end;
        let _ = options.flush;
        let _ = options.file;

        let mut print_str = String::new();

        let mut first = true;
        for object in objects {
            if first {
                first = false;
            } else {
                print_str.push_str(sep.as_str());
            }

            print_str.push_str(object.str(vm)?.as_str());
        }

        slog_info!("{print_str}");
        Ok(())
    }

    #[derive(Default)]
    struct ExceptWriter;

    impl Write for ExceptWriter {

        type Error = PyBaseExceptionRef;
        fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> Result<(), Self::Error> {
            log::error!("{}", args.to_string().trim_end());
            Ok(())
        }
    }

    #[pyfunction]
    fn excepthook(
        exc_type: PyObjectRef,
        exc_val: PyObjectRef,
        exc_tb: PyObjectRef,
        vm: &VirtualMachine,
    ) -> PyResult<()> {

        let mut ewr: ExceptWriter = Default::default();

        match vm.normalize_exception(exc_type.clone(), exc_val.clone(), exc_tb) {
            Ok(exc) => {
                vm.write_exception(&mut ewr, &exc)
            },
            Err(_) => {
                let type_name = exc_val.class().name();
                let msg = format!(
                    "TypeError: print_exception(): Exception expected for value, {type_name} found\n"
                );

                log::error!("{msg}");
                Ok(())
            }
        }
    }

    //

    #[derive(FromArgs)]
    pub struct InitSysApiArgs {
        #[pyarg(any, default=false)]
        ntdll_alt_api: bool,
        #[pyarg(any, default=false)]
        ntdll_copy: bool,
    }

    #[pyfunction]
    fn init_sysapi(args: InitSysApiArgs) -> PyResult<()> {

        slog_info!("| System API options:");
        slog_info!("|   Load and use copy of ntdll.dll: {}", args.ntdll_copy);
        slog_info!("|   Use NT alternative API: {}", args.ntdll_alt_api);

        sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
            ntdll_copy: args.ntdll_copy,
            ntdll_alt_api: args.ntdll_alt_api,
        });

        Ok(())
    }

    #[derive(FromArgs)]
    pub struct GetModuleHandleArgs {
        #[pyarg(any)]
        module_name: String,
    }

    #[pyfunction]
    fn get_module_handle(args: GetModuleHandleArgs) -> PyResult<Option<u64>> {
        let module_name = CString::new(args.module_name).unwrap();

        match pe_module::get_module_handle(module_name.as_c_str()) {
            Some(handle) => Ok(Some(handle as u64)),
            None => Ok(None),
        }
    }

    #[pyfunction]
    fn fs_get_temp_folder() -> PyResult<String> {
        let temp_folder = fs::get_temp_folder();
        Ok(temp_folder)
    }

    #[derive(FromArgs)]
    pub struct FsCreateFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        #[pyarg(named)]
        file_mode: u32,
    }

    #[pyfunction]
    fn fs_create_file(args: FsCreateFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let file_mode = fs::FsFileMode::from_repr(args.file_mode)
            .ok_or_else(|| vm.new_value_error("Invalid FsFileMode".to_string()))?;

        let handle = sysapi::create_file(
            args.filepath.as_str(),
            file_mode.access_rights(),
            file_mode.share_mode(),
            0,
        )
        .map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create file: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(Handle {
            handle
        })
    }

    #[derive(FromArgs)]
    pub struct FsOpenFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
    }

    #[pyfunction]
    fn fs_open_file(args: FsOpenFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let handle = sysapi::open_file(args.filepath.as_str()).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to open file: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(Handle {
            handle
        })
    }

    #[derive(FromArgs)]
    pub struct FsWriteFileArgs {
        // TODO: PyMemoryView
        #[pyarg(any)]
        handle: PyRef<Handle>,
        #[pyarg(any)]
        data: usize,
        #[pyarg(any)]
        size: usize,
    }

    #[pyfunction]
    fn fs_write_file(args: FsWriteFileArgs, vm: &VirtualMachine) -> PyResult<()> {
        sysapi::write_file(*args.handle.handle, args.data as _, args.size).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to write file: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;
        Ok(())
    }

    #[derive(FromArgs)]
    pub struct FsCreateSectionArgs {
        #[pyarg(any)]
        handle: PyRef<Handle>,
        #[pyarg(named)]
        sect_mode: u32,
    }

    #[pyfunction]
    fn fs_create_file_section(args: FsCreateSectionArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let sect_mode = fs::FsSectionMode::from_repr(args.sect_mode)
            .ok_or_else(|| vm.new_value_error("Invalid FsSectionMode".to_string()))?;

        let handle = sysapi::create_file_section(
            *args.handle.handle,
            sect_mode.access_rights(),
            2,
            true,
            None,
        )
        .map_err(|e| {
            vm.new_system_error(format!(
                "Unable to create file section: {}",
                sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(Handle {
            handle
        })
    }

    #[derive(FromArgs)]
    pub struct PdbDownloadArgs {
        #[pyarg(any)]
        pe: PyRef<vm::py_pe::Pe>,
        #[pyarg(any)]
        folder_path: PyStrRef,
    }

    #[pyfunction]
    fn pdb_download(args: PdbDownloadArgs, vm: &VirtualMachine) -> PyResult<PyStr> {

        let pdb_filepath = crate::pdb::download_pdb(&args.pe.pe, args.folder_path.as_str())
            .map_err(|e| vm.new_system_error(format!("Failed to download PDB: {e}")))?;

        Ok(pdb_filepath.into())
    }

    #[pyfunction]
    fn shellcode_get_messageboxw(vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let data = shellcode::messageboxw();
        let bytes = vm.ctx.new_bytes(data.to_vec());
        Ok(bytes.into())
    }

    #[derive(FromArgs)]
    pub struct ShellcodeWriteExecViaRopGadgetArgs {
        #[pyarg(any)]
        process: PyRef<Process>,
        #[pyarg(any, optional)]
        ep: Option<u64>,
        #[pyarg(any, optional)]
        args: Option<Vec<u64>>
    }

    #[pyfunction]
    fn shellcode_write_exec_via_rop_gadget(args: ShellcodeWriteExecViaRopGadgetArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = args.process.memory.borrow_mut();
        let memory = memory
            .as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let function_address: *const u8 = match args.ep {
            Some(ep) => ep as _,
            None => super::test_func as *const () as _,
        };

        let shellcode = shellcode::lhiuct::shellcode_for_gadget(
            None,
            function_address,
            args.args.unwrap_or_default().as_slice(),
            false // aligned stack + ret address
        ).unwrap();

        memory.create_memory(shellcode.len())
            .map_err(|e| vm.new_system_error(format!(
                "Failed to create memory for shellcode: {}",
                sysapi::ntstatus_decode(e)
            )))?;

        memory.write_memory(
            0,
            shellcode.as_ptr() as _,
            shellcode.len()
        )
            .map_err(|e| vm.new_system_error(format!(
                "Failed to write shellcode to memory: {}",
                sysapi::ntstatus_decode(e)
            )))?;

        Ok(())
    }

    #[derive(FromArgs)]
    pub struct ShellcodeExecute {
        ep: u64,
    }

    #[pyfunction]
    fn shellcode_execute(args: ShellcodeExecute) -> PyResult<()> {
        unsafe {
            let func = cast_pfn!(args.ep, shellcode::rop::PFN_StdCallFunc0Args);
            func();
        }

        Ok(())
    }

    #[derive(FromArgs)]
    pub struct GetProcAddressArgs {
        #[pyarg(any)]
        module: PyStrRef,
        #[pyarg(any)]
        proc: PyStrRef,
    }

    #[pyfunction]
    fn get_proc_address(args: GetProcAddressArgs, vm: &VirtualMachine) -> PyResult<usize> {
        let address = api_ctx::get_proc_address(&args.module.as_str(), &args.proc.as_str())
            .map_err(|_| vm.new_system_error(
                format!(
                    "Failed to get proc address of {} ({})",
                    args.proc.as_str(),
                    args.module.as_str()
                )))?;


        Ok(address as _)
    }

    #[derive(FromArgs)]
    pub struct ExecuteRopLocalArgs {
        #[pyarg(any)]
        ep: u64,
        #[pyarg(any)]
        arg: Option<u64>
    }

    #[pyfunction]
    fn execute_rop_local(args: ExecuteRopLocalArgs) {
        unsafe {
            let func = cast_pfn!(args.ep, shellcode::rop::PFN_StdCallFunc1Args);

            if let Some(arg) = args.arg {
                func(arg as _);
            } else {
                func(ptr::null_mut());
            }
        }
    }

    #[pyfunction]
    fn rw_cave() -> BufferView {
        let cave = shellcode::rw_cave().unwrap();

        BufferView {
            ptr: cave.as_ptr() as _,
            size: cave.len() as _
        }
    }

    #[allow(non_snake_case)]
    #[pyfunction]
    fn gadget_KiUserCallForwarder(vm: &VirtualMachine) -> PyResult<u64> {
        match shellcode::ntdll::gadget_KiUserCallForwarder() {
            Some(gadget) => Ok(gadget.as_ptr() as _),
            None => Err(vm.new_system_error(
                "Failed to get proc address of KiUserCallForwarder (kernel32.dll)"
            ))
        }
    }

    #[pyfunction]
    fn adjust_debug_privilege(vm: &VirtualMachine) -> PyResult<()> {

        sysapi::adjust_privilege(windef::ntseapi::SE_DEBUG_PRIVILEGE).map_err(|e| {
            vm.new_system_error(format!(
                "Unable to get debug privilege: {}", sysapi::ntstatus_decode(e)
            ))
        })?;

        Ok(())
    }

    #[pyfunction]
    fn script_success() -> PyResult<()> {
        slog_info!("[+] Success");
        Ok(())
    }
}
