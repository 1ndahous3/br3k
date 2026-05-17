use crate::vm::prelude::*;

extern "C" fn test_func(
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

    use crate::fs;
    use crate::sysapi::{self, backend, ctx};
    use crate::vm;

    use crate::cast_pfn;
    use crate::pe_module;
    use crate::shellcode;
    use crate::slog_info;

    use std::str::FromStr;

    use ctx::SysApiCtx as api_ctx;
    use vm::py_proc::Process;
    use vm::py_resource::{BufferView, Handle};

    // own builtin functions

    use rustpython_vm::function::{ArgIntoBool, PosArgs};
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
                print_str.push_str(&sep);
            }

            print_str.push_str(&object.str(vm)?.to_string());
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
    fn excepthook(exc_type: PyObjectRef, exc_val: PyObjectRef, exc_tb: PyObjectRef, vm: &VirtualMachine) -> PyResult<()> {
        let mut ewr: ExceptWriter = Default::default();

        match vm.normalize_exception(exc_type.clone(), exc_val.clone(), exc_tb) {
            Ok(exc) => vm.write_exception(&mut ewr, &exc),
            Err(_) => {
                let type_name = exc_val.class().name();
                let msg = format!("TypeError: print_exception(): Exception expected for value, {type_name} found\n");

                log::error!("{msg}");
                Ok(())
            }
        }
    }

    use rustpython_vm::extend_module;
    use crate::vm::{
        py_resource,
        py_proc,
        py_thread,
        py_fs,
        py_tx,
        py_pe,
        py_pdb,
        py_ipc,
        py_com_irundown
    };

    use crate::vm::api_strategy;

    macro_rules! register_enum {
        ($vm:expr, $module:expr, $int_enum:expr, $enum_type:path) => {{
            let enum_name = std::any::type_name::<$enum_type>()
                .rsplit("::")
                .next()
                .ok_or_else(|| {
                    $vm.new_system_error(format!("Failed to determine enum name for {}", std::any::type_name::<$enum_type>()))
                })?;

            let members = $vm.ctx.new_dict();

            for item in <$enum_type as strum::VariantArray>::VARIANTS {
                let name: &'static str = item.into();
                members.set_item(name, $vm.ctx.new_int(item.clone() as u32).into(), $vm)?;
            }

            let enum_obj = $int_enum.call((enum_name, members), $vm)?;
            $module.set_attr(enum_name, enum_obj, $vm)?;
        }};
    }

    fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
        extend_module!(vm, module, {
            "Handle" => py_resource::Handle::make_static_type(),
            "BufferView" => py_resource::BufferView::make_static_type(),
            "Process" => py_proc::Process::make_static_type(),
            "Thread" => py_thread::Thread::make_static_type(),
            "Ipc" => py_ipc::Ipc::make_static_type(),
            "FileMapping" => py_fs::FileMapping::make_static_type(),
            "Pe" => py_pe::Pe::make_static_type(),
            "Transaction" => py_tx::Transaction::make_static_type(),
            "Pdb" => py_pdb::Pdb::make_static_type(),
            "PEB" => py_proc::CPeb::make_static_type(),
            "PRTL_USER_PROCESS_PARAMETERS" => py_proc::CPUserProcessParameters::make_static_type(),
            "PROCESS_BASIC_INFORMATION" => py_proc::CProcessBasicInformation::make_static_type(),
            "ComIRundown" => py_com_irundown::ComIRundown::make_static_type(),
        });

        let enum_module = vm.import("enum", 0)?;
        let int_enum = enum_module.get_attr("IntEnum", vm)?;

        register_enum!(vm, module, int_enum, api_strategy::ProcessVmReadStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessVmWriteStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessOpenStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ThreadOpenStrategy);
        register_enum!(vm, module, int_enum, fs::FsFileMode);
        register_enum!(vm, module, int_enum, fs::FsSectionMode);

        Ok(())
    }

    //

    #[derive(FromArgs)]
    pub struct InitSysApiArgs {
        #[pyarg(named, optional)]
        sys_api_backend: OptionalArg<PyStrRef>,
        #[pyarg(named, optional)]
        sys_api_dispatch: OptionalArg<PyDictRef>,
    }

    fn parse_sys_api_dispatch_variant<T>(api_name: &str, variant: &str, vm: &VirtualMachine) -> PyResult<T>
    where
        T: FromStr,
    {
        variant
            .parse()
            .map_err(|_| vm.new_value_error(format!("Invalid system API dispatch variant for {api_name}: {variant}")))
    }

    fn parse_sys_api_dispatch(sys_api_dispatch: OptionalArg<PyDictRef>, vm: &VirtualMachine) -> PyResult<ctx::SysApiDispatchConfig> {
        let mut config = ctx::SysApiDispatchConfig::default();

        if let Some(sys_api_dispatch) = sys_api_dispatch.present() {
            for (api_name, variant) in &sys_api_dispatch {
                let api_name = PyStrRef::try_from_object(vm, api_name)?.to_string();
                let variant = PyStrRef::try_from_object(vm, variant)?.to_string();

                match api_name.as_str() {
                    "CreateProcess" => config.create_process = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "CreateThread" => config.create_thread = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "CreateSection" => config.create_section = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "MapViewOfSection" => config.map_view_of_section = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "UnmapViewOfSection" => config.unmap_view_of_section = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "AllocateVirtualMemory" => config.allocate_virtual_memory = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "ReadVirtualMemory" => config.read_virtual_memory = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    _ => return Err(vm.new_value_error(format!("Unknown system API dispatch target: {api_name}"))),
                }
            }
        }

        Ok(config)
    }

    fn parse_sys_api_backend(
        sys_api_backend: OptionalArg<PyStrRef>,
        vm: &VirtualMachine
    ) -> PyResult<backend::SysApiBackend> {
        if let Some(sys_api_backend) = sys_api_backend.present() {
            let sys_api_backend = sys_api_backend.to_string();
            return sys_api_backend
                .parse()
                .map_err(|_| vm.new_value_error(format!("Invalid system API backend: {sys_api_backend}")));
        }

        Ok(backend::SysApiBackend::default())
    }

    fn log_sys_api_dispatch(sys_api_dispatch: &ctx::SysApiDispatchConfig) {
        slog_info!("|   System API dispatch:");
        slog_info!("|     CreateProcess: {:?}", sys_api_dispatch.create_process);
        slog_info!("|     CreateThread: {:?}", sys_api_dispatch.create_thread);
        slog_info!("|     CreateSection: {:?}", sys_api_dispatch.create_section);
        slog_info!("|     MapViewOfSection: {:?}", sys_api_dispatch.map_view_of_section);
        slog_info!("|     UnmapViewOfSection: {:?}", sys_api_dispatch.unmap_view_of_section);
        slog_info!("|     AllocateVirtualMemory: {:?}", sys_api_dispatch.allocate_virtual_memory);
        slog_info!("|     ReadVirtualMemory: {:?}", sys_api_dispatch.read_virtual_memory);
    }

    #[pyfunction]
    fn init_sysapi(args: InitSysApiArgs, vm: &VirtualMachine) -> PyResult<()> {
        let sys_api_backend = parse_sys_api_backend(args.sys_api_backend, vm)?;
        let sys_api_dispatch = parse_sys_api_dispatch(args.sys_api_dispatch, vm)?;

        slog_info!("| System API options:");
        slog_info!("|   System API backend: {:?}", sys_api_backend);
        log_sys_api_dispatch(&sys_api_dispatch);

        ctx::SysApiCtx::init(ctx::InitOptions {
            sys_api_backend,
            sys_api_dispatch,
        }).map_err(map_to_py_system_error(vm, "Unable to initialize system API"))?;

        Ok(())
    }

    #[derive(FromArgs)]
    pub struct GetModuleHandleArgs {
        #[pyarg(any)]
        module_name: String,
    }

    #[pyfunction]
    fn get_module_handle(args: GetModuleHandleArgs, vm: &VirtualMachine) -> PyResult<Option<u64>> {
        let invalid_module_name = |_| vm.new_value_error("module name contains an interior NUL".to_string());
        let module_name = CString::new(args.module_name)
            .map_err(invalid_module_name)?;

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
    pub struct FsGetTempPathArgs {
        #[pyarg(any, optional)]
        filename: OptionalArg<PyStrRef>,
    }

    #[pyfunction]
    fn fs_get_temp_path(args: FsGetTempPathArgs) -> PyResult<String> {
        let mut temp_path = std::env::temp_dir();

        if let Some(filename) = args.filename.present() {
            temp_path.push(filename.to_string());
        }

        Ok(temp_path.to_string_lossy().into_owned())
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

        let handle = sysapi::create_file(&args.filepath.to_string(), file_mode.access_rights(), file_mode.share_mode(), 0)
            .map_err(map_to_py_system_error(vm, "Unable to create file"))?;

        Ok(Handle { handle })
    }

    #[derive(FromArgs)]
    pub struct FsOpenFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
    }

    #[pyfunction]
    fn fs_open_file(args: FsOpenFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let handle = sysapi::open_file(&args.filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to open file"))?;

        Ok(Handle { handle })
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
        sysapi::write_file(*args.handle.handle, args.data as _, args.size)
            .map_err(map_to_py_system_error(vm, "Unable to write file"))?;
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
        let invalid_section_mode = || vm.new_value_error("Invalid FsSectionMode".to_string());
        let sect_mode = fs::FsSectionMode::from_repr(args.sect_mode)
            .ok_or_else(invalid_section_mode)?;

        let handle = sysapi::create_file_section(*args.handle.handle, sect_mode.access_rights(), 2, true, None)
            .map_err(map_to_py_system_error(vm, "Unable to create file section"))?;

        Ok(Handle { handle })
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
        let pdb_filepath = crate::pdb::download_pdb(&args.pe.pe, &args.folder_path.to_string())
            .map_err(map_to_py_system_error(vm, "Failed to download PDB"))?;

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
        args: Option<Vec<u64>>,
    }

    #[pyfunction]
    fn shellcode_write_exec_via_rop_gadget(args: ShellcodeWriteExecViaRopGadgetArgs, vm: &VirtualMachine) -> PyResult<()> {
        let mut memory = args.process.memory.borrow_mut();
        let memory = memory.as_mut()
            .ok_or_else(|| vm.new_value_error("Memory context is not initialized".to_string()))?;

        let function_address: *const u8 = match args.ep {
            Some(ep) => ep as _,
            None => super::test_func as *const () as _,
        };

        let shellcode = shellcode::lhiuct::shellcode_for_gadget(
            None,
            function_address,
            args.args.unwrap_or_default().as_slice(),
            false, // aligned stack + ret address
        )
        .ok_or_else(|| vm.new_system_error("Failed to build shellcode for ROP gadget".to_string()))?;

        memory
            .create_memory(shellcode.len())
            .map_err(map_process_memory_error_to_py_exception(vm, "Failed to create memory for shellcode"))?;

        memory
            .write_memory(
                0,
                shellcode.as_ptr() as _,
                shellcode.len()
            )
            .map_err(map_process_memory_error_to_py_exception(vm, "Failed to write shellcode to memory"))?;

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
        let module = args.module.to_string();
        let proc = args.proc.to_string();

        let address = api_ctx::get_proc_address(&module, &proc)
            .map_err(map_to_py_system_error(vm, "Unable to get procedure address"))?;

        Ok(address as _)
    }

    #[derive(FromArgs)]
    pub struct ExecuteRopLocalArgs {
        #[pyarg(any)]
        ep: u64,
        #[pyarg(any)]
        arg: Option<u64>,
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
    fn rw_cave(vm: &VirtualMachine) -> PyResult<BufferView> {
        let cave = shellcode::rw_cave()
            .ok_or_else(|| vm.new_system_error("Failed to find RW cave".to_string()))?;

        Ok(BufferView { ptr: cave.as_ptr() as _, size: cave.len() as _ })
    }

    #[allow(non_snake_case)]
    #[pyfunction]
    fn gadget_KiUserCallForwarder(vm: &VirtualMachine) -> PyResult<u64> {
        match shellcode::ntdll::gadget_KiUserCallForwarder() {
            Some(gadget) => Ok(gadget.as_ptr() as _),
            None => Err(vm.new_system_error("Failed to get proc address of KiUserCallForwarder (kernel32.dll)")),
        }
    }

    #[pyfunction]
    fn adjust_debug_privilege(vm: &VirtualMachine) -> PyResult<()> {
        sysapi::adjust_privilege(windef::ntseapi::SE_DEBUG_PRIVILEGE)
            .map_err(map_to_py_system_error(vm, "Unable to get debug privilege"))?;

        Ok(())
    }

}
