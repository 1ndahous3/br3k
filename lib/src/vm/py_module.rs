use crate::vm::prelude::*;

extern "C" fn test_func(
    a1: u64, a2: u64, a3: u64, a4: u64,
    a5: u64, a6: u64, a7: u64, a8: u64
) -> u64 {
    log::info!("test_func({a1}, {a2}, {a3}, {a4}, {a5}, {a6}, {a7}, {a8})");
    10
}

/// Windows research primitives for the embedded br3k Python VM.
///
/// Use only for authorized, non-malicious education, research, and testing.
/// Import feature namespaces (`proc`, `fs`, `pe`, and others) for new scripts;
/// the root also retains older names for compatibility. This is an embedded
/// module provided by br3k-cli/br3k-dll, not a package installed into CPython.
///
/// Addresses are integers in the address space specified by each operation;
/// lengths and offsets are bytes unless documented otherwise. Native resources
/// and executable addresses require valid lifetimes and matching target ABIs.
/// Invalid pointers may crash the host rather than produce a Python exception.
/// Most OS failures become `SystemError`; argument/state errors commonly become
/// `ValueError` or `TypeError`. Availability depends on Windows build, access
/// rights, target architecture, and the chosen system API backend.
///
/// `= ...` in generated signatures means optional, not a literal Ellipsis value.
/// Omission and `None` are different: only nullable parameters accept `None`.
/// Root and namespaced strategy enums are separately created IntEnum classes
/// with matching values; use one namespace consistently rather than testing identity.
#[pymodule]
pub mod br3k {

    use crate::prelude::*;
    use crate::vm::prelude::*;

    use crate::fs;
    use crate::sysapi::{self, backend, ctx};
    use crate::vm;

    use crate::cast_pfn;
    use crate::pe;
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

    /// Log the string representation of each object through the br3k script logger.
    ///
    /// `sep` defaults to a space. The compatibility arguments `end`, `flush`, and
    /// `file` are accepted but ignored; this function does not redirect output.
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

    /// Format an exception and traceback through the br3k error logger.
    ///
    /// Intended as the embedded VM's exception hook; accepts an exception type,
    /// value, and traceback (`None` when absent).
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
        py_mem,
        py_pe,
        py_pdb,
        py_br3k_ipc,
        py_com_irundown,
        py_threadpool
    };

    use crate::vm::api_strategy;

    macro_rules! register_enum_as {
        ($vm:expr, $module:expr, $int_enum:expr, $enum_name:expr, $enum_type:path) => {{
            let members = $vm.ctx.new_dict();

            for item in <$enum_type as strum::VariantArray>::VARIANTS {
                let name: &'static str = item.into();
                members.set_item(name, $vm.ctx.new_int(item.clone() as u32).into(), $vm)?;
            }

            let enum_obj = $int_enum.call(($enum_name, members), $vm)?;
            $module.set_attr($enum_name, enum_obj, $vm)?;
        }};
    }

    macro_rules! register_enum {
        ($vm:expr, $module:expr, $int_enum:expr, $enum_type:path) => {{
            let enum_name = std::any::type_name::<$enum_type>()
                .rsplit("::")
                .next()
                .ok_or_else(|| {
                    $vm.new_system_error(format!("Failed to determine enum name for {}", std::any::type_name::<$enum_type>()))
                })?;

            register_enum_as!($vm, $module, $int_enum, enum_name, $enum_type);
        }};
    }

    fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
        module.set_attr("__path__", vm.ctx.new_list(vec![]), vm)?;

        extend_module!(vm, module, {
            "Handle" => py_resource::Handle::make_static_type(),
            "BufferView" => py_resource::BufferView::make_static_type(),
            "Process" => py_proc::Process::make_static_type(),
            "Thread" => py_thread::Thread::make_static_type(),
            "ThreadPool" => py_threadpool::ThreadPool::make_static_type(),
            "Br3kIPC" => py_br3k_ipc::Br3kIPC::make_static_type(),
            "FileMapping" => py_fs::FileMapping::make_static_type(),
            "Transaction" => py_tx::Transaction::make_static_type(),
            "Pdb" => py_pdb::Pdb::make_static_type(),
            "PEB" => py_proc::CPeb::make_static_type(),
            "PRTL_USER_PROCESS_PARAMETERS" => py_proc::CPUserProcessParameters::make_static_type(),
            "PROCESS_BASIC_INFORMATION" => py_proc::CProcessBasicInformation::make_static_type(),
            "PROCESS_MODULE" => py_proc::CProcessModule::make_static_type(),
            "PROCESS_MEMORY_REGION" => py_proc::CProcessMemoryRegion::make_static_type(),
            "PROCESS_WORKING_SET_REGION" => py_proc::CProcessWorkingSetRegion::make_static_type(),
            "ProcessMemoryMap" => py_proc::CProcessMemoryMap::make_static_type(),
            "WORKER_FACTORY_BASIC_INFORMATION" => py_threadpool::CWorkerFactoryBasicInformation::make_static_type(),
            "ComIRundown" => py_com_irundown::ComIRundown::make_static_type(),
        });

        let enum_module = vm.import("enum", 0)?;
        let int_enum = enum_module.get_attr("IntEnum", vm)?;

        register_enum!(vm, module, int_enum, api_strategy::ProcessVmReadStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessVmWriteStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessOpenStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ThreadOpenStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessSuspendStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ProcessResumeStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ThreadSuspendStrategy);
        register_enum!(vm, module, int_enum, api_strategy::ThreadResumeStrategy);
        register_enum!(vm, module, int_enum, api_strategy::FileDeleteStrategy);
        register_enum!(vm, module, int_enum, api_strategy::FileOpenStrategy);
        register_enum!(vm, module, int_enum, api_strategy::FileRenameStrategy);
        register_enum!(vm, module, int_enum, api_strategy::FileChangeStrategy);
        register_enum!(vm, module, int_enum, py_threadpool::ThreadPoolWorkItem);
        register_enum!(vm, module, int_enum, fs::FsFileMode);
        register_enum!(vm, module, int_enum, fs::FsSectionMode);

        attach_native_submodule(vm, module, "br3k.pe", "pe", py_pe::api::pe::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.mem", "mem", py_mem::mem::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.fs", "fs", fs_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.pdb", "pdb", pdb_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.com", "com", com_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.ipc", "ipc", ipc_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.shellcode", "shellcode", shellcode_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.sysapi", "sysapi", sysapi_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.proc", "proc", proc_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.tx", "tx", tx_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.resource", "resource", resource_api::module_def(&vm.ctx))?;
        attach_native_submodule(vm, module, "br3k.config", "config", config_api::module_def(&vm.ctx))?;

        Ok(())
    }

    fn attach_native_submodule(
        vm: &VirtualMachine,
        parent: &Py<PyModule>,
        module_name: &'static str,
        attr_name: &'static str,
        module_def: &'static rustpython_vm::builtins::PyModuleDef,
    ) -> PyResult<()> {
        let module = module_def.create_module(vm)?;
        module_def.exec_module(vm, &module)?;

        vm.sys_module
            .get_attr("modules", vm)?
            .set_item(module_name, module.clone().into(), vm)?;
        parent.set_attr(attr_name, module, vm)?;

        Ok(())
    }

    //

    #[py_api]
    #[derive(FromArgs)]
    pub struct InitSysApiArgs {
        /// Dll (default), DllCopy, or DirectSyscall; names are case-sensitive.
        #[pyarg(named, optional)]
        sys_api_backend: OptionalArg<PyStrRef>,
        /// Dispatch target names to variant names; omitted entries retain their defaults.
        #[pyi(ty = "dict[str, str]")]
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
                    "QueueApcThread" => config.queue_apc_thread = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "SetInformation_Delete" => config.set_information_delete = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
                    "SetInformation_Rename" => config.set_information_rename = parse_sys_api_dispatch_variant(&api_name, &variant, vm)?,
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
        slog_info!("|     QueueApcThread: {:?}", sys_api_dispatch.queue_apc_thread);
        slog_info!("|     SetInformation_Delete: {:?}", sys_api_dispatch.set_information_delete);
        slog_info!("|     SetInformation_Rename: {:?}", sys_api_dispatch.set_information_rename);
    }

    /// Configure the engine-wide system API backend and dispatch choices.
    ///
    /// `sys_api_backend` accepts `Dll` (default), `DllCopy`, or `DirectSyscall`.
    /// `sys_api_dispatch` is a string-to-string mapping. Omitted entries use defaults;
    /// unknown keys, variants, or backend names raise `ValueError`. A selected call
    /// that is unavailable fails instead of retrying another variant. Configure this
    /// before creating native resources; it is not a per-object or per-call setting.
    ///
    /// Dispatch keys and variants (default first):
    /// - CreateProcess: NtCreateProcessEx, NtCreateProcess
    /// - CreateThread: NtCreateThreadEx, NtCreateThread
    /// - CreateSection: NtCreateSection, NtCreateSectionEx
    /// - MapViewOfSection: NtMapViewOfSection, NtMapViewOfSectionEx
    /// - UnmapViewOfSection: NtUnmapViewOfSection, NtUnmapViewOfSectionEx
    /// - AllocateVirtualMemory: NtAllocateVirtualMemory, NtAllocateVirtualMemoryEx
    /// - ReadVirtualMemory: NtReadVirtualMemory, NtReadVirtualMemoryEx
    /// - QueueApcThread: NtQueueApcThread, NtQueueApcThreadEx, NtQueueApcThreadEx2
    /// - SetInformation_Delete: FileDispositionInformation, FileDispositionInformationEx
    /// - SetInformation_Rename: FileRenameInformation, FileRenameInformationEx
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

    /// Return a locally loaded module's base address, or `None` if not found.
    ///
    /// Does not open a remote module or load a missing DLL. Interior NUL characters
    /// in `module_name` raise `ValueError`.
    #[pyfunction]
    fn get_module_handle(args: GetModuleHandleArgs, vm: &VirtualMachine) -> PyResult<Option<u64>> {
        let invalid_module_name = |_| vm.new_value_error("module name contains an interior NUL".to_string());
        let module_name = CString::new(args.module_name)
            .map_err(invalid_module_name)?;

        match pe::module::handle(module_name.as_c_str()) {
            Some(handle) => Ok(Some(handle as u64)),
            None => Ok(None),
        }
    }

    /// Return the current process's temporary-folder path without creating it.
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

    /// Return the temporary-directory path, optionally joined with `filename`.
    ///
    /// Does not create a file or choose a unique name. An absolute filename can
    /// replace the directory when joined; this is not a path-sanitization function.
    #[pyfunction]
    fn fs_get_temp_path(args: FsGetTempPathArgs) -> PyResult<String> {
        let mut temp_path = std::env::temp_dir();

        if let Some(filename) = args.filename.present() {
            temp_path.push(filename.to_string());
        }

        Ok(temp_path.to_string_lossy().into_owned())
    }

    #[derive(FromArgs)]
    pub struct ConfigReadVariablesArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
    }

    /// Read the `variables` mapping from a YAML script configuration.
    ///
    /// Returns a dictionary of supported scalar/container values. YAML null becomes
    /// Python `None`. Invalid files or unsupported config values raise `ValueError`;
    /// conversion failures raise `SystemError`. Does not inject globals into a VM.
    #[pyfunction]
    fn config_read_variables(args: ConfigReadVariablesArgs, py_vm: &VirtualMachine) -> PyResult<PyDictRef> {
        let script_vars = vm::read_script_config(&args.filepath.to_string())
            .map_err(|e| py_vm.new_value_error(e))?;

        vm::script_vars_to_py_object(&script_vars, py_vm)
            .map_err(|e| py_vm.new_system_error(format!("Unable to convert config variables: {e}")))
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsCreateFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        /// File access/share mode, independent of creation disposition.
        #[pyi(ty = "br3k.fs.FileMode | int")]
        #[pyarg(named)]
        file_mode: u32,
    }

    /// Create or overwrite a file with the requested `FileMode` and return an owning handle.
    ///
    /// The native create disposition is FILE_OVERWRITE_IF: existing content can
    /// be lost. Invalid modes raise `ValueError`, native errors `SystemError`.
    #[pyfunction]
    fn fs_create_file(args: FsCreateFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let file_mode = fs::FsFileMode::from_repr(args.file_mode)
            .ok_or_else(|| vm.new_value_error("Invalid FsFileMode".to_string()))?;

        let handle = sysapi::create_file(&args.filepath.to_string(), file_mode.access_rights(), file_mode.share_mode(), 0)
            .map_err(map_to_py_system_error(vm, "Unable to create file"))?;

        Ok(Handle { handle })
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsOpenFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        /// Defaults to FileMode.Read.
        #[pyi(ty = "br3k.fs.FileMode | int")]
        #[pyarg(named, optional)]
        file_mode: OptionalArg<u32>,
        /// Defaults to OpenStrategy.NtOpenFile.
        #[pyi(ty = "br3k.fs.OpenStrategy | int")]
        #[pyarg(named, optional)]
        file_open_strategy: OptionalArg<u32>,
    }

    /// Open an existing file and return an owning handle.
    ///
    /// Defaults to `FileMode.Read` and `OpenStrategy.NtOpenFile`. The NtCreateFile
    /// strategy also uses an existing-file disposition, not automatic file creation.
    #[pyfunction]
    fn fs_open_file(args: FsOpenFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
        let file_mode = args.file_mode
            .into_option()
            .map(|v| fs::FsFileMode::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FsFileMode".to_string())))
            .transpose()?
            .unwrap_or(fs::FsFileMode::Read);
        let file_open_strategy = args.file_open_strategy
            .into_option()
            .map(|v| api_strategy::FileOpenStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileOpenStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileOpenStrategy::NtOpenFile);

        let handle = file_open_strategy.open_file(&args.filepath.to_string(), &file_mode)
            .map_err(map_to_py_system_error(vm, "Unable to open file"))?;

        Ok(Handle { handle })
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsDeleteFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        /// Defaults to DeleteStrategy.NtDeleteFile.
        #[pyi(ty = "br3k.fs.DeleteStrategy | int")]
        #[pyarg(named, optional)]
        file_delete_strategy: OptionalArg<u32>,
    }

    /// Delete the named file using `DeleteStrategy.NtDeleteFile` by default.
    ///
    /// SetInformationFile uses the configured SetInformation_Delete dispatch.
    /// Deletion may be deferred until open handles close; native failures raise `SystemError`.
    #[pyfunction]
    fn fs_delete_file(args: FsDeleteFileArgs, vm: &VirtualMachine) -> PyResult<()> {
        let file_delete_strategy = args.file_delete_strategy
            .into_option()
            .map(|v| api_strategy::FileDeleteStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileDeleteStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileDeleteStrategy::NtDeleteFile);

        file_delete_strategy.delete_file(&args.filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to delete file"))?;

        Ok(())
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsRenameFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        #[pyarg(any)]
        new_filepath: PyStrRef,
        /// Defaults to RenameStrategy.Rename.
        #[pyi(ty = "br3k.fs.RenameStrategy | int")]
        #[pyarg(named, optional)]
        file_rename_strategy: OptionalArg<u32>,
    }

    /// Rename or copy/delete a file to `new_filepath`.
    ///
    /// Defaults to `RenameStrategy.Rename`, which uses SetInformation_Rename dispatch.
    /// `CopyDelete` is not atomic: a failure can leave a destination copy.
    #[pyfunction]
    fn fs_rename_file(args: FsRenameFileArgs, vm: &VirtualMachine) -> PyResult<()> {
        let file_rename_strategy = args.file_rename_strategy
            .into_option()
            .map(|v| api_strategy::FileRenameStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileRenameStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileRenameStrategy::Rename);

        file_rename_strategy.rename_file(&args.filepath.to_string(), &args.new_filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to rename file"))?;

        Ok(())
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsChangeFileArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        /// Defaults to ChangeStrategy.DeleteFile.
        #[pyi(ty = "br3k.fs.ChangeStrategy | int")]
        #[pyarg(named, optional)]
        file_change_strategy: OptionalArg<u32>,
        /// Used only by DeleteFile; defaults to DeleteStrategy.NtDeleteFile.
        #[pyi(ty = "br3k.fs.DeleteStrategy | int")]
        #[pyarg(named, optional)]
        file_delete_strategy: OptionalArg<u32>,
        /// Used only by OpenFile; defaults to OpenStrategy.NtOpenFile.
        #[pyi(ty = "br3k.fs.OpenStrategy | int")]
        #[pyarg(named, optional)]
        file_open_strategy: OptionalArg<u32>,
    }

    /// Delete a file or overwrite its content with zeros using the selected strategy.
    ///
    /// Defaults to `ChangeStrategy.DeleteFile`, `DeleteStrategy.NtDeleteFile`, and
    /// `OpenStrategy.NtOpenFile`. The delete/open strategies apply to their respective
    /// change modes. Zeroing is destructive but is not guaranteed secure erasure.
    #[pyfunction]
    fn fs_change_file(args: FsChangeFileArgs, vm: &VirtualMachine) -> PyResult<()> {
        let file_change_strategy = args.file_change_strategy
            .into_option()
            .map(|v| api_strategy::FileChangeStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileChangeStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileChangeStrategy::DeleteFile);
        let file_delete_strategy = args.file_delete_strategy
            .into_option()
            .map(|v| api_strategy::FileDeleteStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileDeleteStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileDeleteStrategy::NtDeleteFile);
        let file_open_strategy = args.file_open_strategy
            .into_option()
            .map(|v| api_strategy::FileOpenStrategy::from_repr(v)
                .ok_or_else(|| vm.new_value_error("Invalid FileOpenStrategy".to_string())))
            .transpose()?
            .unwrap_or(api_strategy::FileOpenStrategy::NtOpenFile);

        file_change_strategy.change_file(&args.filepath.to_string(), &file_delete_strategy, &file_open_strategy)
            .map_err(map_to_py_system_error(vm, "Unable to change file"))?;

        Ok(())
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

    /// Write `size` bytes from local pointer `data` to an open file handle.
    ///
    /// The caller must keep readable backing storage alive. `data` is an address,
    /// not Python bytes; prefer `write_bytes()` for ordinary file output.
    #[pyfunction]
    fn fs_write_file(args: FsWriteFileArgs, vm: &VirtualMachine) -> PyResult<()> {
        sysapi::write_file(*args.handle.handle, args.data as _, args.size)
            .map_err(map_to_py_system_error(vm, "Unable to write file"))?;
        Ok(())
    }

    #[derive(FromArgs)]
    pub struct FsReadBytesArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
    }

    /// Read an entire file into independent Python bytes. I/O failures raise `SystemError`.
    #[pyfunction]
    fn fs_read_bytes(args: FsReadBytesArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let data = std::fs::read(args.filepath.to_string())
            .map_err(map_to_py_system_error(vm, "Unable to read file"))?;

        Ok(vm.ctx.new_bytes(data))
    }

    #[derive(FromArgs)]
    pub struct FsWriteBytesArgs {
        #[pyarg(any)]
        filepath: PyStrRef,
        #[pyarg(any)]
        data: PyRef<PyBytes>,
    }

    /// Create or truncate a file and write Python bytes to it.
    ///
    /// Parent directories must already exist. I/O failures raise `SystemError`.
    #[pyfunction]
    fn fs_write_bytes(args: FsWriteBytesArgs, vm: &VirtualMachine) -> PyResult<()> {
        std::fs::write(args.filepath.to_string(), args.data.as_bytes())
            .map_err(map_to_py_system_error(vm, "Unable to write file"))?;

        Ok(())
    }

    #[py_api]
    #[derive(FromArgs)]
    pub struct FsCreateSectionArgs {
        #[pyarg(any)]
        handle: PyRef<Handle>,
        /// Section-handle access rights, not page-protection flags.
        #[pyi(ty = "br3k.fs.SectionMode | int")]
        #[pyarg(named)]
        sect_mode: u32,
    }

    /// Create an image section from an open file handle.
    ///
    /// `sect_mode` selects section-handle access rights; it does not change the
    /// read-only page-protection argument used by this wrapper. Returns an owning handle.
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

    /// Obtain the matching PDB for a native `br3k.pe.native.PtrImage` in `folder_path`.
    ///
    /// Uses PE debug identity and the core's download cache. Returns the local PDB
    /// path; lookup, download, and filesystem failures raise `SystemError`.
    #[pyfunction]
    fn pdb_download(args: PdbDownloadArgs, vm: &VirtualMachine) -> PyResult<PyStr> {
        let pdb_filepath = crate::pdb::download_pdb(&args.pe.pe, &args.folder_path.to_string())
            .map_err(map_to_py_system_error(vm, "Failed to download PDB"))?;

        Ok(pdb_filepath.into())
    }

    /// Return the built-in MessageBox payload bytes for the current build architecture.
    ///
    /// This does not allocate executable memory or execute the payload.
    #[pyfunction]
    fn shellcode_get_messageboxw(vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
        let data = shellcode::messageboxw();
        let bytes = vm.ctx.new_bytes(data.to_vec());
        Ok(bytes)
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

    /// Build and write an architecture-specific ROP-call payload through the process memory context.
    ///
    /// Requires an initialized write strategy. `ep=None` selects the built-in test
    /// function; `args` defaults to an empty list. This prepares memory but does not
    /// start a thread. Unsupported gadget generation raises `SystemError`.
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

    /// Call local address `ep` with the native zero-argument calling convention.
    ///
    /// The address must be executable and ABI-compatible. This is an unsafe native
    /// call: invalid code can crash or hang the host rather than raise a Python exception.
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

    /// Resolve a named export in a module loaded in the current process.
    ///
    /// The returned address is local, not automatically valid in another process.
    /// Missing modules/exports and invalid names raise `SystemError`.
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

    /// Call local address `ep` with one pointer-sized argument (`None` means null).
    ///
    /// The caller owns address validity, lifetime, and ABI compatibility. Despite the
    /// historical name, this wrapper directly calls the supplied address.
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

    /// Find a writable local code/data cave and return a non-owning buffer view.
    ///
    /// The result borrows a loaded module's memory, not newly allocated storage.
    /// Raises `SystemError` when no suitable cave is available.
    #[pyfunction]
    fn rw_cave(vm: &VirtualMachine) -> PyResult<BufferView> {
        let cave = shellcode::rw_cave()
            .ok_or_else(|| vm.new_system_error("Failed to find RW cave".to_string()))?;

        Ok(BufferView { ptr: cave.as_ptr() as _, size: cave.len() as _ })
    }

    /// Return the local address of an architecture-specific infinite-loop gadget.
    ///
    /// Raises `SystemError` when unavailable. Calling it can hang the calling thread.
    #[pyfunction]
    fn gadget_inf_loop(vm: &VirtualMachine) -> PyResult<u64> {
        match shellcode::rop::gadget_inf_loop() {
            Some(gadget) => Ok(gadget.as_ptr() as _),
            None => Err(vm.new_system_error("Failed to find infinite loop gadget")),
        }
    }

    /// Return the local KiUserCallForwarder gadget address, or raise `SystemError` if unavailable.
    #[allow(non_snake_case)]
    #[pyfunction]
    fn gadget_KiUserCallForwarder(vm: &VirtualMachine) -> PyResult<u64> {
        match shellcode::ntdll::gadget_KiUserCallForwarder() {
            Some(gadget) => Ok(gadget.as_ptr() as _),
            None => Err(vm.new_system_error("Failed to get proc address of KiUserCallForwarder (kernel32.dll)")),
        }
    }

    /// Enable SeDebugPrivilege on the current process token.
    ///
    /// Does not grant privileges absent from the token or bypass protected-process
    /// restrictions. Native failures raise `SystemError`.
    #[pyfunction]
    fn adjust_debug_privilege(vm: &VirtualMachine) -> PyResult<()> {
        sysapi::adjust_privilege(windef::ntseapi::SE_DEBUG_PRIVILEGE)
            .map_err(map_to_py_system_error(vm, "Unable to get debug privilege"))?;

        Ok(())
    }

    /// File I/O, native mappings, and explicit open/delete/rename/change strategies.
    ///
    /// Native path-based operations expect Windows filesystem paths; prefer
    /// absolute paths. `create_file` can overwrite existing content, `write_bytes`
    /// truncates, and change/delete operations are destructive. Mapping and
    /// section APIs expose local addresses and owning handles, not Python streams.
    ///
    /// Example (read-only):
    /// ```python
    /// from br3k import fs
    /// data = fs.read_bytes(r"C:\Windows\System32\notepad.exe")
    /// mapping = fs.Mapping(r"C:\Windows\System32\notepad.exe")
    /// size = mapping.size
    /// ```
    #[pymodule(name = "br3k.fs")]
    pub mod fs_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "FileMapping" => py_fs::FileMapping::make_static_type(),
                "Mapping" => py_fs::FileMapping::make_static_type(),
            });

            let enum_module = vm.import("enum", 0)?;
            let int_enum = enum_module.get_attr("IntEnum", vm)?;

            register_enum_as!(vm, module, int_enum, "FileMode", fs::FsFileMode);
            register_enum_as!(vm, module, int_enum, "SectionMode", fs::FsSectionMode);
            register_enum_as!(vm, module, int_enum, "OpenStrategy", api_strategy::FileOpenStrategy);
            register_enum_as!(vm, module, int_enum, "DeleteStrategy", api_strategy::FileDeleteStrategy);
            register_enum_as!(vm, module, int_enum, "RenameStrategy", api_strategy::FileRenameStrategy);
            register_enum_as!(vm, module, int_enum, "ChangeStrategy", api_strategy::FileChangeStrategy);

            Ok(())
        }

        /// Return the current process's temporary-folder path without creating it.
        #[pyfunction(name = "get_temp_folder")]
        fn get_temp_folder() -> PyResult<String> {
            super::fs_get_temp_folder()
        }

        /// Return the temporary-directory path, optionally joined with `filename`.
        ///
        /// Does not create a file or choose a unique name. An absolute filename can
        /// replace the directory when joined; this is not a path-sanitization function.
        #[pyfunction(name = "get_temp_path")]
        fn get_temp_path(args: super::FsGetTempPathArgs) -> PyResult<String> {
            super::fs_get_temp_path(args)
        }

        /// Create or overwrite a file with the requested `FileMode` and return an owning handle.
        ///
        /// The native create disposition is FILE_OVERWRITE_IF: existing content can
        /// be lost. Invalid modes raise `ValueError`, native errors `SystemError`.
        #[pyfunction(name = "create_file")]
        fn create_file(args: super::FsCreateFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
            super::fs_create_file(args, vm)
        }

        /// Open an existing file and return an owning handle.
        ///
        /// Defaults to `FileMode.Read` and `OpenStrategy.NtOpenFile`. The NtCreateFile
        /// strategy also uses an existing-file disposition, not automatic file creation.
        #[pyfunction(name = "open_file")]
        fn open_file(args: super::FsOpenFileArgs, vm: &VirtualMachine) -> PyResult<Handle> {
            super::fs_open_file(args, vm)
        }

        /// Delete the named file using `DeleteStrategy.NtDeleteFile` by default.
        ///
        /// SetInformationFile uses the configured SetInformation_Delete dispatch.
        /// Deletion may be deferred until open handles close; native failures raise `SystemError`.
        #[pyfunction(name = "delete_file")]
        fn delete_file(args: super::FsDeleteFileArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::fs_delete_file(args, vm)
        }

        /// Rename or copy/delete a file to `new_filepath`.
        ///
        /// Defaults to `RenameStrategy.Rename`, which uses SetInformation_Rename dispatch.
        /// `CopyDelete` is not atomic: a failure can leave a destination copy.
        #[pyfunction(name = "rename_file")]
        fn rename_file(args: super::FsRenameFileArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::fs_rename_file(args, vm)
        }

        /// Delete a file or overwrite its content with zeros using the selected strategy.
        ///
        /// Defaults to `ChangeStrategy.DeleteFile`, `DeleteStrategy.NtDeleteFile`, and
        /// `OpenStrategy.NtOpenFile`. The delete/open strategies apply to their respective
        /// change modes. Zeroing is destructive but is not guaranteed secure erasure.
        #[pyfunction(name = "change_file")]
        fn change_file(args: super::FsChangeFileArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::fs_change_file(args, vm)
        }

        /// Write `size` bytes from local pointer `data` to an open file handle.
        ///
        /// The caller must keep readable backing storage alive. `data` is an address,
        /// not Python bytes; prefer `write_bytes()` for ordinary file output.
        #[pyfunction(name = "write_file")]
        fn write_file(args: super::FsWriteFileArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::fs_write_file(args, vm)
        }

        /// Read an entire file into independent Python bytes. I/O failures raise `SystemError`.
        #[pyfunction(name = "read_bytes")]
        fn read_bytes(args: super::FsReadBytesArgs, vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
            super::fs_read_bytes(args, vm)
        }

        /// Create or truncate a file and write Python bytes to it.
        ///
        /// Parent directories must already exist. I/O failures raise `SystemError`.
        #[pyfunction(name = "write_bytes")]
        fn write_bytes(args: super::FsWriteBytesArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::fs_write_bytes(args, vm)
        }

        /// Create an image section from an open file handle.
        ///
        /// `sect_mode` selects section-handle access rights; it does not change the
        /// read-only page-protection argument used by this wrapper. Returns an owning handle.
        #[pyfunction(name = "create_file_section")]
        fn create_file_section(args: super::FsCreateSectionArgs, vm: &VirtualMachine) -> PyResult<Handle> {
            super::fs_create_file_section(args, vm)
        }
    }

    /// Matching-PDB downloads, symbol RVAs, and structure-field offsets.
    ///
    /// Resolve against the exact image build, then add the target module base to
    /// a symbol RVA. Field offsets are already byte offsets within their type.
    /// `download` accepts a native `pe.native.PtrImage`, not a `pe.Image` snapshot.
    #[pymodule(name = "br3k.pdb")]
    pub mod pdb_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "Pdb" => py_pdb::Pdb::make_static_type(),
            });

            Ok(())
        }

        /// Obtain the matching PDB for a native `br3k.pe.native.PtrImage` in `folder_path`.
        ///
        /// Uses PE debug identity and the core's download cache. Returns the local PDB
        /// path; lookup, download, and filesystem failures raise `SystemError`.
        #[pyfunction(name = "download")]
        fn download(args: super::PdbDownloadArgs, vm: &VirtualMachine) -> PyResult<PyStr> {
            super::pdb_download(args, vm)
        }
    }

    /// COM IRundown research bindings with explicit build-specific addresses.
    ///
    /// This is not general COM automation. The caller supplies matching COM
    /// module symbols and an initialized process read context. See IRundown for
    /// the constructor's base-address/RVA distinction and operation order.
    #[pymodule(name = "br3k.com")]
    pub mod com_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "IRundown" => py_com_irundown::ComIRundown::make_static_type(),
                "ComIRundown" => py_com_irundown::ComIRundown::make_static_type(),
            });

            Ok(())
        }
    }

    /// Named-pipe communication with the br3k component in a selected process.
    ///
    /// Channel and Br3kIPC refer to the same class. This protocol is specific
    /// to br3k; it is not a general named-pipe or RPC library.
    #[pymodule(name = "br3k.ipc")]
    pub mod ipc_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "Br3kIPC" => py_br3k_ipc::Br3kIPC::make_static_type(),
                "Channel" => py_br3k_ipc::Br3kIPC::make_static_type(),
            });

            Ok(())
        }
    }

    /// Architecture-specific payload bytes, local gadgets, and native call helpers.
    ///
    /// Generating bytes does not execute them. Execution methods accept raw
    /// addresses and do not validate memory permissions, instruction sets, or
    /// calling conventions. Availability differs between x86, AMD64, and ARM64;
    /// local addresses must not be assumed valid in another process.
    #[pymodule(name = "br3k.shellcode")]
    pub mod shellcode_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "BufferView" => py_resource::BufferView::make_static_type(),
            });

            Ok(())
        }

        /// Return the built-in MessageBox payload bytes for the current build architecture.
        ///
        /// This does not allocate executable memory or execute the payload.
        #[pyfunction(name = "messageboxw")]
        fn messageboxw(vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
            super::shellcode_get_messageboxw(vm)
        }

        /// Return the built-in MessageBox payload bytes for the current build architecture.
        ///
        /// This does not allocate executable memory or execute the payload.
        #[pyfunction(name = "get_messageboxw")]
        fn get_messageboxw(vm: &VirtualMachine) -> PyResult<PyRef<PyBytes>> {
            super::shellcode_get_messageboxw(vm)
        }

        /// Build and write an architecture-specific ROP-call payload through the process memory context.
        ///
        /// Requires an initialized write strategy. `ep=None` selects the built-in test
        /// function; `args` defaults to an empty list. This prepares memory but does not
        /// start a thread. Unsupported gadget generation raises `SystemError`.
        #[pyfunction(name = "write_exec_via_rop_gadget")]
        fn write_exec_via_rop_gadget(args: super::ShellcodeWriteExecViaRopGadgetArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::shellcode_write_exec_via_rop_gadget(args, vm)
        }

        /// Call local address `ep` with the native zero-argument calling convention.
        ///
        /// The address must be executable and ABI-compatible. This is an unsafe native
        /// call: invalid code can crash or hang the host rather than raise a Python exception.
        #[pyfunction(name = "execute")]
        fn execute(args: super::ShellcodeExecute) -> PyResult<()> {
            super::shellcode_execute(args)
        }

        /// Call local address `ep` with one pointer-sized argument (`None` means null).
        ///
        /// The caller owns address validity, lifetime, and ABI compatibility. Despite the
        /// historical name, this wrapper directly calls the supplied address.
        #[pyfunction(name = "execute_rop_local")]
        fn execute_rop_local(args: super::ExecuteRopLocalArgs) {
            super::execute_rop_local(args)
        }

        /// Find a writable local code/data cave and return a non-owning buffer view.
        ///
        /// The result borrows a loaded module's memory, not newly allocated storage.
        /// Raises `SystemError` when no suitable cave is available.
        #[pyfunction(name = "rw_cave")]
        fn rw_cave(vm: &VirtualMachine) -> PyResult<BufferView> {
            super::rw_cave(vm)
        }

        /// Return the local address of an architecture-specific infinite-loop gadget.
        ///
        /// Raises `SystemError` when unavailable. Calling it can hang the calling thread.
        #[pyfunction(name = "gadget_inf_loop")]
        fn gadget_inf_loop(vm: &VirtualMachine) -> PyResult<u64> {
            super::gadget_inf_loop(vm)
        }

        /// Return the local KiUserCallForwarder gadget address, or raise `SystemError` if unavailable.
        #[allow(non_snake_case)]
        #[pyfunction(name = "gadget_KiUserCallForwarder")]
        fn gadget_KiUserCallForwarder(vm: &VirtualMachine) -> PyResult<u64> {
            super::gadget_KiUserCallForwarder(vm)
        }
    }

    /// Engine-wide system API configuration and local export lookup.
    ///
    /// The CLI and DLL initialize default Dll dispatch before running scripts.
    /// Use `init()` at the start of a scenario to replace those choices.
    /// Backend selection only covers managed calls; helper calls without a
    /// syscall equivalent remain DLL calls. No selected dispatch variant silently
    /// falls back to another variant on failure.
    ///
    /// Example:
    /// ```python
    /// from br3k import sysapi
    /// sysapi.init(sys_api_backend="Dll", sys_api_dispatch={"CreateThread": "NtCreateThreadEx"})
    /// ```
    #[pymodule(name = "br3k.sysapi")]
    pub mod sysapi_api {
        use super::*;

        /// Configure the engine-wide system API backend and dispatch choices.
        ///
        /// `sys_api_backend` accepts `Dll` (default), `DllCopy`, or `DirectSyscall`.
        /// `sys_api_dispatch` is a string-to-string mapping. Omitted entries use defaults;
        /// unknown keys, variants, or backend names raise `ValueError`. A selected call
        /// that is unavailable fails instead of retrying another variant. Configure this
        /// before creating native resources; it is not a per-object or per-call setting.
        ///
        /// Dispatch keys and variants (default first):
        /// - CreateProcess: NtCreateProcessEx, NtCreateProcess
        /// - CreateThread: NtCreateThreadEx, NtCreateThread
        /// - CreateSection: NtCreateSection, NtCreateSectionEx
        /// - MapViewOfSection: NtMapViewOfSection, NtMapViewOfSectionEx
        /// - UnmapViewOfSection: NtUnmapViewOfSection, NtUnmapViewOfSectionEx
        /// - AllocateVirtualMemory: NtAllocateVirtualMemory, NtAllocateVirtualMemoryEx
        /// - ReadVirtualMemory: NtReadVirtualMemory, NtReadVirtualMemoryEx
        /// - QueueApcThread: NtQueueApcThread, NtQueueApcThreadEx, NtQueueApcThreadEx2
        /// - SetInformation_Delete: FileDispositionInformation, FileDispositionInformationEx
        /// - SetInformation_Rename: FileRenameInformation, FileRenameInformationEx
        #[pyfunction(name = "init")]
        fn init(args: super::InitSysApiArgs, vm: &VirtualMachine) -> PyResult<()> {
            super::init_sysapi(args, vm)
        }

        /// Return a locally loaded module's base address, or `None` if not found.
        ///
        /// Does not open a remote module or load a missing DLL. Interior NUL characters
        /// in `module_name` raise `ValueError`.
        #[pyfunction(name = "get_module_handle")]
        fn get_module_handle(args: super::GetModuleHandleArgs, vm: &VirtualMachine) -> PyResult<Option<u64>> {
            super::get_module_handle(args, vm)
        }

        /// Resolve a named export in a module loaded in the current process.
        ///
        /// The returned address is local, not automatically valid in another process.
        /// Missing modules/exports and invalid names raise `SystemError`.
        #[pyfunction(name = "get_proc_address")]
        fn get_proc_address(args: super::GetProcAddressArgs, vm: &VirtualMachine) -> PyResult<usize> {
            super::get_proc_address(args, vm)
        }

        /// Enable SeDebugPrivilege on the current process token.
        ///
        /// Does not grant privileges absent from the token or bypass protected-process
        /// restrictions. Native failures raise `SystemError`.
        #[pyfunction(name = "adjust_debug_privilege")]
        fn adjust_debug_privilege(vm: &VirtualMachine) -> PyResult<()> {
            super::adjust_debug_privilege(vm)
        }
    }

    /// Process/thread lifecycle, memory strategies, snapshots, and thread-pool experiments.
    ///
    /// Constructors configure wrappers; opening/creating and memory initialization
    /// are separate steps. Snapshot records are returned by query methods and
    /// generally have no public constructor. They are not live views of the target.
    ///
    /// Example (requires an already running notepad.exe and sufficient access):
    /// ```python
    /// from br3k import proc
    /// process = proc.Process(name="notepad.exe",
    ///     process_open_strategy=proc.ProcessOpenStrategy.OpenProcess,
    ///     process_vm_read_strategy=proc.ProcessVmReadStrategy.ReadVirtualMemory)
    /// process.open()
    /// process.init_memory()
    /// modules = process.modules()
    /// regions = process.memory_map().executable
    /// ```
    #[pymodule(name = "br3k.proc")]
    pub mod proc_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "Process" => py_proc::Process::make_static_type(),
                "Thread" => py_thread::Thread::make_static_type(),
                "ThreadPool" => py_threadpool::ThreadPool::make_static_type(),
                "PEB" => py_proc::CPeb::make_static_type(),
                "ProcessParameters" => py_proc::CPUserProcessParameters::make_static_type(),
                "BasicInformation" => py_proc::CProcessBasicInformation::make_static_type(),
                "Module" => py_proc::CProcessModule::make_static_type(),
                "MemoryRegion" => py_proc::CProcessMemoryRegion::make_static_type(),
                "MemoryMap" => py_proc::CProcessMemoryMap::make_static_type(),
                "WorkingSetRegion" => py_proc::CProcessWorkingSetRegion::make_static_type(),
                "ThreadInfo" => py_proc::CProcessThreadInfo::make_static_type(),
                "WorkerFactoryBasicInformation" => py_threadpool::CWorkerFactoryBasicInformation::make_static_type(),
            });

            let enum_module = vm.import("enum", 0)?;
            let int_enum = enum_module.get_attr("IntEnum", vm)?;

            register_enum_as!(vm, module, int_enum, "ProcessVmReadStrategy", api_strategy::ProcessVmReadStrategy);
            register_enum_as!(vm, module, int_enum, "ProcessVmWriteStrategy", api_strategy::ProcessVmWriteStrategy);
            register_enum_as!(vm, module, int_enum, "ProcessOpenStrategy", api_strategy::ProcessOpenStrategy);
            register_enum_as!(vm, module, int_enum, "ThreadOpenStrategy", api_strategy::ThreadOpenStrategy);
            register_enum_as!(vm, module, int_enum, "ProcessSuspendStrategy", api_strategy::ProcessSuspendStrategy);
            register_enum_as!(vm, module, int_enum, "ProcessResumeStrategy", api_strategy::ProcessResumeStrategy);
            register_enum_as!(vm, module, int_enum, "ThreadSuspendStrategy", api_strategy::ThreadSuspendStrategy);
            register_enum_as!(vm, module, int_enum, "ThreadResumeStrategy", api_strategy::ThreadResumeStrategy);
            register_enum_as!(vm, module, int_enum, "ThreadPoolWorkItem", py_threadpool::ThreadPoolWorkItem);

            Ok(())
        }
    }

    /// Native transactions with explicit thread attachment and rollback.
    ///
    /// Transaction participation depends on the filesystem and operation. Use
    /// `try/finally` to clear the calling thread's transaction, including after
    /// errors. This wrapper does not provide a context manager or commit method.
    #[pymodule(name = "br3k.tx")]
    pub mod tx_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "Transaction" => py_tx::Transaction::make_static_type(),
            });

            Ok(())
        }
    }

    /// Owning native handles and non-owning flat buffer views.
    ///
    /// Keep the bytes owner alive while any BufferView address is used:
    /// ```python
    /// from br3k import resource
    /// data = b"example"
    /// view = resource.BufferView(data)
    /// address, size = view.ptr, view.size
    /// ```
    /// A view does not retain `data` or grant permission to mutate immutable bytes.
    #[pymodule(name = "br3k.resource")]
    pub mod resource_api {
        use super::*;

        use rustpython_vm::extend_module;

        pub(super) fn module_exec(vm: &VirtualMachine, module: &Py<PyModule>) -> PyResult<()> {
            extend_module!(vm, module, {
                "Handle" => py_resource::Handle::make_static_type(),
                "BufferView" => py_resource::BufferView::make_static_type(),
            });

            Ok(())
        }
    }

    /// Read the same YAML `variables` configuration accepted by the CLI.
    ///
    /// Example configuration:
    /// ```yaml
    /// variables:
    ///   PROCESS_NAME: notepad.exe
    ///   OPTIONAL_PATH: null
    /// ```
    /// `read_variables(path)` returns values without changing script globals.
    /// Passing `--config path` to the CLI applies them before script execution.
    /// Values support strings, booleans, null, unsigned 32-bit integers, lists,
    /// and recursively nested string-keyed mappings. Floats, negative integers,
    /// integers above 0xffffffff, and custom YAML tags are rejected.
    #[pymodule(name = "br3k.config")]
    pub mod config_api {
        use super::*;

        /// Read the `variables` mapping from a YAML script configuration.
        ///
        /// Returns a dictionary of supported scalar/container values. YAML null becomes
        /// Python `None`. Invalid files or unsupported config values raise `ValueError`;
        /// conversion failures raise `SystemError`. Does not inject globals into a VM.
        #[pyfunction(name = "read_variables")]
        fn read_variables(args: super::ConfigReadVariablesArgs, vm: &VirtualMachine) -> PyResult<PyDictRef> {
            super::config_read_variables(args, vm)
        }
    }

}
