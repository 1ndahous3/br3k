use crate::{fs, python, sysapi};
use python::api_strategy;

use rustpython_vm::{
    VirtualMachine, Interpreter,
    pyclass, pymodule,
    AsObject,
    PyPayload, PyRef,
    class::PyClassImpl,
    builtins::PyModule,
};

#[macro_export]
macro_rules! register_enum {
    ($vm:expr, $module:expr, $enum_type:path) => {{
        let enum_name = std::any::type_name::<$enum_type>()
            .rsplit("::")
            .next()
            .unwrap();

        let type_obj = $vm.ctx.new_class(
            Some(enum_name),
            enum_name,
            $vm.ctx.types.object_type.to_owned(),
            Default::default(),
        );

        for item in <$enum_type as strum::VariantArray>::VARIANTS {
            let name: &'static str = item.into();
            let attr_name = $vm.ctx.intern_str(name);
            let value = $vm.ctx.new_int(item.clone() as u32);
            type_obj.set_attr(attr_name, value.into());
        }

        $module.set_attr(enum_name, type_obj, $vm).unwrap();
    }};
}

#[pyclass(module = false, name = "Handle")]
#[derive(Debug, PyPayload)]
pub struct Handle {
    pub handle: sysapi::UniqueHandle,
}

#[pyclass]
impl Handle {}

#[pymodule]
pub mod br3k {

    use crate::prelude::*;
    use crate::{sysapi_ctx, sysapi, fs, python, pe_module, shellcode};

    use sysapi_ctx::SysApiCtx as api_ctx;
    use python::py_module::Handle;

    use rustpython_vm::{
        VirtualMachine,
        FromArgs,
        PyRef, PyObjectRef, PyResult,
        builtins::{PyStr, PyStrRef}
    };

    #[derive(FromArgs)]
    pub struct InitSysApiArgs {
        #[pyarg(any, default=false)]
        ntdll_alt_api: bool,
        #[pyarg(any, default=false)]
        ntdll_copy: bool,
    }

    #[pyfunction]
    fn init_sysapi(args: InitSysApiArgs) -> PyResult<()> {

        log::info!("| System API options:");
        log::info!("|   Load and use copy of ntdll.dll: {}", args.ntdll_copy);
        log::info!("|   Use NT alternative API: {}", args.ntdll_alt_api);

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
        pe: PyRef<python::py_pe::Pe>,
        #[pyarg(any)]
        folder_path: PyStrRef,
    }

    #[pyfunction]
    fn pdb_download(args: PdbDownloadArgs, vm: &VirtualMachine) -> PyResult<PyStr> {

        let pdb_filepath = crate::pdb::download_pdb(&args.pe.pe, args.folder_path.as_str())
            .map_err(|e| vm.new_system_error(format!(
                "Failed to download PDB: {}", e)))?;

        Ok(pdb_filepath.into())
    }

    #[pyfunction]
    fn shellcode_get_messageboxw(vm: &VirtualMachine) -> PyResult<PyObjectRef> {
        let data = shellcode::shellcode_messageboxw();
        let bytes = vm.ctx.new_bytes(data.to_vec());
        Ok(bytes.into())
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

    #[pyfunction]
    fn script_success() -> PyResult<()> {
        log::info!("[+] Success");
        Ok(())
    }
}


pub struct PythonCore {
    interpreter: Interpreter,
}

impl PythonCore {
    fn register_enums(vm: &VirtualMachine, module: &PyRef<PyModule>) {
        register_enum!(vm, module, api_strategy::ProcessMemoryStrategy);
        register_enum!(vm, module, api_strategy::ProcessOpenMethod);
        register_enum!(vm, module, fs::FsFileMode);
        register_enum!(vm, module, fs::FsSectionMode);
    }

    pub fn new() -> Self {
        let interpreter = Interpreter::with_init(Default::default(), |vm| {
            vm.add_frozen(rustpython_pylib::FROZEN_STDLIB);

            let br3k_module = br3k::make_module(vm);

            let module_classes = [
                ("Handle", Handle::make_class(&vm.ctx)),
                ("Process", python::py_proc::Process::make_class(&vm.ctx)),
                ("FileMapping", python::py_fs::FileMapping::make_class(&vm.ctx)),
                ("Pe", python::py_pe::Pe::make_class(&vm.ctx)),
                ("Transaction", python::py_tx::Transaction::make_class(&vm.ctx)),
                ("Pdb", python::py_pdb::Pdb::make_class(&vm.ctx)),
                ("PEB", python::py_proc::CPeb::make_class(&vm.ctx)),
                ("PRTL_USER_PROCESS_PARAMETERS", python::py_proc::CPUserProcessParameters::make_class(&vm.ctx)),
                ("PROCESS_BASIC_INFORMATION", python::py_proc::CProcessBasicInformation::make_class(&vm.ctx)),
                ("ComIRundown", python::py_com_irundown::ComIRundown::make_class(&vm.ctx)),
            ];

            for (name, class) in module_classes {
                br3k_module.set_attr(name, class, vm).unwrap();
            }

            Self::register_enums(vm, &br3k_module);

            vm.add_native_module("br3k".to_string(), Box::new(move |_vm| br3k_module.clone()))
        });

        Self { interpreter }
    }

    pub fn execute_script(&self, script: &str) -> Result<(), String> {
        self.interpreter
            .enter(|vm| {
                let scope = vm.new_scope_with_builtins();
                scope
                    .globals
                    .set_item("__name__", vm.ctx.new_str("__main__").into(), vm)
                    .map_err(|e| format!("Failed to set __name__: {:?}", e))?;

                vm.run_code_string(scope, script, "<script>".to_owned())
                    .map(drop)
                    .map_err(|e| {
                        let err_str = vm
                            .call_method(e.as_object(), "__str__", ())
                            .ok()
                            .and_then(|s| s.downcast::<rustpython_vm::builtins::PyStr>().ok())
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_else(|| "<unprintable>".into());
                        format!("Python error: {}", err_str)
                    })
            })
            .map_err(|e| format!("Interpreter error: {}", e))
    }
}
