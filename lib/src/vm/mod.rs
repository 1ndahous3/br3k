pub mod py_module;

mod prelude;
mod py_fs;
mod py_pe;
mod py_proc;
mod py_ipc;
mod py_tx;
mod py_pdb;
mod py_com_irundown;

mod api_strategy;


// (s)cript logging

#[macro_export]
macro_rules! slog_info {
    ($($arg:tt)*) => {
        log::info!("[script] {}", format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! slog_warn {
    ($($arg:tt)*) => {
        log::warn!("[script] {}", format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! slog_error {
    ($($arg:tt)*) => {
        log::error!("[script] {}", format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! slog_debug {
    ($($arg:tt)*) => {
        log::debug!("[script] {}", format_args!($($arg)*));
    }
}

#[macro_export]
macro_rules! slog_trace {
    ($($arg:tt)*) => {
        log::trace!("[script] {}", format_args!($($arg)*));
    }
}

//

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

use prelude::*;
use crate::fs;

use py_module::Handle;
use py_module::br3k;

pub struct Vm {
    interpreter: Interpreter,
}

impl Default for Vm {
    fn default() -> Self {
        let interpreter = Interpreter::with_init(Default::default(), |vm| {
            vm.add_frozen(rustpython_pylib::FROZEN_STDLIB);

            let br3k_module = br3k::make_module(vm);

            let module_classes = [
                ("Handle", Handle::make_class(&vm.ctx)),
                ("Process", py_proc::Process::make_class(&vm.ctx)),
                ("Ipc", py_ipc::Ipc::make_class(&vm.ctx)),
                ("FileMapping", py_fs::FileMapping::make_class(&vm.ctx)),
                ("Pe", py_pe::Pe::make_class(&vm.ctx)),
                ("Transaction", py_tx::Transaction::make_class(&vm.ctx)),
                ("Pdb", py_pdb::Pdb::make_class(&vm.ctx)),
                ("PEB", py_proc::CPeb::make_class(&vm.ctx)),
                ("PRTL_USER_PROCESS_PARAMETERS", py_proc::CPUserProcessParameters::make_class(&vm.ctx)),
                ("PROCESS_BASIC_INFORMATION", py_proc::CProcessBasicInformation::make_class(&vm.ctx)),
                ("ComIRundown", py_com_irundown::ComIRundown::make_class(&vm.ctx)),
            ];

            for (name, class) in module_classes {
                br3k_module.set_attr(name, class, vm).unwrap();
            }

            Self::register_enums(vm, &br3k_module);

            vm.add_native_module("br3k".to_string(), Box::new(move |_vm| br3k_module.clone()))
        });

        Self { interpreter }
    }
}

impl Vm {
    fn register_enums(vm: &VirtualMachine, module: &PyRef<PyModule>) {
        register_enum!(vm, module, api_strategy::ProcessMemoryStrategy);
        register_enum!(vm, module, api_strategy::ProcessOpenMethod);
        register_enum!(vm, module, fs::FsFileMode);
        register_enum!(vm, module, fs::FsSectionMode);
    }    

    pub fn execute_script(&self, script: &str, script_path: Option<String>) -> Result<(), String> {
        self.interpreter
            .enter(|vm| {
                let scope = vm.new_scope_with_builtins();
                scope
                    .globals
                    .set_item("__name__", vm.ctx.new_str("__main__").into(), vm)
                    .map_err(|e| format!("Failed to set __name__: {e:?}"))?;

                vm.run_code_string(scope, script, script_path.unwrap_or(String::from("<script>")))
                    .map(drop)
                    .map_err(|e| {
                        let err_str = vm
                            .call_method(e.as_object(), "__str__", ())
                            .ok()
                            .and_then(|s| s.downcast::<rustpython_vm::builtins::PyStr>().ok())
                            .map(|s| s.as_str().to_string())
                            .unwrap_or_else(|| "<unprintable>".into());
                        format!("Python error: {err_str}")
                    })
            })
            .map_err(|e| format!("Interpreter error: {e}"))
    }
}