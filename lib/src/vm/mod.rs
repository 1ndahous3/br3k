pub mod py_module;

mod prelude;
mod adapters;
mod py_com_irundown;
mod py_fs;
mod py_br3k_ipc;
mod py_mem;
mod py_pdb;
mod py_pe;
mod py_proc;
mod py_resource;
mod py_thread;
mod py_threadpool;
mod py_tx;

mod api_strategy;
mod config;

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

use prelude::*;
use py_module::br3k;

pub use config::{
    read_script_config, script_var_log_value, script_var_to_py_object, script_vars_to_py_object,
};

use std::borrow::Cow;
use std::collections::HashMap;
use std::result::Result;

#[derive(Clone)]
pub enum ScriptVarType {
    String(Cow<'static, str>),
    Number(u32),
    Boolean(bool),
    None,
    List(Vec<ScriptVarType>),
    Object(HashMap<String, ScriptVarType>),
}

pub type ScriptVars = HashMap<String, ScriptVarType>;

#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("failed to set up Python VM: {0}")]
    RuntimeSetup(&'static str),
    #[error("br3k module is missing required attribute: {0}")]
    MissingBr3kAttribute(&'static str),
    #[error("script execution failed")]
    ScriptExecution,
}

pub struct Vm {
    interpreter: Interpreter,
}

impl Default for Vm {
    fn default() -> Self {
        let builder = Interpreter::builder(Default::default());
        let stdlib_defs = rustpython_stdlib::stdlib_module_defs(&builder.ctx);
        let br3k_def = br3k::module_def(&builder.ctx);

        let interpreter = builder
            .add_native_modules(&stdlib_defs)
            .add_frozen_modules(rustpython_pylib::FROZEN_STDLIB)
            .add_native_module(br3k_def)
            .build();

        Self { interpreter }
    }
}

impl Vm {
    pub fn execute_script(
        &self,
        script: &str,
        script_path: Option<String>,
        script_vars: &Option<ScriptVars>
    ) -> Result<(), VmError> {
        self.interpreter.enter(|vm| {
            let scope = vm.new_scope_with_builtins();

            let br3k_mod = vm.import("br3k", 0).map_err(|exc| {
                vm.print_exception(exc);
                VmError::RuntimeSetup("import br3k")
            })?;

            let print_fn = vm
                .get_attribute_opt(br3k_mod.clone(), "print")
                .map_err(|exc| {
                    vm.print_exception(exc);
                    VmError::RuntimeSetup("load br3k.print")
                })?
                .ok_or(VmError::MissingBr3kAttribute("print"))?;

            let excepthook_fn = vm
                .get_attribute_opt(br3k_mod.clone(), "excepthook")
                .map_err(|exc| {
                    vm.print_exception(exc);
                    VmError::RuntimeSetup("load br3k.excepthook")
                })?
                .ok_or(VmError::MissingBr3kAttribute("excepthook"))?;

            vm.sys_module.set_attr("excepthook", excepthook_fn, vm).map_err(|exc| {
                vm.print_exception(exc);
                VmError::RuntimeSetup("set sys.excepthook")
            })?;

            scope.globals.set_item("print", print_fn, vm).map_err(|exc| {
                vm.print_exception(exc);
                VmError::RuntimeSetup("set print")
            })?;

            scope.globals.set_item("__name__", vm.ctx.new_str("__main__").into(), vm).map_err(|exc| {
                vm.print_exception(exc);
                VmError::RuntimeSetup("set __name__")
            })?;

            let script_path = script_path.unwrap_or(String::from("<script>"));
            scope.globals.set_item("__file__", vm.ctx.new_str(script_path.clone()).into(), vm).map_err(|exc| {
                vm.print_exception(exc);
                VmError::RuntimeSetup("set __file__")
            })?;

            if let Some(script_vars) = script_vars {
                for var in script_vars {
                    log::info!("custom script variable: {}={}", var.0, script_var_log_value(var.1));
                    let value = script_var_to_py_object(var.0.as_str(), var.1, vm)?;

                    scope.globals.set_item(var.0.as_str(), value, vm).map_err(|exc| {
                        vm.print_exception(exc);
                        VmError::RuntimeSetup("set custom script variable")
                    })?;
                }
            }

            let res = vm.run_string(scope, script, script_path);

            match res {
                Ok(_) => Ok(()),
                Err(exc) => {
                    vm.print_exception(exc);
                    Err(VmError::ScriptExecution)
                }
            }
        })
    }
}
