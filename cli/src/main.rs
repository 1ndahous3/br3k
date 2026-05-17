use clap::{Arg, Command};

use br3k::ipc;
use br3k::logging;
use br3k::sysapi::{self, ctx};
use br3k::vm;

use std::borrow::Cow;

use serde_yaml::{Mapping, Value};

fn script_var_from_yaml(name: &str, value: &Value) -> Result<vm::ScriptVarType, String> {
    match value {
        Value::Null => Ok(vm::ScriptVarType::None),
        Value::Bool(value) => Ok(vm::ScriptVarType::Boolean(*value)),
        Value::Number(value) => {
            let value = value.as_u64()
                .ok_or_else(|| format!("Variable '{name}' must be an unsigned integer"))?;
            let value = u32::try_from(value)
                .map_err(|_| format!("Variable '{name}' does not fit into u32"))?;
            Ok(vm::ScriptVarType::Number(value))
        }
        Value::String(value) => Ok(vm::ScriptVarType::String(Cow::Owned(value.clone()))),
        _ => Err(format!("Variable '{name}' has unsupported YAML type")),
    }
}

fn script_vars_from_yaml(variables: &Mapping) -> Result<vm::ScriptVars, String> {
    let mut script_vars = vm::ScriptVars::new();

    for (name, value) in variables {
        let name = name
            .as_str()
            .ok_or_else(|| "Config field 'variables' must contain only string keys".to_string())?;

        script_vars.insert(name.to_string(), script_var_from_yaml(name, value)?);
    }

    Ok(script_vars)
}

fn read_script_config(config_path: &str) -> Result<vm::ScriptVars, String> {
    let config_data = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Unable to read config file '{config_path}': {e}"))?;
    let config: Value = serde_yaml::from_str(&config_data)
        .map_err(|e| format!("Unable to parse config file '{config_path}': {e}"))?;

    let variables = config
        .get("variables")
        .ok_or_else(|| format!("Config file '{config_path}' is missing 'variables'"))?
        .as_mapping()
        .ok_or_else(|| format!("Config file '{config_path}' field 'variables' must be an object"))?;

    script_vars_from_yaml(variables)
}

fn main() {

    if let Err(e) = logging::init(true, false) {
        log::error!("Unable to initialize logger: {e}");
    }

    logging::log_header();

    let matches = Command::new("br3k")
        .arg(
            Arg::new("script")
                .long("script")
                .help("Path to the Python script to execute"),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .requires("script")
                .help("Path to a YAML config file with Python globals in the 'variables' object"),
        )
        .get_matches();

    if let Some(script_path) = matches.get_one::<String>("script") {
        log::info!("Mode: script file ({})", script_path);
        let script_vars = match matches.get_one::<String>("config") {
            Some(config_path) => match read_script_config(config_path) {
                Ok(script_vars) => Some(script_vars),
                Err(e) => {
                    log::error!("{e}");
                    std::process::exit(1);
                }
            },
            None => None,
        };

        let script_data = match std::fs::read_to_string(script_path) {
            Ok(script_data) => script_data,
            Err(e) => {
                log::error!("Unable to open script file: {e}");
                std::process::exit(1);
            }
        };

        let vm = vm::Vm::default();
        match vm.execute_script(&script_data, Some(script_path.clone()), &script_vars) {
            Ok(_) => {
                log::info!("Script executed successfully");
            }
            Err(_) => {
                log::error!("Error executing script");
                std::process::exit(1);
            }
        }
    } else {
        let pid: u32 = unsafe { (*sysapi::teb()).ClientId.UniqueProcess } as _;
        log::info!("Mode: IPC client ({pid})");

        if let Err(e) = ctx::SysApiCtx::init(ctx::InitOptions::default()) {
            log::error!("Unable to initialize system API context: {e}");
            std::process::exit(1);
        }

        let pipe_handle = match ipc::open_pipe(pid as _) {
            Ok(pipe_handle) => pipe_handle,
            Err(error) => {
                log::error!("Unable to open pipe: {error}");
                std::process::exit(1);
            }
        };

        let script_data = match ipc::receive_data(*pipe_handle) {
            Ok(script_data) => script_data,
            Err(error) => {
                log::error!("Unable to read script from pipe: {error}");
                std::process::exit(1);
            }
        };

        let script = match String::from_utf8(script_data) {
            Ok(script) => script,
            Err(e) => {
                log::error!("IPC script is not valid UTF-8: {e}");
                std::process::exit(1);
            }
        };

        let vm = vm::Vm::default();
        match vm.execute_script(&script, None, &None) {
            Ok(_) => {
                log::info!("Script executed successfully");
            }
            Err(_) => {
                log::error!("Error executing script");
                std::process::exit(1);
            }
        }
    }
}
