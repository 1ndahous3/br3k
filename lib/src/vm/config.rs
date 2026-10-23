use super::prelude::*;

use super::{ScriptVarType, ScriptVars, VmError};

use std::borrow::Cow;
use std::collections::HashMap;
use std::result::Result;

use serde_yaml::{Mapping, Value};

pub fn script_var_from_yaml(name: &str, value: &Value) -> Result<ScriptVarType, String> {
    match value {
        Value::Null => Ok(ScriptVarType::None),
        Value::Bool(value) => Ok(ScriptVarType::Boolean(*value)),
        Value::Number(value) => {
            let value = value
                .as_u64()
                .ok_or_else(|| format!("Variable '{name}' must be an unsigned integer"))?;
            let value = u32::try_from(value)
                .map_err(|_| format!("Variable '{name}' does not fit into u32"))?;
            Ok(ScriptVarType::Number(value))
        }
        Value::String(value) => Ok(ScriptVarType::String(Cow::Owned(value.clone()))),
        Value::Sequence(values) => {
            let mut script_values = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                script_values.push(script_var_from_yaml(&format!("{name}[{index}]"), value)?);
            }

            Ok(ScriptVarType::List(script_values))
        }
        Value::Mapping(values) => {
            let mut script_values = HashMap::new();
            for (key, value) in values {
                let key = key
                    .as_str()
                    .ok_or_else(|| format!("Variable '{name}' object must contain only string keys"))?;
                script_values.insert(key.to_string(), script_var_from_yaml(&format!("{name}.{key}"), value)?);
            }

            Ok(ScriptVarType::Object(script_values))
        }
        _ => Err(format!("Variable '{name}' has unsupported YAML type")),
    }
}

pub fn script_vars_from_yaml(variables: &Mapping) -> Result<ScriptVars, String> {
    let mut script_vars = ScriptVars::new();

    for (name, value) in variables {
        let name = name
            .as_str()
            .ok_or_else(|| "Config field 'variables' must contain only string keys".to_string())?;

        script_vars.insert(name.to_string(), script_var_from_yaml(name, value)?);
    }

    Ok(script_vars)
}

pub fn read_script_config(config_path: &str) -> Result<ScriptVars, String> {
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

pub fn script_var_to_py_object(
    name: &str,
    value: &ScriptVarType,
    vm: &VirtualMachine,
) -> Result<PyObjectRef, VmError> {
    match value {
        ScriptVarType::String(str) => Ok(vm.ctx.new_str(str.as_ref()).into()),
        ScriptVarType::Number(num) => Ok(vm.ctx.new_int(*num).into()),
        ScriptVarType::Boolean(bool) => Ok(vm.ctx.new_bool(*bool).into()),
        ScriptVarType::None => Ok(vm.ctx.none().into()),
        ScriptVarType::List(values) => {
            let mut items = Vec::with_capacity(values.len());
            for (index, value) in values.iter().enumerate() {
                items.push(script_var_to_py_object(&format!("{name}[{index}]"), value, vm)?);
            }

            Ok(vm.ctx.new_list(items).into())
        }
        ScriptVarType::Object(values) => {
            let object = vm.ctx.new_dict();
            for (key, value) in values {
                let value = script_var_to_py_object(&format!("{name}.{key}"), value, vm)?;
                object.set_item(key.as_str(), value, vm).map_err(|exc| {
                    vm.print_exception(exc);
                    VmError::RuntimeSetup("set custom script object field")
                })?;
            }

            Ok(object.into())
        }
    }
}

pub fn script_vars_to_py_object(script_vars: &ScriptVars, vm: &VirtualMachine) -> Result<PyDictRef, VmError> {
    let object = vm.ctx.new_dict();
    for (name, value) in script_vars {
        let value = script_var_to_py_object(name, value, vm)?;
        object.set_item(name.as_str(), value, vm).map_err(|exc| {
            vm.print_exception(exc);
            VmError::RuntimeSetup("set config variable object field")
        })?;
    }

    Ok(object)
}

pub fn script_var_log_value(value: &ScriptVarType) -> String {
    match value {
        ScriptVarType::String(str) => str.to_string(),
        ScriptVarType::Number(num) => num.to_string(),
        ScriptVarType::Boolean(bool) => bool.to_string(),
        ScriptVarType::None => "None".to_string(),
        ScriptVarType::List(values) => format!("[{} values]", values.len()),
        ScriptVarType::Object(values) => format!("{{{} fields}}", values.len()),
    }
}
