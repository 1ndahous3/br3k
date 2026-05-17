pub use rustpython_vm::{
    VirtualMachine, Interpreter,
    pyclass, pymodule,
    AsObject, TryFromObject, FromArgs,
    PyPayload,
    Py, PyRef, PyObjectRef, PyResult,
    class::PyClassImpl,
    types::Constructor,
    function::OptionalArg,
    builtins::{
        PyModule, PyType,
        PyStr, PyBytes,
        PyStrRef, PyBaseExceptionRef,
        PyDictRef
    }
};

use crate::vm::api_strategy;

use std::fmt;

pub fn to_py_system_error<E: fmt::Display>(vm: &VirtualMachine, context: &str, error: E) -> PyBaseExceptionRef {
    vm.new_system_error(format!("{context}: {error}"))
}

pub fn map_to_py_system_error<'vm, E: fmt::Display>(
    vm: &'vm VirtualMachine,
    context: &'static str,
) -> impl FnOnce(E) -> PyBaseExceptionRef + 'vm {
    move |error| to_py_system_error(vm, context, error)
}

pub fn to_py_value_error<E: fmt::Display>(vm: &VirtualMachine, context: &str, error: E) -> PyBaseExceptionRef {
    vm.new_value_error(format!("{context}: {error}"))
}

pub fn map_to_py_value_error<'vm, E: fmt::Display>(
    vm: &'vm VirtualMachine,
    context: &'static str,
) -> impl FnOnce(E) -> PyBaseExceptionRef + 'vm {
    move |error| to_py_value_error(vm, context, error)
}

pub fn process_memory_error_to_py_exception(
    vm: &VirtualMachine,
    context: &str,
    error: api_strategy::ProcessMemoryError,
) -> PyBaseExceptionRef {
    let message = format!("{context}: {error}");
    match error {
        api_strategy::ProcessMemoryError::MissingReadStrategy { .. } => vm.new_value_error(message),
        api_strategy::ProcessMemoryError::MissingWriteStrategy { .. } => vm.new_value_error(message),
        api_strategy::ProcessMemoryError::MissingLocalSectionMap { .. } => vm.new_value_error(message),
        _ => vm.new_system_error(message),
    }
}

pub fn map_process_memory_error_to_py_exception<'vm>(
    vm: &'vm VirtualMachine,
    context: &'static str,
) -> impl FnOnce(api_strategy::ProcessMemoryError) -> PyBaseExceptionRef + 'vm {
    move |error| process_memory_error_to_py_exception(vm, context, error)
}
