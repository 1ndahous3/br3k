use crate::vm::prelude::*;

use rustpython_vm::builtins::PyListRef;
use rustpython_vm::convert::ToPyObject;
use std::marker::PhantomData;

/// A Python list constructed from typed elements. Clones retain list identity.
/// Python may subsequently mutate it; this adapter never casts elements back to T.
#[derive(Debug)]
pub struct PyListOf<T> {
    object: PyListRef,
    element: PhantomData<fn() -> T>,
}

impl<T: ToPyObject> PyListOf<T> {
    pub fn new(items: Vec<T>, vm: &VirtualMachine) -> Self {
        Self { object: vm.ctx.new_list(items.into_iter().map(|item| item.to_pyobject(vm)).collect()), element: PhantomData }
    }
}

impl<T> Clone for PyListOf<T> {
    fn clone(&self) -> Self { Self { object: self.object.clone(), element: PhantomData } }
}

impl<T> ToPyObject for PyListOf<T> {
    fn to_pyobject(self, _vm: &VirtualMachine) -> PyObjectRef { self.object.into() }
}

impl<T> From<PyListOf<T>> for PyListRef {
    fn from(list: PyListOf<T>) -> Self { list.object }
}

impl<T> From<PyListOf<T>> for PyObjectRef {
    fn from(list: PyListOf<T>) -> Self { list.object.into() }
}

/// Conversion metadata for a Rust enum exposed as a Python IntEnum.
pub trait PythonEnum: Copy {
    fn python_type(vm: &VirtualMachine) -> PyResult<PyObjectRef>;
    fn value(self) -> u32;
}

/// A Python enum instance constructed from a concrete Rust enum value.
#[derive(Debug)]
pub struct PyEnumValue<E> {
    object: PyObjectRef,
    value: PhantomData<fn() -> E>,
}

impl<E: PythonEnum> PyEnumValue<E> {
    pub fn new(value: E, vm: &VirtualMachine) -> PyResult<Self> {
        let object = E::python_type(vm)?.call((value.value(),), vm)?;
        Ok(Self { object, value: PhantomData })
    }
}

impl<E> Clone for PyEnumValue<E> {
    fn clone(&self) -> Self { Self { object: self.object.clone(), value: PhantomData } }
}

impl<E> ToPyObject for PyEnumValue<E> {
    fn to_pyobject(self, _vm: &VirtualMachine) -> PyObjectRef { self.object }
}
