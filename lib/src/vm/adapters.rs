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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::image::Layout;

    #[test]
    fn typed_list_clones_preserve_python_identity_and_mutations() {
        crate::vm::Vm::default().interpreter.enter(|vm| {
            let list = PyListOf::new(vec![vm.ctx.new_str("first")], vm);
            let copy = list.clone();
            list.object.borrow_vec_mut().push(vm.ctx.new_int(42).into());
            assert_eq!(copy.object.borrow_vec().len(), 2);
            assert!(list.to_pyobject(vm).is(&copy.to_pyobject(vm)));
            let empty = PyListOf::<PyRef<PyBytes>>::new(Vec::new(), vm);
            assert!(empty.object.borrow_vec().is_empty());
        });
    }

    #[test]
    fn typed_enums_use_registered_class_and_propagate_lookup_errors() {
        crate::vm::Vm::default().interpreter.enter(|vm| {
            let pe = vm.import("br3k", 0).unwrap().get_attr("pe", vm).unwrap();
            let class = pe.get_attr("Layout", vm).unwrap();
            let value = PyEnumValue::new(Layout::File, vm).unwrap().to_pyobject(vm);
            assert!(value.class().as_object().is(&class));
            let expected = class.get_attr("File", vm).unwrap();
            assert!(value.is(&expected));
            pe.set_attr("Layout", vm.ctx.none(), vm).unwrap();
            assert!(PyEnumValue::new(Layout::Mapped, vm).is_err());
        });
    }
}
