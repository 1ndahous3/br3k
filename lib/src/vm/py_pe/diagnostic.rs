use crate::vm::prelude::*;

use crate::pe::diagnostic as raw;

/// Stage, severity, and optional location for a retained analysis limitation.
#[pyclass(module = "br3k.pe.analysis", name = "Diagnostic")]
#[derive(Clone, Debug, PyPayload)]
pub struct Diagnostic { pub(crate) diagnostic: raw::Diagnostic }

#[pyclass]
impl Diagnostic {
    /// Analysis or build stage that produced this diagnostic.
    #[pygetset]
    fn stage(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::diagnostic::Stage>> { PyEnumValue::new(self.diagnostic.stage, vm) }
    /// Importance of the limitation or failure, not a malware-confidence score.
    #[pygetset]
    fn severity(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::diagnostic::Severity>> { PyEnumValue::new(self.diagnostic.severity, vm) }
    /// Human-readable explanation of the limitation or failure.
    #[pygetset]
    fn message(&self) -> String { self.diagnostic.message.clone() }
    /// Image-relative location when available, otherwise None.
    #[pygetset]
    fn rva(&self) -> Option<u32> { self.diagnostic.rva }
}

pub(crate) fn to_py(diagnostics: &[raw::Diagnostic], vm: &VirtualMachine) -> PyListOf<PyRef<Diagnostic>> {
    PyListOf::new(diagnostics.iter().cloned().map(|diagnostic| Diagnostic { diagnostic }.into_ref(&vm.ctx)).collect(), vm)
}
