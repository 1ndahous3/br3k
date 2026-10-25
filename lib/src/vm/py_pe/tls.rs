use crate::vm::prelude::*;

use crate::pe::tls::{TlsCallback, TlsDirectory, TlsSanitizeResult};

/// One parsed TLS callback pointer. Reading this record never invokes the callback.
#[pyclass(module = "br3k.pe.tls", name = "Callback")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeTlsCallback {
    callback: TlsCallback,
}

#[pyclass]
impl PeTlsCallback {
    /// Zero-based position in the TLS callback array.
    #[pygetset]
    fn index(zelf: &Py<Self>) -> usize {
        zelf.callback.index
    }

    /// Callback virtual address recorded in the array.
    #[pygetset]
    fn address(zelf: &Py<Self>) -> u64 {
        zelf.callback.address
    }

    /// Callback RVA when its address can be represented relative to the image base; otherwise None.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> Option<u32> {
        zelf.callback.rva
    }

    /// Return a compact human-readable summary.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        match zelf.callback.rva {
            Some(rva) => format!(
                "#{index} va=0x{address:x} rva=0x{rva:x}",
                index = zelf.callback.index,
                address = zelf.callback.address,
            ),
            None => format!(
                "#{index} va=0x{address:x}",
                index = zelf.callback.index,
                address = zelf.callback.address,
            ),
        }
    }
}

/// Parsed TLS directory and callback table. Pointer fields are virtual addresses, not RVAs.
#[pyclass(module = "br3k.pe.tls", name = "Directory")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeTlsDirectory {
    directory: TlsDirectory,
}

#[pyclass]
impl PeTlsDirectory {
    /// RVA of the TLS directory.
    #[pygetset]
    fn rva(zelf: &Py<Self>) -> u32 {
        zelf.directory.rva
    }

    /// TLS data-directory size in bytes.
    #[pygetset]
    fn size(zelf: &Py<Self>) -> u32 {
        zelf.directory.size
    }

    /// Virtual address of the start of the TLS initialization template.
    #[pygetset]
    fn start_raw_data(zelf: &Py<Self>) -> u64 {
        zelf.directory.start_raw_data
    }

    /// Exclusive end virtual address of the TLS initialization template.
    #[pygetset]
    fn end_raw_data(zelf: &Py<Self>) -> u64 {
        zelf.directory.end_raw_data
    }

    /// Virtual address of the loader-written TLS index.
    #[pygetset]
    fn address_of_index(zelf: &Py<Self>) -> u64 {
        zelf.directory.address_of_index
    }

    /// Virtual address of the null-terminated TLS callback array.
    #[pygetset]
    fn address_of_callbacks(zelf: &Py<Self>) -> u64 {
        zelf.directory.address_of_callbacks
    }

    /// Number of zero-initialized bytes following the TLS template.
    #[pygetset]
    fn size_of_zero_fill(zelf: &Py<Self>) -> u32 {
        zelf.directory.size_of_zero_fill
    }

    /// Raw TLS characteristics, including alignment bits.
    #[pygetset]
    fn characteristics(zelf: &Py<Self>) -> u32 {
        zelf.directory.characteristics
    }

    /// Number of parsed callback pointers.
    #[pygetset]
    fn callback_count(zelf: &Py<Self>) -> usize {
        zelf.directory.callbacks.len()
    }

    /// Whether the parsed callback array is nonempty.
    #[pygetset]
    fn has_callbacks(zelf: &Py<Self>) -> bool {
        !zelf.directory.callbacks.is_empty()
    }

    /// Parsed callback records in array order.
    #[pygetset]
    fn callbacks(zelf: &Py<Self>, vm: &VirtualMachine) -> PyListOf<PyRef<PeTlsCallback>> {
        tls_callbacks_to_py(&zelf.directory.callbacks, vm)
    }

    /// Return a compact human-readable summary.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "rva=0x{:x} size=0x{:x} callbacks={}",
            zelf.directory.rva,
            zelf.directory.size,
            zelf.directory.callbacks.len()
        )
    }
}

/// Local image bytes and an account of TLS fields cleared by a sanitization operation.
#[pyclass(module = "br3k.pe.tls", name = "SanitizeResult")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeTlsSanitizeResult {
    result: TlsSanitizeResult,
}

#[pyclass]
impl PeTlsSanitizeResult {
    /// Image bytes after the local TLS edit.
    #[pygetset]
    fn image(zelf: &Py<Self>, vm: &VirtualMachine) -> PyRef<PyBytes> {
        vm.ctx.new_bytes(zelf.result.image.clone())
    }

    /// Whether the input image had a TLS directory.
    #[pygetset]
    fn directory_present(zelf: &Py<Self>) -> bool {
        zelf.result.directory_present
    }

    /// Number of callbacks observed before sanitization.
    #[pygetset]
    fn callback_count(zelf: &Py<Self>) -> usize {
        zelf.result.callback_count
    }

    /// Whether the operation cleared the callback pointer.
    #[pygetset]
    fn cleared_callbacks(zelf: &Py<Self>) -> bool {
        zelf.result.cleared_callbacks
    }

    /// Whether the operation cleared the TLS data-directory entry.
    #[pygetset]
    fn cleared_directory(zelf: &Py<Self>) -> bool {
        zelf.result.cleared_directory
    }

    /// Return a compact human-readable summary.
    #[pymethod]
    fn summary(zelf: &Py<Self>) -> String {
        format!(
            "tls_present={} callbacks={} cleared_callbacks={} cleared_directory={}",
            zelf.result.directory_present,
            zelf.result.callback_count,
            zelf.result.cleared_callbacks,
            zelf.result.cleared_directory
        )
    }
}

pub(crate) fn tls_directory_to_py(
    directory: Option<TlsDirectory>,
    vm: &VirtualMachine,
) -> Option<PyRef<PeTlsDirectory>> {
    match directory {
        Some(directory) => Some(PeTlsDirectory { directory }.into_ref(&vm.ctx)),
        None => None,
    }
}

pub(crate) fn tls_sanitize_result_to_py(
    result: TlsSanitizeResult,
    vm: &VirtualMachine,
) -> PyRef<PeTlsSanitizeResult> {
    PeTlsSanitizeResult { result }.into_ref(&vm.ctx)
}

fn tls_callbacks_to_py(
    callbacks: &[TlsCallback],
    vm: &VirtualMachine,
) -> PyListOf<PyRef<PeTlsCallback>> {
    let callbacks = callbacks
        .iter()
        .cloned()
        .map(|callback| PeTlsCallback { callback }.into_ref(&vm.ctx))
        .collect::<Vec<_>>();

    PyListOf::new(callbacks, vm)
}
