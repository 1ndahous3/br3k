use crate::vm::prelude::*;

use crate::pe::embedded::EmbeddedImage;

/// PE-shaped object found within a parent image. Its inferred layout determines whether parent code scans exclude its bytes.
#[pyclass(module = "br3k.pe.analysis", name = "EmbeddedImage")]
#[derive(Clone, Debug, PyPayload)]
pub struct PeEmbeddedImage {
    image: EmbeddedImage,
}

#[pyclass]
impl PeEmbeddedImage {
    /// Start offset in the parent image's stored byte buffer, not an independent process address.
    #[pygetset]
    fn offset(&self) -> usize { self.image.offset }

    /// Inferred file-layout extent in bytes.
    #[pygetset]
    fn file_size(&self) -> usize { self.image.file_size }

    /// SizeOfImage of the embedded candidate, in bytes.
    #[pygetset]
    fn mapped_size(&self) -> u32 { self.image.mapped_size }

    /// COFF machine value of the embedded candidate.
    #[pygetset]
    fn machine(&self) -> u16 { self.image.machine }

    /// Inferred file or mapped layout, or Ambiguous when both interpretations remain plausible.
    #[pygetset]
    fn layout(&self, vm: &VirtualMachine) -> PyResult<PyEnumValue<crate::pe::embedded::EmbeddedImageLayout>> {
        PyEnumValue::new(self.image.layout, vm)
    }

    /// Whether the candidate lies within a resource payload.
    #[pygetset]
    fn resource_backed(&self) -> bool { self.image.resource_backed }

    /// Whether the candidate is treated as embedded file data and excluded from parent-image code analysis.
    #[pygetset]
    fn excluded_from_parent(&self) -> bool { self.image.excluded_from_parent() }
}

pub(crate) fn embedded_images_to_py(images: Vec<EmbeddedImage>, vm: &VirtualMachine) -> PyListOf<PyRef<PeEmbeddedImage>> {
    PyListOf::new(images.into_iter().map(|image| PeEmbeddedImage { image }.into_ref(&vm.ctx)).collect(), vm)
}
