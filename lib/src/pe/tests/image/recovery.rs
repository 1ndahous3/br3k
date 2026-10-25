use super::*;

#[test]
fn recovery_rejects_unrelated_reference_before_analysis() {
    let mapped = file_image().to_mapped().unwrap();
    let mut reference = file_image();
    reference.write_u32(reference.file_header_offset() + 4, 0x12345678).unwrap();
    let result = crate::pe::recovery::imports::Plan::from_image(mapped, &Default::default(), Default::default(), Some(reference));
    assert!(matches!(result, Err(crate::pe::recovery::imports::Error::Image(Error::ReferenceIdentity("timestamp")))));
}

#[test]
fn recovery_validation_uses_the_current_model() {
    let mapped = file_image().to_mapped().unwrap();
    let plan = crate::pe::recovery::imports::Plan::from_image(mapped, &Default::default(),
        crate::pe::recovery::imports::Options::from_strength(crate::pe::recovery::imports::ImportRecoveryStrength::Fast), None).unwrap();
    assert!(plan.validate(&plan.model).unwrap().is_empty());
    let mut edited = plan.model.clone();
    edited.add_module("missing.dll", 0x1000, 1).unwrap();
    assert!(!plan.validate(&edited).unwrap().is_empty());
    assert!(plan.validate(&plan.model).unwrap().is_empty());
    assert!(plan.build(&edited, Default::default()).is_err());
}
