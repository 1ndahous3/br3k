use super::*;

#[test]
fn records_classes_constants_and_distinct_enum_registrations() {
    let mut exports = Exports::default();
    let root = syn::parse_quote! {
        fn module_exec() {
            extend_module!(vm, module, { "Handle" => resources::Handle::make_static_type(), "PAGE_TEST" => vm.ctx.new_int(PAGE_TEST) });
            register_enum!(vm, module, int_enum, fs::FileMode);
        }
    };
    let nested = syn::parse_quote! {
        fn module_exec() {
            extend_module!(vm, module, { "Handle" => resources::Handle::make_static_type() });
            register_enum_as!(vm, module, int_enum, "Mode", fs::FileMode);
        }
    };
    exports.collect("br3k", &root).unwrap();
    exports.collect("br3k.resource", &nested).unwrap();
    assert_eq!(exports.canonical_classes()["Handle"], "br3k.resource.Handle");
    assert_eq!(exports.constants["br3k.PAGE_TEST"], "int");
    assert_eq!(exports.enums["br3k.FileMode"], "fs::FileMode");
    assert_eq!(exports.enums["br3k.resource.Mode"], "fs::FileMode");
    assert_eq!(exports.classes.len(), 2);
}
