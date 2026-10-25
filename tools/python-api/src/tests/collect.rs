use super::*;

fn node(module: &str, item: Item) -> Node { Node { item, path: "fixture.rs".into(), rust_module: module.into(), py_module: None } }

#[test]
fn resolves_from_args_through_imports_without_name_guessing() {
    let nodes = vec![
        node("test::one", syn::parse_quote! {
            #[derive(FromArgs)] struct Args {
                /// Number of bytes to read.
                #[pyarg(any)] size: usize,
                #[pyi(ty = "str | None")] #[pyarg(named, optional)] label: OptionalArg<PyObjectRef>,
            }
        }),
        node("test::two", syn::parse_quote! { #[derive(FromArgs)] struct Args { #[pyarg(any)] wrong: bool } }),
        node("test::consumer", syn::parse_quote! { use super::one::*; }),
    ];
    let source = node("test::consumer", syn::parse_quote! { fn read(args: Args, vm: &VirtualMachine) {} });
    let Item::Fn(function) = &source.item else { unreachable!() };
    let context = Context { nodes, bindings: Vec::new(), registrations: Vec::new(), enums: BTreeMap::new() };
    let params = context.parameters(&function.sig, &[], &source, None).unwrap();
    assert_eq!(params.len(), 2);
    assert_eq!(params[0].name, "size");
    assert_eq!(params[0].doc, "Number of bytes to read.");
    assert_eq!(params[1].ty, "str | None");
    assert!(params[1].keyword && params[1].optional);
    let foreign = node("other", source.item.clone());
    assert!(context.parameters(&function.sig, &[], &foreign, None).is_err());
}

#[test]
fn rejects_parameter_override_typo_and_infers_nested_types() {
    let context = Context { nodes: Vec::new(), bindings: Vec::new(), registrations: Vec::new(), enums: BTreeMap::new() };
    let source = node("test", syn::parse_quote! { fn read(data: Vec<Option<u32>>) {} });
    let Item::Fn(function) = &source.item else { unreachable!() };
    assert_eq!(context.parameters(&function.sig, &[], &source, None).unwrap()[0].ty, "Iterable[int | None]");
    assert!(context.parameters(&function.sig, &[], &source, None).unwrap()[0].positional_only);
    let attrs = vec![syn::parse_quote!(#[pyi(params(dtaa = "bytes"))])];
    assert!(context.parameters(&function.sig, &attrs, &source, None).is_err());
}

#[test]
fn default_values_and_implicit_from_args_modes_are_optional_without_guessing() {
    let source = node("fixture", syn::parse_quote! { fn print(options: Options, py_vm: &VirtualMachine) {} });
    let Item::Fn(function) = &source.item else { unreachable!() };
    let context = Context {
        nodes: vec![node("fixture", syn::parse_quote! {
            #[derive(FromArgs)] struct Options {
                ep: u64,
                #[pyarg(named, default)] file: Option<PyObjectRef>,
                #[pyarg(named, default = ArgIntoBool::FALSE)] flush: ArgIntoBool,
            }
        })], bindings: Vec::new(), registrations: Vec::new(), enums: BTreeMap::new(),
    };
    let params = context.parameters(&function.sig, &[], &source, None).unwrap();
    assert_eq!(params.len(), 3);
    assert!(!params[0].optional && !params[0].positional_only && !params[0].keyword);
    assert!(params[1].optional && params[2].optional);
    assert_eq!(params[2].ty, "bool");
}

#[test]
fn return_types_map_to_python_annotations() {
    let context = Context {
        nodes: Vec::new(), bindings: Vec::new(),
        registrations: vec![Registration { old: "Layout".into(), domain: String::new(), name: "Layout".into() }],
        enums: BTreeMap::from([("Layout".into(), "crate::pe::image::Layout".into())]),
    };
    let source = node("fixture", syn::parse_quote!(fn example() {}));
    for (ty, expected) in [
        (syn::parse_quote!(PyResult<Option<PyRef<PyBytes>>>), "bytes | None"),
        (syn::parse_quote!(Option<PyRef<PyBool>>), "bool | None"),
        (syn::parse_quote!(PyListOf<PyRef<PyStr>>), "list[str]"),
        (syn::parse_quote!(PyResult<PyEnumValue<crate::pe::image::Layout>>), "br3k.pe.Layout"),
        (syn::parse_quote!(Either<PyRef<PyBytes>, PyListOf<u8>>), "bytes | list[int]"),
        (syn::parse_quote!(Vec<u8>), "bytes"),
    ] {
        assert_eq!(context.py_type(&ty, &source, None, Direction::Output).unwrap(), expected);
    }
    assert_eq!(context.py_type(&syn::parse_quote!(Vec<u8>), &source, None, Direction::Input).unwrap(), "Iterable[int]");
    assert!(context.py_type(&syn::parse_quote!(Vec<PyRef<PyStr>>), &source, None, Direction::Output).is_err());
}

#[test]
fn generated_api_is_documented_and_current() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let api = collect(&root).unwrap();
    assert!(api.classes.iter().flat_map(|class| &class.methods).all(|method| !method.returns.contains("Any")));
    assert!(api.functions.iter().all(|(_, method)| !method.returns.contains("Any") || matches!(method.name.as_str(), "config_read_variables" | "read_variables")));
    for class in &api.classes {
        assert!(!class.doc.is_empty(), "{}.{} needs source documentation", class.module, class.name);
        assert!(class.variants.iter().all(|(_, doc)| !doc.is_empty()), "{} has undocumented variants", class.name);
        for method in &class.methods { assert!(!method.doc.is_empty(), "{}.{} needs source documentation", class.name, method.name); }
    }
    for (module, method) in &api.functions {
        assert!(!method.doc.is_empty(), "{module}.{} needs source documentation", method.name);
    }
    for (name, contents) in crate::render::generate(&api).unwrap() {
        assert_eq!(fs::read_to_string(root.join(&name)).unwrap(), contents, "{name} is stale; run cargo api");
    }
}
