use crate::{Error, annotations, exports::Exports, model::*};
use quote::ToTokens;
use std::{collections::{BTreeMap, BTreeSet}, fs, io, path::Path, result::Result};
use syn::{Attribute, Expr, FnArg, GenericArgument, ImplItem, Item, Lit, Meta, Pat, PathArguments, ReturnType, Type, parse::Parser, punctuated::Punctuated, spanned::Spanned, visit::{self, Visit}};

#[derive(Clone)]
struct Node { item: Item, path: String, rust_module: String, py_module: Option<String> }
#[derive(Clone)]
struct Binding { rust: String, rust_module: String, module: String, name: String, node: Node }
#[derive(Clone)]
struct Registration { old: String, domain: String, name: String }
impl Registration {
    fn module(&self) -> String { if self.domain.is_empty() { "br3k.pe".into() } else { format!("br3k.pe.{}", self.domain) } }
    fn full(&self) -> String { format!("{}.{}", self.module(), self.name) }
}

fn has(attrs: &[Attribute], name: &str) -> bool { attrs.iter().any(|attr| attr.path().is_ident(name)) }
fn strings(attrs: &[Attribute], name: &str) -> Result<BTreeMap<String, String>, Error> {
    let mut values = BTreeMap::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident(name)) {
        if let Meta::List(_) = &attr.meta {
            let nested = attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)?;
            for meta in nested {
                if let Meta::NameValue(pair) = meta && let Expr::Lit(value) = pair.value && let Lit::Str(value) = value.lit {
                    values.insert(pair.path.to_token_stream().to_string(), value.value());
                }
            }
        }
    }
    Ok(values)
}
fn flags(attrs: &[Attribute], name: &str) -> Result<BTreeSet<String>, Error> {
    let mut values = BTreeSet::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident(name)) {
        if let Meta::List(_) = attr.meta {
            for meta in attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)? {
                if let Meta::Path(path) = meta { values.insert(path.to_token_stream().to_string()); }
            }
        }
    }
    Ok(values)
}
fn has_default(attrs: &[Attribute]) -> Result<bool, Error> {
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("pyarg")) {
        for meta in attr.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)? {
            if meta.path().is_ident("default") || meta.path().is_ident("optional") { return Ok(true); }
        }
    }
    Ok(false)
}
fn doc(attrs: &[Attribute]) -> String {
    attrs.iter().filter_map(|attr| {
        if attr.path().is_ident("doc") && let Meta::NameValue(pair) = &attr.meta && let Expr::Lit(value) = &pair.value && let Lit::Str(value) = &value.lit {
            Some(value.value().strip_prefix(' ').unwrap_or(&value.value()).to_string())
        } else { None }
    }).collect::<Vec<_>>().join("\n").trim().to_string()
}
fn type_name(ty: &Type) -> Option<String> {
    match ty { Type::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()), _ => None }
}
fn location(node: &Node, span: proc_macro2::Span) -> Location { Location { path: node.path.clone(), line: span.start().line } }

fn walk(root: &Path, dir: &Path, nodes: &mut Vec<Node>) -> Result<(), Error> {
    let mut paths = fs::read_dir(dir)?.map(|entry| entry.map(|entry| entry.path())).collect::<Result<Vec<_>, io::Error>>()?;
    paths.sort();
    for path in paths {
        if path.is_dir() { walk(root, &path, nodes)?; continue; }
        if path.extension().is_none_or(|ext| ext != "rs") { continue; }
        let file = syn::parse_file(&fs::read_to_string(&path)?).map_err(|error| format!("{}: {error}", path.display()))?;
        let relative = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
        let module = relative.trim_end_matches(".rs").trim_end_matches("/mod").replace('/', "::");
        flatten(file.items, &relative, &module, None, nodes)?;
    }
    Ok(())
}
fn flatten(items: Vec<Item>, path: &str, module: &str, py_module: Option<String>, nodes: &mut Vec<Node>) -> Result<(), Error> {
    for item in items {
        if let Item::Mod(inner) = &item && let Some((_, children)) = &inner.content {
            let name = strings(&inner.attrs, "pymodule")?.get("name").cloned()
                .or_else(|| has(&inner.attrs, "pymodule").then(|| inner.ident.to_string())).or_else(|| py_module.clone());
            flatten(children.clone(), path, &format!("{module}::{}", inner.ident), name, nodes)?;
        }
        nodes.push(Node { item, path: path.into(), rust_module: module.into(), py_module: py_module.clone() });
    }
    Ok(())
}

fn registrations(nodes: &[Node]) -> Result<Vec<Registration>, Error> {
    let value = nodes.iter().find_map(|node| match &node.item {
        Item::Const(value) if node.path.ends_with("py_pe/namespaces.rs") && value.ident == "TYPES" => Some(value.expr.as_ref()), _ => None,
    }).ok_or("PE registration table not found")?;
    let Expr::Reference(value) = value else { return Err("expected a reference to the registration array".into()); };
    let Expr::Array(values) = value.expr.as_ref() else { return Err("expected registration array".into()); };
    values.elems.iter().map(|value| {
        let Expr::Tuple(fields) = value else { return Err("expected registration tuple".into()); };
        let fields = fields.elems.iter().map(|field| match field {
            Expr::Lit(value) if matches!(value.lit, Lit::Str(_)) => if let Lit::Str(value) = &value.lit { Ok(value.value()) } else { unreachable!() },
            _ => Err("registration fields must be strings"),
        }).collect::<Result<Vec<_>, _>>()?;
        if fields.len() != 3 { return Err("registration must have three fields".into()); }
        Ok(Registration { old: fields[0].clone(), domain: fields[1].clone(), name: fields[2].clone() })
    }).collect()
}

#[derive(Default)]
struct Macros { enums: BTreeMap<String, String>, error: Option<syn::Error> }
impl<'ast> Visit<'ast> for Macros {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac.path.is_ident("python_enums") {
            match Punctuated::<Expr, syn::Token![,]>::parse_terminated.parse2(mac.tokens.clone()) {
                Ok(entries) => {
                    for entry in entries {
                        if let Expr::Tuple(pair) = &entry && pair.elems.len() == 2
                            && let (Expr::Lit(name), Expr::Path(ty)) = (&pair.elems[0], &pair.elems[1]) && let Lit::Str(name) = &name.lit {
                            self.enums.insert(name.value(), ty.path.to_token_stream().to_string().replace(' ', ""));
                        } else { self.error = Some(syn::Error::new_spanned(entry, "expected (Python name, Rust enum type)")); }
                    }
                }
                Err(error) => self.error = Some(error),
            }
        }
        visit::visit_macro(self, mac);
    }
}
#[derive(Clone, Copy, PartialEq)]
enum Direction { Input, Output }

struct Context { nodes: Vec<Node>, bindings: Vec<Binding>, registrations: Vec<Registration>, enums: BTreeMap<String, String> }
impl Context {
    fn visible_paths(&self, ty: &Type, source: &Node) -> BTreeSet<String> {
        fn absolute(module: &str, parts: &[String]) -> String {
            let mut path = module.split("::").map(str::to_string).collect::<Vec<_>>();
            for part in parts {
                match part.as_str() {
                    "crate" => path = vec!["lib".into(), "src".into()],
                    "self" => (), "super" => { path.pop(); }, _ => path.push(part.clone()),
                }
            }
            path.join("::")
        }
        fn imports(tree: &syn::UseTree, prefix: &[String], name: &str, found: &mut Vec<Vec<String>>) {
            let mut prefix = prefix.to_vec();
            match tree {
                syn::UseTree::Path(path) => { prefix.push(path.ident.to_string()); imports(&path.tree, &prefix, name, found); }
                syn::UseTree::Group(group) => { for item in &group.items { imports(item, &prefix, name, found); } }
                syn::UseTree::Name(item) if item.ident == name => { prefix.push(item.ident.to_string()); found.push(prefix); }
                syn::UseTree::Rename(item) if item.rename == name => { prefix.push(item.ident.to_string()); found.push(prefix); }
                syn::UseTree::Glob(_) => { prefix.push(name.into()); found.push(prefix); }
                _ => (),
            }
        }
        let Type::Path(path) = ty else { return BTreeSet::new(); };
        let parts = path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>();
        let mut paths = BTreeSet::from([absolute(&source.rust_module, &parts)]);
        if parts.len() == 1 {
            for node in self.nodes.iter().filter(|node| node.rust_module == source.rust_module) {
                if let Item::Use(item) = &node.item {
                    let mut found = Vec::new();
                    imports(&item.tree, &[], &parts[0], &mut found);
                    paths.extend(found.iter().map(|parts| absolute(&source.rust_module, parts)));
                }
            }
        }
        paths
    }

    fn binding(&self, ty: &Type, node: &Node) -> Result<Option<&Binding>, Error> {
        let Some(name) = type_name(ty) else { return Ok(None); };
        let candidates = self.bindings.iter().filter(|item| item.rust == name).collect::<Vec<_>>();
        if candidates.len() <= 1 { return Ok(candidates.first().copied()); }
        let module_hint = match ty {
            Type::Path(ty) => ty.path.segments.iter().rev().nth(1).map(|part| part.ident.to_string()), _ => None,
        };
        let selected = candidates.iter().filter(|item| module_hint.as_ref().map_or(item.rust_module == node.rust_module, |hint| item.rust_module.ends_with(&format!("::{hint}")))).copied().collect::<Vec<_>>();
        if selected.len() == 1 { Ok(Some(selected[0])) } else { Err(format!("{}: ambiguous Python wrapper for Rust type {name}", node.path).into()) }
    }

    fn py_type(&self, ty: &Type, node: &Node, owner: Option<&Binding>, direction: Direction) -> Result<String, Error> {
        match ty {
            Type::Reference(ty) => return self.py_type(&ty.elem, node, owner, direction),
            Type::Tuple(ty) if ty.elems.is_empty() => return Ok("None".into()),
            Type::Slice(ty) if type_name(&ty.elem).as_deref() == Some("u8") => return Ok("bytes".into()),
            Type::Tuple(ty) => return Ok(format!("tuple[{}]", ty.elems.iter().map(|ty| self.py_type(ty, node, owner, direction)).collect::<Result<Vec<_>, _>>()?.join(", "))),
            _ => (),
        }
        let Some(name) = type_name(ty) else { return Ok("Any".into()); };
        let simple = match name.as_str() {
            "Self" => Some(owner.map_or("Any".into(), |owner| format!("{}.{}", owner.module, owner.name))),
            "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" => Some("int".into()),
            "f32" | "f64" => Some("float".into()), "bool" | "ArgIntoBool" => Some("bool".into()),
            "PyDictRef" => Some("dict[Any, Any]".into()),
            "PyObjectRef" | "PosArgs" => Some("Any".into()),
            "str" | "String" | "PyStr" | "PyStrRef" => Some("str".into()), "PyBytes" | "PyBytesRef" => Some("bytes".into()), "PyInt" => Some("int".into()), _ => None,
        };
        if let Some(simple) = simple { return Ok(simple); }
        if let Type::Path(path) = ty && let PathArguments::AngleBracketed(args) = &path.path.segments.last().unwrap().arguments {
            let types = args.args.iter().filter_map(|arg| if let GenericArgument::Type(ty) = arg { Some(ty) } else { None }).collect::<Vec<_>>();
            if let Some(inner) = types.first() {
                if name == "PyEnumValue" {
                    let rust = inner.to_token_stream().to_string().replace(' ', "");
                    let matches = self.enums.iter().filter(|(_, path)| **path == rust || path.rsplit("::").next() == type_name(inner).as_deref()).collect::<Vec<_>>();
                    if matches.len() != 1 { return Err(format!("{}: expected one registered enum for {rust}", node.path).into()); }
                    return Ok(self.registrations.iter().find(|registration| registration.old == *matches[0].0).ok_or("unregistered Python enum")?.full());
                }
                if name == "Vec" && direction == Direction::Output {
                    return match type_name(inner).as_deref() {
                        Some("u8") => Ok("bytes".into()),
                        Some("PyObjectRef") => Ok("list[Any]".into()),
                        _ => Err(format!("{}: use PyListOf<T> to return a typed Python list", node.path).into()),
                    };
                }
                if name == "Either" {
                    return Ok(types.iter().map(|ty| self.py_type(ty, node, owner, direction)).collect::<Result<Vec<_>, _>>()?.join(" | "));
                }
                let value = self.py_type(inner, node, owner, direction)?;
                match name.as_str() {
                    "PyResult" | "Result" | "PyRef" | "Py" | "OptionalArg" => return Ok(value),
                    "Option" => return Ok(format!("{value} | None")),
                    "Vec" => return Ok(format!("Iterable[{value}]")),
                    "PyListOf" => return Ok(format!("list[{value}]")),
                    _ => (),
                }
            }
        }
        Ok(self.binding(ty, node)?.map_or("Any".into(), |item| format!("{}.{}", item.module, item.name)))
    }

    fn args_struct(&self, ty: &Type, source: &Node) -> Result<Option<(&Node, &syn::ItemStruct)>, Error> {
        let Some(name) = type_name(ty) else { return Ok(None); };
        let candidates = self.nodes.iter().filter_map(|node| {
            if let Item::Struct(item) = &node.item && item.ident == name && flags(&item.attrs, "derive").ok()?.contains("FromArgs") { Some((node, item)) } else { None }
        }).collect::<Vec<_>>();
        if candidates.len() <= 1 { return Ok(candidates.first().copied()); }
        let visible = self.visible_paths(ty, source);
        let local = candidates.iter().filter(|(node, item)| visible.contains(&format!("{}::{}", node.rust_module, item.ident))).copied().collect::<Vec<_>>();
        if local.len() == 1 { Ok(Some(local[0])) } else { Err(format!("{}: ambiguous FromArgs {name}", source.path).into()) }
    }

    fn parameters(&self, sig: &syn::Signature, attrs: &[Attribute], node: &Node, owner: Option<&Binding>) -> Result<Vec<Parameter>, Error> {
        let hints = annotations::read(attrs)?;
        let mut params = Vec::new();
        for argument in &sig.inputs {
            let FnArg::Typed(argument) = argument else { continue; };
            let name = match argument.pat.as_ref() { Pat::Ident(name) => name.ident.to_string(), _ => return Err(format!("{}: add explicit argument names", node.path).into()) };
            let native_type = match argument.ty.as_ref() { Type::Reference(ty) => type_name(&ty.elem), ty => type_name(ty) };
            if native_type.as_deref() == Some("VirtualMachine") || matches!(name.as_str(), "cls" | "_cls" | "zelf") { continue; }
            if let Some((source, record)) = self.args_struct(&argument.ty, node)? {
                for field in &record.fields {
                    let flags = flags(&field.attrs, "pyarg")?;
                    let hints = annotations::read(&field.attrs)?;
                    params.push(Parameter {
                        name: field.ident.as_ref().ok_or("FromArgs requires named fields")?.to_string(),
                        ty: hints.ty.unwrap_or(self.py_type(&field.ty, source, owner, Direction::Input)?),
                        optional: has_default(&field.attrs)?,
                        keyword: flags.contains("named"), positional_only: flags.contains("positional"), doc: doc(&field.attrs),
                    });
                }
            } else {
                let variadic = native_type.as_deref() == Some("PosArgs");
                params.push(Parameter { name: if variadic { format!("*{name}") } else { name }, ty: self.py_type(&argument.ty, node, owner, Direction::Input)?, optional: type_name(&argument.ty).as_deref() == Some("OptionalArg"), keyword: false, positional_only: !variadic, doc: String::new() });
            }
        }
        for (name, ty) in hints.params {
            let parameter = params.iter_mut().find(|param| param.name == name).ok_or_else(|| format!("{}: type hint names nonexistent parameter {name}", node.path))?;
            parameter.ty = ty;
        }
        Ok(params)
    }

    fn method(&self, sig: &syn::Signature, attrs: &[Attribute], node: &Node, owner: Option<&Binding>, kind: MethodKind, attr: &str) -> Result<Method, Error> {
        let returns = match annotations::read(attrs)?.returns {
            Some(returns) => returns,
            None => match &sig.output { ReturnType::Default => "None".into(), ReturnType::Type(_, ty) => self.py_type(ty, node, owner, Direction::Output)? },
        };
        Ok(Method {
            name: strings(attrs, attr)?.get("name").cloned().unwrap_or_else(|| sig.ident.to_string()), kind,
            parameters: self.parameters(sig, attrs, node, owner)?, returns, doc: doc(attrs), location: location(node, sig.span()),
        })
    }

    fn constructor(&self, node: &Node, implementation: &syn::ItemImpl, owner: &Binding) -> Result<Method, Error> {
        let args = implementation.items.iter().find_map(|item| if let ImplItem::Type(item) = item && item.ident == "Args" { Some(&item.ty) } else { None }).ok_or("Constructor::Args missing")?;
        let method = implementation.items.iter().find_map(|item| if let ImplItem::Fn(item) = item && item.sig.ident == "py_new" { Some(item) } else { None }).ok_or("Constructor::py_new missing")?;
        let parameters = if let Type::Tuple(tuple) = args {
            let names = method.sig.inputs.iter().find_map(|arg| match arg {
                FnArg::Typed(arg) => match arg.pat.as_ref() { Pat::Tuple(tuple) => Some(&tuple.elems), _ => None }, _ => None,
            });
            let mut params = Vec::new();
            for (index, ty) in tuple.elems.iter().enumerate() {
                let name = names.and_then(|names| names.get(index)).and_then(|pat| match pat { Pat::Ident(name) => Some(name.ident.to_string()), _ => None }).unwrap_or_else(|| format!("arg{index}"));
                params.push(Parameter { name, ty: self.py_type(ty, node, Some(owner), Direction::Input)?, optional: type_name(ty).as_deref() == Some("OptionalArg"), keyword: false, positional_only: true, doc: String::new() });
            }
            params
        } else if self.args_struct(args, node)?.is_some() {
            let sig: syn::Signature = syn::parse_quote!(fn constructor(args: #args));
            self.parameters(&sig, &method.attrs, node, Some(owner))?
        } else {
            let name = method.sig.inputs.iter().filter_map(|arg| match arg {
                FnArg::Typed(arg) => match arg.pat.as_ref() { Pat::Ident(name) if !["_cls", "cls", "vm", "_vm"].contains(&name.ident.to_string().as_str()) => Some(name.ident.clone()), _ => None }, _ => None,
            }).next().ok_or("constructor argument name missing")?;
            let sig: syn::Signature = syn::parse_quote!(fn constructor(#name: #args));
            self.parameters(&sig, &method.attrs, node, Some(owner))?
        };
        Ok(Method { name: "__init__".into(), kind: MethodKind::Constructor, parameters, returns: "None".into(), doc: doc(&method.attrs), location: location(node, method.span()) })
    }
}

pub fn collect(root: &Path) -> Result<Api, Error> {
    let mut nodes = Vec::new();
    walk(root, &root.join("lib/src/vm"), &mut nodes)?;
    walk(root, &root.join("lib/src/pe"), &mut nodes)?;
    let path = "lib/src/fs.rs";
    flatten(syn::parse_file(&fs::read_to_string(root.join(path))?)?.items, path, "lib::src::fs", None, &mut nodes)?;
    let registrations = registrations(&nodes)?;
    let mut registered = registrations.iter().map(Registration::full).collect::<BTreeSet<_>>();
    let mut exports = Exports::default();
    for node in &nodes {
        if !matches!(node.item, Item::Mod(_)) && let Some(module) = &node.py_module { exports.collect(module, &node.item)?; }
    }
    // PE's temporary root exports are moved by its canonical namespace table at runtime.
    exports.classes.retain(|name, _| !name.starts_with("br3k.pe."));
    let external_names = exports.canonical_classes();
    registered.extend(external_names.values().cloned());
    registered.extend(exports.enums.keys().cloned());
    let mut bindings = Vec::new();
    for node in &nodes {
        if let Item::Struct(item) = &node.item && has(&item.attrs, "pyclass") {
            let attrs = strings(&item.attrs, "pyclass")?;
            let identity = attrs.get("module").zip(attrs.get("name")).map(|(module, name)| (module.clone(), name.clone()))
                .or_else(|| external_names.get(&item.ident.to_string()).and_then(|name| name.rsplit_once('.')).map(|(module, name)| (module.into(), name.into())));
            if let Some((module, name)) = identity {
                bindings.push(Binding { rust: item.ident.to_string(), rust_module: node.rust_module.clone(), module, name, node: node.clone() });
            }
        }
    }
    let mut macros = Macros::default();
    for node in nodes.iter().filter(|node| node.path.ends_with("py_pe/enums.rs")) { macros.visit_item(&node.item); }
    let context = Context { nodes, bindings, registrations, enums: macros.enums.clone() };
    let mut api = Api::default();
    for node in &context.nodes {
        if let Item::Mod(item) = &node.item && has(&item.attrs, "pymodule") {
            let name = strings(&item.attrs, "pymodule")?.get("name").cloned().unwrap_or_else(|| item.ident.to_string());
            api.modules.insert(name, doc(&item.attrs));
        }
    }
    for (full, rust) in &exports.classes {
        let canonical = external_names.get(rust).ok_or("class export has no canonical name")?;
        if full != canonical {
            let (module, name) = full.rsplit_once('.').unwrap();
            api.aliases.push((module.into(), name.into(), canonical.clone()));
        }
    }
    for owner in context.bindings.iter().filter(|owner| registered.contains(&format!("{}.{}", owner.module, owner.name))) {
        let Item::Struct(item) = &owner.node.item else { unreachable!() };
        let mut class = Class { module: owner.module.clone(), name: owner.name.clone(), doc: doc(&item.attrs), methods: Vec::new(), variants: Vec::new(), location: location(&owner.node, item.span()) };
        for node in &context.nodes {
            let Item::Impl(implementation) = &node.item else { continue; };
            if type_name(&implementation.self_ty).as_deref() != Some(&owner.rust) { continue; }
            if !has(&implementation.attrs, "pyclass") && implementation.trait_.as_ref().is_none_or(|(_, path, _)| path.segments.last().unwrap().ident != "Constructor") { continue; }
            let resolved = context.binding(&implementation.self_ty, node)?.ok_or("Python impl has no matching class")?;
            if resolved.module != owner.module || resolved.name != owner.name { continue; }
            if implementation.trait_.as_ref().is_some_and(|(_, path, _)| path.segments.last().unwrap().ident == "Constructor") {
                class.methods.push(context.constructor(node, implementation, owner)?);
            }
            if !has(&implementation.attrs, "pyclass") { continue; }
            for method in &implementation.items {
                let ImplItem::Fn(method) = method else { continue; };
                for (attr, kind) in [("pymethod", MethodKind::Method), ("pyclassmethod", MethodKind::ClassMethod), ("pystaticmethod", MethodKind::StaticMethod), ("pygetset", MethodKind::Property)] {
                    if !has(&method.attrs, attr) { continue; }
                    let setter = flags(&method.attrs, attr)?.contains("setter");
                    let mut method = context.method(&method.sig, &method.attrs, node, Some(owner), if setter { MethodKind::Setter } else { kind }, attr)?;
                    if setter { method.name = method.name.strip_prefix("set_").unwrap_or(&method.name).into(); }
                    class.methods.push(method);
                }
            }
        }
        api.classes.push(class);
    }
    for node in context.nodes.iter().filter(|node| node.py_module.is_some()) {
        // Inline modules have their own nodes, so visit their members only once.
        if let Item::Fn(item) = &node.item && has(&item.attrs, "pyfunction") {
            let module = node.py_module.clone().ok_or("pyfunction outside a named pymodule")?;
            api.functions.push((module, context.method(&item.sig, &item.attrs, node, None, MethodKind::Function, "pyfunction")?));
        }
    }
    if let Some(error) = macros.error { return Err(error.into()); }
    let mut enums = exports.enums;
    for (old, rust) in macros.enums {
        let registration = context.registrations.iter().find(|registration| registration.old == old).ok_or_else(|| format!("enum {old} has no canonical registration"))?;
        enums.insert(registration.full(), rust);
    }
    for (full, rust) in enums {
        let rust_name = rust.rsplit("::").next().unwrap();
        let definitions = context.nodes.iter().filter_map(|node| if let Item::Enum(item) = &node.item && matches!(item.vis, syn::Visibility::Public(_)) && item.ident == rust_name { Some((node, item)) } else { None }).collect::<Vec<_>>();
        if definitions.len() != 1 { return Err(format!("enum {rust} has {} definitions", definitions.len()).into()); }
        let (node, item) = definitions[0];
        let (module, name) = full.rsplit_once('.').unwrap();
        api.classes.push(Class { module: module.into(), name: name.into(), doc: doc(&item.attrs), methods: Vec::new(),
            variants: item.variants.iter().map(|variant| (variant.ident.to_string(), doc(&variant.attrs))).collect(), location: location(node, item.span()) });
    }
    for (full, ty) in exports.constants {
        let (module, name) = full.rsplit_once('.').unwrap();
        api.constants.push((module.into(), name.into(), ty));
    }
    let actual = api.classes.iter().map(|class| format!("{}.{}", class.module, class.name)).collect::<BTreeSet<_>>();
    if actual != registered || actual.len() != api.classes.len() { return Err(format!("Python registration/schema mismatch: missing={:?}, extra={:?}", registered.difference(&actual).collect::<Vec<_>>(), actual.difference(&registered).collect::<Vec<_>>()).into()); }
    api.classes.sort_by(|left, right| (&left.module, &left.name).cmp(&(&right.module, &right.name)));
    api.functions.sort_by(|left, right| (&left.0, &left.1.name).cmp(&(&right.0, &right.1.name)));
    Ok(api)
}

#[cfg(test)]
mod tests {
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
    fn return_adapters_follow_rustpython_conversion_semantics() {
        let context = Context {
            nodes: Vec::new(), bindings: Vec::new(),
            registrations: vec![Registration { old: "Layout".into(), domain: String::new(), name: "Layout".into() }],
            enums: BTreeMap::from([("Layout".into(), "crate::pe::image::Layout".into())]),
        };
        let source = node("fixture", syn::parse_quote!(fn example() {}));
        for (ty, expected) in [
            (syn::parse_quote!(PyResult<Option<PyRef<PyBytes>>>), "bytes | None"),
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
    fn repository_schema_and_generated_files_are_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
        let api = collect(&root).unwrap();
        let comparison = api.classes.iter().find(|class| class.module == "br3k.pe.analysis" && class.name == "Comparison").unwrap();
        assert!(comparison.methods.iter().find(|method| method.name == "complete").unwrap().doc.contains("optional components"));
        assert!(api.classes.len() > 100);
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
        assert!(api.aliases.iter().any(|(module, name, target)| module == "br3k" && name == "Process" && target == "br3k.proc.Process"));
        assert!(api.constants.iter().any(|(module, name, _)| module == "br3k.mem" && name == "MEM_IMAGE"));
        let imports = api.classes.iter().find(|class| class.module == "br3k.pe.analysis" && class.name == "ImportComparison").unwrap();
        assert_eq!(imports.methods.iter().map(|method| method.name.as_str()).collect::<Vec<_>>(), ["changes"]);
        for (name, contents) in crate::render::generate(&api).unwrap() {
            assert_eq!(fs::read_to_string(root.join(&name)).unwrap(), contents, "{name} is stale; run cargo api");
        }
    }
}
