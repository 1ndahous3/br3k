use crate::Error;
use quote::ToTokens;
use std::{collections::BTreeMap, result::Result};
use syn::{Expr, Item, Lit, Token, parse::Parser, punctuated::Punctuated, visit::Visit};

/// Explicit exports in native module initialization, before RustPython expands the macros.
#[derive(Default)]
pub struct Exports {
    pub classes: BTreeMap<String, String>,
    pub enums: BTreeMap<String, String>,
    pub constants: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
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
}

impl Exports {
    pub fn collect(&mut self, module: &str, item: &Item) -> Result<(), Error> {
        struct Collector<'a> { exports: &'a mut Exports, module: &'a str, error: Option<syn::Error> }
        impl Collector<'_> {
            fn record(&mut self, mac: &syn::Macro) -> syn::Result<()> {
                if mac.path.is_ident("register_enum") || mac.path.is_ident("register_enum_as") {
                    let args = Punctuated::<Expr, Token![,]>::parse_terminated.parse2(mac.tokens.clone())?;
                    let Expr::Path(ty) = args.last().ok_or_else(|| syn::Error::new_spanned(mac, "missing enum type"))? else {
                        return Err(syn::Error::new_spanned(mac, "expected enum type path"));
                    };
                    let name = if mac.path.is_ident("register_enum_as") {
                        let Some(Expr::Lit(value)) = args.get(3) else { return Err(syn::Error::new_spanned(mac, "expected enum name")); };
                        let Lit::Str(name) = &value.lit else { return Err(syn::Error::new_spanned(value, "expected enum name string")); };
                        name.value()
                    } else { ty.path.segments.last().unwrap().ident.to_string() };
                    self.exports.enums.insert(format!("{}.{name}", self.module), ty.path.to_token_stream().to_string().replace(' ', ""));
                }
                if mac.path.is_ident("extend_module") {
                    let parser = |input: syn::parse::ParseStream| {
                        let _: Expr = input.parse()?;
                        let _: Token![,] = input.parse()?;
                        let _: Expr = input.parse()?;
                        let _: Token![,] = input.parse()?;
                        let content;
                        syn::braced!(content in input);
                        while !content.is_empty() {
                            let name: syn::LitStr = content.parse()?;
                            let _: Token![=>] = content.parse()?;
                            let value: Expr = content.parse()?;
                            let full = format!("{}.{}", self.module, name.value());
                            if let Expr::Call(call) = &value && let Expr::Path(path) = call.func.as_ref()
                                && path.path.segments.last().is_some_and(|segment| segment.ident == "make_static_type")
                                && let Some(ty) = path.path.segments.iter().rev().nth(1) {
                                self.exports.classes.insert(full, ty.ident.to_string());
                            } else if name.value().chars().any(|ch| ch.is_ascii_uppercase())
                                && name.value().chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_') {
                                self.exports.constants.insert(full, if name.value() == "PE_DATA_DIRECTORY_NAMES" { "list[str]" } else { "int" }.into());
                            }
                            if !content.is_empty() { let _: Token![,] = content.parse()?; }
                        }
                        Ok(())
                    };
                    parser.parse2(mac.tokens.clone())?;
                }
                Ok(())
            }
        }
        impl<'ast> Visit<'ast> for Collector<'_> {
            fn visit_macro(&mut self, mac: &'ast syn::Macro) {
                if let Err(error) = self.record(mac) { self.error = Some(error); }
            }
        }
        let mut collector = Collector { exports: self, module, error: None };
        collector.visit_item(item);
        if let Some(error) = collector.error { return Err(error.into()); }
        Ok(())
    }

    pub fn canonical_classes(&self) -> BTreeMap<String, String> {
        let mut names = BTreeMap::new();
        let mut exports = self.classes.iter().collect::<Vec<_>>();
        // Feature namespaces take precedence; prefer short names within them.
        exports.sort_by_key(|(name, _)| {
            let (module, alias) = name.rsplit_once('.').unwrap();
            (module != "br3k", std::cmp::Reverse(alias.len()), std::cmp::Reverse(module.len()))
        });
        for (name, rust) in exports { names.insert(rust.clone(), name.clone()); }
        names
    }
}
