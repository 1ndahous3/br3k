use std::collections::BTreeMap;
use syn::{Attribute, Item, LitStr, Result, visit_mut::{self, VisitMut}};

#[derive(Clone, Debug, Default)]
pub struct Hints {
    pub returns: Option<String>,
    pub ty: Option<String>,
    pub params: BTreeMap<String, String>,
}

fn type_text(literal: LitStr) -> Result<String> {
    let value = literal.value();
    let mut depth = 0usize;
    for ch in value.chars() {
        match ch {
            '[' => depth += 1,
            ']' if depth != 0 => depth -= 1,
            ']' => return Err(syn::Error::new_spanned(literal, "unbalanced Python type brackets")),
            ch if ch.is_ascii_alphanumeric() || "._ ,|".contains(ch) => (),
            _ => return Err(syn::Error::new_spanned(literal, "expected a Python type expression using names, brackets, commas, and unions")),
        }
    }
    if value.trim().is_empty() || depth != 0 {
        return Err(syn::Error::new_spanned(literal, "empty or unbalanced Python type expression"));
    }
    Ok(value)
}

pub fn read(attrs: &[Attribute]) -> Result<Hints> {
    let mut hints = Hints::default();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("pyi")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("returns") || meta.path.is_ident("ty") {
                let slot = if meta.path.is_ident("returns") { &mut hints.returns } else { &mut hints.ty };
                if slot.is_some() { return Err(meta.error("duplicate type hint")); }
                *slot = Some(type_text(meta.value()?.parse()?)?);
            } else if meta.path.is_ident("params") {
                meta.parse_nested_meta(|param| {
                    let name = param.path.get_ident().ok_or_else(|| param.error("expected a parameter name"))?.to_string();
                    let value = type_text(param.value()?.parse()?)?;
                    if hints.params.insert(name, value).is_some() { return Err(param.error("duplicate parameter hint")); }
                    Ok(())
                })?;
            } else { return Err(meta.error("expected returns, ty, or params")); }
            Ok(())
        })?;
    }
    Ok(hints)
}

fn consume(attrs: &mut Vec<Attribute>, field: bool) -> Result<()> {
    let hints = read(attrs)?;
    if field && (hints.returns.is_some() || !hints.params.is_empty()) || !field && hints.ty.is_some() {
        return Err(syn::Error::new(proc_macro2::Span::call_site(), "use ty on fields; returns/params on functions"));
    }
    attrs.retain(|attr| !attr.path().is_ident("pyi"));
    Ok(())
}

pub fn strip(item: &mut Item) -> Result<()> {
    #[derive(Default)]
    struct Strip { error: Option<syn::Error> }
    impl Strip {
        fn take(&mut self, attrs: &mut Vec<Attribute>, field: bool) {
            if let Err(error) = consume(attrs, field) {
                if let Some(previous) = &mut self.error { previous.combine(error); } else { self.error = Some(error); }
            }
        }
    }
    impl VisitMut for Strip {
        fn visit_impl_item_fn_mut(&mut self, method: &mut syn::ImplItemFn) {
            self.take(&mut method.attrs, false);
            visit_mut::visit_impl_item_fn_mut(self, method);
        }
        fn visit_item_fn_mut(&mut self, function: &mut syn::ItemFn) {
            self.take(&mut function.attrs, false);
            visit_mut::visit_item_fn_mut(self, function);
        }
        fn visit_field_mut(&mut self, field: &mut syn::Field) {
            self.take(&mut field.attrs, true);
            visit_mut::visit_field_mut(self, field);
        }
    }
    let mut visitor = Strip::default();
    visitor.visit_item_mut(item);
    visitor.error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    #[test]
    fn preserves_runtime_attributes_and_docs() {
        let mut item: Item = syn::parse_quote! {
            #[pyclass] impl Example {
                /// Current immutable image.
                #[pyi(returns = "br3k.pe.Image", params(other = "str | None"))]
                #[pymethod] fn get(&self, other: PyObjectRef) -> PyObjectRef { todo!() }
            }
        };
        strip(&mut item).unwrap();
        let text = quote!(#item).to_string();
        assert!(!text.contains("pyi"));
        assert!(text.contains("pyclass") && text.contains("pymethod") && text.contains("Current immutable image."));
    }

    #[test]
    fn rejects_unknown_duplicate_and_unbalanced_hints() {
        for attr in [
            syn::parse_quote!(#[pyi(result = "int")]),
            syn::parse_quote!(#[pyi(returns = "int", returns = "str")]),
            syn::parse_quote!(#[pyi(returns = "list[int")]),
        ] { assert!(read(&[attr]).is_err()); }
    }
}
