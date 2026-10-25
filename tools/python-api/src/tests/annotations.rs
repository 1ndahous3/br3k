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
