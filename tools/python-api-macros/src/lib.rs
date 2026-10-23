use proc_macro::TokenStream;
use quote::quote;

/// Validate and consume colocated #[pyi(...)] metadata before RustPython expands the item.
/// This macro does not write files, register runtime types, or replace RustPython documentation.
#[proc_macro_attribute]
pub fn py_api(args: TokenStream, item: TokenStream) -> TokenStream {
    if !args.is_empty() {
        return syn::Error::new(proc_macro::Span::call_site().into(), "py_api does not accept arguments").into_compile_error().into();
    }
    let mut item = syn::parse_macro_input!(item as syn::Item);
    match br3k_python_api::annotations::strip(&mut item) {
        Ok(()) => quote!(#item).into(),
        Err(error) => error.into_compile_error().into(),
    }
}
