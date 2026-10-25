use crate::{Error, model::*};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::result::Result;

pub fn signature(method: &Method) -> String {
    let mut parts = Vec::new();
    match method.kind {
        MethodKind::Method | MethodKind::Property | MethodKind::Setter | MethodKind::Constructor => parts.push("self".to_string()),
        MethodKind::ClassMethod => parts.push("cls".to_string()), _ => (),
    }
    let ordered = method.parameters.iter().filter(|param| !param.keyword).chain(method.parameters.iter().filter(|param| param.keyword)).collect::<Vec<_>>();
    let mut keyword = false;
    let mut optional = false;
    for (index, param) in ordered.iter().enumerate() {
        if param.name.starts_with('*') { keyword = true; }
        if !keyword && (param.keyword || optional && !param.optional) { parts.push("*".into()); keyword = true; }
        parts.push(format!("{}: {}{}", param.name, param.ty, if param.optional { " = ..." } else { "" }));
        optional |= param.optional;
        if param.positional_only && ordered.get(index + 1).is_none_or(|next| !next.positional_only) { parts.push("/".into()); }
    }
    format!("{}({}) -> {}", method.name, parts.join(", "), method.returns)
}

fn unshadow_type(ty: &str, names: &BTreeSet<&str>) -> String {
    ty.split_inclusive(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.')
        .map(|part| {
            let name = part.trim_end_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.');
            if names.contains(name) && matches!(name, "bytes" | "str" | "int" | "float" | "bool" | "list" | "dict" | "tuple" | "set" | "object" | "type") {
                format!("builtins.{part}")
            } else { part.to_string() }
        }).collect()
}

fn method_doc(method: &Method) -> String {
    let mut text = method.doc.clone();
    let documented = method.parameters.iter().filter(|param| !param.doc.is_empty()).collect::<Vec<_>>();
    if !documented.is_empty() {
        if !text.is_empty() { text.push_str("\n\n"); }
        text.push_str("Parameters:\n");
        for parameter in documented {
            let _ = writeln!(text, "    {}: {}", parameter.name, parameter.doc.replace('\n', "\n        "));
        }
    }
    text.trim_end().to_string()
}

fn docstring(out: &mut String, text: &str, indent: &str) {
    if text.is_empty() { return; }
    let text = unwrap_prose(text).replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"");
    let _ = writeln!(out, "{indent}\"\"\"");
    for line in text.lines() {
        if line.trim().is_empty() { out.push('\n'); } else { let _ = writeln!(out, "{indent}{}", line.trim_end()); }
    }
    let _ = writeln!(out, "{indent}\"\"\"");
}

fn stub_method(out: &mut String, method: &Method, indent: &str) {
    match method.kind {
        MethodKind::Property => { let _ = writeln!(out, "{indent}@property"); }
        MethodKind::Setter => { let _ = writeln!(out, "{indent}@{}.setter", method.name); }
        MethodKind::ClassMethod => { let _ = writeln!(out, "{indent}@classmethod"); }
        MethodKind::StaticMethod => { let _ = writeln!(out, "{indent}@staticmethod"); }
        _ => (),
    }
    let doc = method_doc(method);
    let _ = write!(out, "{indent}def {}:", signature(method));
    if doc.is_empty() { out.push_str(" ...\n"); } else {
        out.push('\n');
        let body_indent = format!("{indent}    ");
        docstring(out, &doc, &body_indent);
        let _ = writeln!(out, "{body_indent}...");
    }
}

fn validate_type(ty: &str, classes: &BTreeSet<String>) -> Result<(), Error> {
    for word in ty.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_') {
        if word.starts_with("br3k.") && !classes.contains(word) { return Err(format!("type hint references unregistered class {word}").into()); }
    }
    Ok(())
}

pub fn generate(api: &Api) -> Result<BTreeMap<String, String>, Error> {
    let mut generated = BTreeMap::new();
    let modules = api.modules.keys().cloned().chain(api.classes.iter().map(|class| class.module.clone())).chain(api.functions.iter().map(|(module, _)| module.clone())).collect::<BTreeSet<_>>();
    let classes = api.classes.iter().map(|class| format!("{}.{}", class.module, class.name)).chain(api.aliases.iter().map(|(module, name, _)| format!("{module}.{name}"))).collect::<BTreeSet<_>>();
    for method in api.classes.iter().flat_map(|class| &class.methods).chain(api.functions.iter().map(|(_, method)| method)) {
        validate_type(&method.returns, &classes)?;
        for param in &method.parameters { validate_type(&param.ty, &classes)?; }
    }
    for module in &modules {
        let prefix = format!("{module}.");
        let domains = modules.iter().filter_map(|module| module.strip_prefix(&prefix)).filter(|name| !name.contains('.')).collect::<Vec<_>>();
        let mut public_names = domains.clone();
        let package = !domains.is_empty();
        let path = module.replace('.', "/");
        let mut stub = String::from("# Generated by cargo api. Edit Rust declarations, not this file.\n");
        if let Some(doc) = api.modules.get(module) { docstring(&mut stub, doc, ""); }
        stub.push_str("from typing import Any, Iterable\nfrom enum import IntEnum\nimport builtins\nimport br3k\n");
        let methods = api.classes.iter().filter(|class| &class.module == module).flat_map(|class| &class.methods)
            .chain(api.functions.iter().filter(|(owner, _)| owner == module).map(|(_, method)| method));
        let dependencies = methods.flat_map(|method| std::iter::once(&method.returns).chain(method.parameters.iter().map(|param| &param.ty)))
            .flat_map(|ty| ty.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_'))
            .filter(|word| word.starts_with("br3k.")).filter_map(|word| word.rsplit_once('.').map(|(module, _)| module)).collect::<BTreeSet<_>>();
        for dependency in dependencies.iter().filter(|name| **name != "br3k") { let _ = writeln!(stub, "import {dependency}"); }
        stub.push('\n');
        if package {
            let _ = writeln!(stub, "from . import {}\n", domains.iter().map(|name| format!("{name} as {name}")).collect::<Vec<_>>().join(", "));
        }
        let module_classes = api.classes.iter().filter(|class| &class.module == module).collect::<Vec<_>>();
        for class in module_classes {
            public_names.push(class.name.as_str());
            let _ = writeln!(stub, "class {}{}:", class.name, if class.variants.is_empty() { "" } else { "(IntEnum)" });
            docstring(&mut stub, &class.doc, "    ");
            for (variant, doc) in &class.variants {
                let _ = writeln!(stub, "    {variant} = ...");
                docstring(&mut stub, doc, "    ");
            }
            let names = class.methods.iter().map(|method| method.name.as_str()).collect();
            for method in &class.methods {
                let mut method = method.clone();
                method.returns = unshadow_type(&method.returns, &names);
                for parameter in &mut method.parameters { parameter.ty = unshadow_type(&parameter.ty, &names); }
                stub_method(&mut stub, &method, "    ");
            }
            if class.doc.is_empty() && class.methods.is_empty() && class.variants.is_empty() { stub.push_str("    ...\n"); }
            stub.push('\n');
        }
        let functions = api.functions.iter().filter(|(owner, _)| owner == module).collect::<Vec<_>>();
        for (_, function) in functions {
            public_names.push(function.name.as_str());
            stub_method(&mut stub, function, "");
            stub.push('\n');
        }
        let aliases = api.aliases.iter().filter(|(owner, _, _)| owner == module).collect::<Vec<_>>();
        for (_, name, target) in aliases {
            public_names.push(name.as_str());
            let (target_module, target_name) = target.rsplit_once('.').unwrap();
            if target_module == module {
                let _ = writeln!(stub, "{name} = {target_name}");
            } else {
                let _ = writeln!(stub, "from {target_module} import {target_name} as {name}");
            }
        }
        let constants = api.constants.iter().filter(|(owner, _, _)| owner == module).collect::<Vec<_>>();
        if !constants.is_empty() {
            for (_, name, ty) in constants {
                public_names.push(name.as_str());
                let _ = writeln!(stub, "{name}: {ty}");
            }
        }
        stub.push_str("\n__all__ = [\n");
        for name in public_names { let _ = writeln!(stub, "    {name:?},"); }
        stub.push_str("]\n");
        generated.insert(format!("stubs/{path}{}.pyi", if package { "/__init__" } else { "" }), stub.trim_end().to_string() + "\n");
    }
    Ok(generated)
}

// Unwrap source comments without reformatting Markdown blocks in docstrings.
fn unwrap_prose(text: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    let mut continuation_indent: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if let Some((marker, length)) = fence {
            let count = trimmed.chars().take_while(|&ch| ch == marker).count();
            if indent < 4 && count >= length && trimmed[count..].trim().is_empty() { fence = None; }
            lines.push(line.into());
            continue;
        }
        let marker = trimmed.chars().next().unwrap_or(' ');
        let count = trimmed.chars().take_while(|&ch| ch == marker).count();
        if indent < 4 && matches!(marker, '`' | '~') && count >= 3 {
            fence = Some((marker, count));
            continuation_indent = None;
            lines.push(line.into());
            continue;
        }
        let list_prefix = if ["- ", "+ ", "* "].iter().any(|prefix| trimmed.starts_with(prefix)) {
            Some(2)
        } else {
            let digits = trimmed.bytes().take_while(u8::is_ascii_digit).count();
            (digits > 0 && (trimmed[digits..].starts_with(". ") || trimmed[digits..].starts_with(") "))).then_some(digits + 2)
        };
        let rule = matches!(marker, '-' | '*' | '_' | '=') && count >= 3 && trimmed.chars().all(|ch| ch == marker || ch == ' ');
        let block = trimmed.is_empty() || indent >= 4 && continuation_indent != Some(indent) || line.starts_with('\t') || rule
            || trimmed.starts_with(['#', '|', '>', '<']) || trimmed.starts_with('[') && trimmed.contains("]:");
        if block {
            continuation_indent = None;
            lines.push(line.into());
            continue;
        }
        if list_prefix.is_none() && continuation_indent.is_some_and(|expected| indent == 0 || indent == expected) {
            let previous = lines.last_mut().unwrap();
            previous.push(' ');
            previous.push_str(trimmed);
        } else {
            lines.push(line.into());
            continuation_indent = Some(indent + list_prefix.unwrap_or(0));
        }
        if line.ends_with("  ") || line.ends_with('\\') { continuation_indent = None; }
    }
    lines.join("\n")
}

#[cfg(test)]
#[path = "tests/render.rs"]
mod tests;
