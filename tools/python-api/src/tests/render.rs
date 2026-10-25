use super::*;

#[test]
fn docstrings_unwrap_paragraphs_and_list_continuations() {
    let source = "First line\nsecond line.\n\n- One item\n  continued.\n- Another item.\n\n1. Numbered item\n   continued.\n10. Longer number\n    continued.\n";
    assert_eq!(unwrap_prose(source), "First line second line.\n\n- One item continued.\n- Another item.\n\n1. Numbered item continued.\n10. Longer number continued.");
}

#[test]
fn docstrings_preserve_markdown_blocks_and_hard_breaks() {
    let source = "# Heading\n\n```python\nfirst()\nsecond()\n```\n\n~~~~text\n~~~\nstill fenced\n~~~~\n\n    indented\n    code\n\n| A | B |\n|---|---|\n\n- Outer\n  - Inner\n\n> Quoted\n> lines\n\nLine  \nnext\\\nlast\n\n---\n\n[link]: target.md";
    assert_eq!(unwrap_prose(source), source);
}

#[test]
fn docstrings_escape_python_delimiters() {
    let mut text = String::new();
    docstring(&mut text, "path C:\\files\n\ntriple \"\"\"", "    ");
    assert!(text.contains("C:\\\\files"));
    assert!(text.contains("\\\"\\\"\\\""));
    assert!(text.lines().all(|line| line == line.trim_end()));
}

#[test]
fn unknown_public_types_fail_generation() {
    assert!(validate_type("list[br3k.pe.NoSuchType]", &BTreeSet::new()).is_err());
    assert!(validate_type("list[int | None]", &BTreeSet::new()).is_ok());
}

#[test]
fn stubs_preserve_public_aliases_and_builtin_types_in_class_scope() {
    let location = Location { path: "fixture.rs".into(), line: 1 };
    let api = Api {
        modules: BTreeMap::from([("br3k".into(), String::new()), ("br3k.fs".into(), String::new())]),
        classes: vec![Class {
            module: "br3k.fs".into(), name: "Mapping".into(), doc: "Mapped bytes.".into(), location: location.clone(), variants: Vec::new(),
            methods: vec![Method {
                name: "bytes".into(), kind: MethodKind::Method, parameters: Vec::new(), returns: "bytes | None".into(),
                doc: "Copy mapped bytes.".into(), location,
            }],
        }],
        aliases: vec![("br3k.fs".into(), "FileMapping".into(), "br3k.fs.Mapping".into()), ("br3k".into(), "FileMapping".into(), "br3k.fs.Mapping".into())],
        ..Api::default()
    };
    let files = generate(&api).unwrap();
    let stub = &files["stubs/br3k/fs.pyi"];
    assert!(stub.contains("def bytes(self) -> builtins.bytes | None:"));
    assert!(stub.contains("FileMapping = Mapping"));
    assert!(!stub.contains("from br3k.fs import Mapping as FileMapping"));
    let root = &files["stubs/br3k/__init__.pyi"];
    assert!(root.contains("from br3k.fs import Mapping as FileMapping"));
    assert!(root.contains("    \"FileMapping\","));
    assert!(stub.contains("Copy mapped bytes."));
    assert!(files.keys().all(|path| path.starts_with("stubs/") && path.ends_with(".pyi")));
}

#[test]
fn signatures_preserve_argument_modes() {
    let parameter = |name: &str, keyword, positional_only, optional| Parameter {
        name: name.into(), ty: "int".into(), keyword, positional_only, optional, doc: String::new(),
    };
    let method = Method {
        name: "read".into(), kind: MethodKind::Method, returns: "bytes".into(), doc: String::new(),
        location: Location { path: "fixture.rs".into(), line: 1 },
        parameters: vec![
            parameter("offset", false, true, false),
            parameter("mode", true, false, true),
            parameter("size", false, false, false),
        ],
    };
    assert_eq!(signature(&method), "read(self, offset: int, /, size: int, *, mode: int = ...) -> bytes");
}

#[test]
fn variadic_arguments_do_not_duplicate_keyword_separator() {
    let method = Method {
        name: "print".into(), kind: MethodKind::Function, returns: "None".into(), doc: String::new(),
        location: Location { path: "fixture.rs".into(), line: 1 },
        parameters: vec![
            Parameter { name: "*objects".into(), ty: "Any".into(), optional: false, keyword: false, positional_only: false, doc: String::new() },
            Parameter { name: "sep".into(), ty: "str".into(), optional: true, keyword: true, positional_only: false, doc: String::new() },
        ],
    };
    assert_eq!(signature(&method), "print(*objects: Any, sep: str = ...) -> None");
}
