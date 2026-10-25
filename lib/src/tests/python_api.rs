use crate::vm::{ScriptVarType, ScriptVars, Vm};
use std::fs;
use std::path::Path;

#[test]
fn python_stubs_match_runtime_registration() {
    crate::logging::init(true, false).unwrap();
    fn collect_stubs(dir: &Path, module: &str, stubs: &mut ScriptVars) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let stem = path.file_stem().unwrap().to_str().unwrap();
            if path.is_dir() { collect_stubs(&path, &format!("{module}.{stem}"), stubs); continue; }
            if path.extension().is_none_or(|extension| extension != "pyi") { continue; }
            let module = if stem == "__init__" { module.to_string() } else { format!("{module}.{stem}") };
            let source = fs::read_to_string(path).unwrap();
            stubs.insert(module, ScriptVarType::String(source.into()));
        }
    }
    let mut stubs = ScriptVars::new();
    collect_stubs(&Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("stubs/br3k"), "br3k", &mut stubs);
    let script = r#"
import ast
import br3k

def resolve(name):
    obj = br3k
    for part in name.split(".")[1:]:
        obj = getattr(obj, part)
    return obj

for module_name, source in STUBS.items():
    module = resolve(module_name)
    names = set()
    tree = ast.parse(source, filename=module_name + ".pyi")
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            owner = getattr(module, node.name)
            assert isinstance(owner, type), (module_name, node.name)
            if module_name.startswith("br3k.pe"):
                assert owner.__name__ == node.name, node.name
                assert owner.__module__ == module_name, node.name
            names.add(node.name)
            members = set()
            for member in node.body:
                if isinstance(member, ast.FunctionDef):
                    assert hasattr(owner, member.name), (node.name, member.name)
                    members.add(member.name)
                elif isinstance(member, ast.Assign):
                    for target in member.targets:
                        assert hasattr(owner, target.id), (node.name, target.id)
                        members.add(target.id)
            assert not {name for name in owner.__dict__ if not name.startswith("_")} - members, (module_name, node.name)
        elif isinstance(node, ast.FunctionDef):
            assert callable(getattr(module, node.name)), node.name
            names.add(node.name)
        elif isinstance(node, ast.AnnAssign):
            assert hasattr(module, node.target.id), node.target.id
            names.add(node.target.id)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 1 and node.module is None:
                names.update(alias.asname or alias.name for alias in node.names)
            elif node.module and node.module.startswith("br3k."):
                for alias in node.names:
                    name = alias.asname or alias.name
                    assert getattr(module, name) is getattr(resolve(node.module), alias.name), (module_name, name)
                    names.add(name)
    public = {name for name in dir(module) if not name.startswith("_")}
    assert public == names, (module_name, public - names, names - public)
"#;
    let vars = ScriptVars::from([("STUBS".into(), ScriptVarType::Object(stubs))]);
    Vm::default().execute_script(script, None, &Some(vars)).expect("stubs must parse and match every native namespace, export, alias, and member");
}
