mod prelude;
pub mod sysapi;
pub mod br3k_ipc;
mod str;
pub mod fs;
mod kdump;
mod pdb;
pub mod pe;
mod shellcode;

pub mod vm;
pub mod logging;

pub const BR3K_VERSION: &str = env!("BR3K_VERSION");

#[cfg(test)]
mod tests {
    use crate::vm::{ScriptVarType, ScriptVars, Vm};

    use std::fs;
    use std::path::{Path, PathBuf};

    const SCRIPT_HEADER: &str = "\
# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# =============================================================================

";

    const TEST_SCRIPT_HEADER: &str = "\
# =============================================================================
# IMPORTANT USAGE NOTICE
# 1. Use only for authorized, non-malicious education, research, and testing.
# 2. This script is part of the test suite. It requires the config globals declared in the header;
#    pass every required value explicitly (for example, with the CLI '--config' option),
#    using `null` when a value is intentionally unset.
# 3. For standalone use with your own targets, it's more convenient to replace the globals
#    with concrete values and keep only the logic you need.
# =============================================================================

";

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("lib crate must be inside the workspace")
            .to_path_buf()
    }

    fn py_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        collect_py_files(dir, &mut files);
        files.sort();
        files
    }

    fn collect_py_files(dir: &Path, files: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()));

        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("failed to read entry in {}: {e}", dir.display()))
                .path();

            if path.is_dir() {
                collect_py_files(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "py") {
                files.push(path);
            }
        }
    }

    fn assert_py_files_have_header(dir: &str, expected_header: &str) {
        let root = workspace_root();
        let dir_path = root.join(dir);
        let files = py_files(&dir_path);
        assert!(!files.is_empty(), "no Python files found in {}", dir_path.display());

        let failed_files = files
            .iter()
            .filter_map(|path| {
                let data = fs::read_to_string(path)
                    .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

                if data.starts_with(expected_header) {
                    None
                } else {
                    Some(path.strip_prefix(&root).unwrap_or(path).display().to_string())
                }
            })
            .collect::<Vec<_>>();

        assert!(
            failed_files.is_empty(),
            "Python files have invalid headers:\n{}",
            failed_files.join("\n")
        );
    }

    #[test]
    fn scripts_have_usage_headers() {
        assert_py_files_have_header("scripts", SCRIPT_HEADER);
    }

    #[test]
    fn test_scripts_have_usage_headers() {
        assert_py_files_have_header("tests/vm", TEST_SCRIPT_HEADER);
    }

    #[test]
    fn pe_python_surface_smoke() {
        let script = r#"
import br3k

pe = br3k.pe
assert pe.Image.__name__ == "Image"
assert pe.Image.__module__ == "br3k.pe"
assert pe.Image.__doc__
assert pe.imports.Model.__name__ == "Model"
assert pe.imports.Model.__module__ == "br3k.pe.imports"
assert pe.recovery.Plan.__module__ == "br3k.pe.recovery"
assert not hasattr(pe, "PeImage")
for feature in ("headers", "sections", "imports", "exports", "resources", "relocations", "tls", "code"):
    assert hasattr(pe.Image, feature), feature
assert hasattr(pe, "ProcessView") and hasattr(pe, "Capture")
assert hasattr(pe.analysis.Comparison, "exports")
assert hasattr(pe.recovery.Plan, "build") and hasattr(pe.recovery.Plan, "validate")
assert hasattr(pe.Editor, "build")
assert hasattr(pe.imports.Imports, "delay") and hasattr(pe.imports.Imports, "bound")
assert hasattr(pe.code.Code, "trace")
assert pe.IMAGE_FILE_MACHINE_ARM64 == 0xaa64

try:
    pe.Image(b"not a PE")
except ValueError:
    pass
else:
    raise AssertionError("Image accepted invalid headers")
try:
    pe.recovery.Options(strength=pe.exports.SourcePolicy.Auto)
except TypeError:
    pass
else:
    raise AssertionError("An unrelated semantic enum was accepted")

options = pe.recovery.Options(strength=pe.recovery.Strength.Fast, trace_entry_point=True)
assert options.trace_entry_point
model = pe.imports.Model(8)
model.add_module("user32.dll", 0x2000, 1)
model.add_function("user32.dll", 0x2000, name="MessageBoxW")
function = model.imports()[0]
assert function.confidence == 100
assert function.evidence[0].kind == pe.imports.EvidenceKind.ManualSlot
assert function.evidence[0].resolution == pe.imports.ResolutionKind.Exact
assert model.pointer_size == 8 and model.revision == 2
before = model.revision
try:
    model.remove_function(0xffffffff)
except ValueError:
    pass
assert model.revision == before
assert pe.Layout.__module__ == "br3k.pe"
assert not hasattr(br3k, "PeImage") and not hasattr(pe.recovery, "ModuleDump")
assert not hasattr(pe.imports.Model, "fix_dump")
"#;

        Vm::default()
            .execute_script(script, None, &None)
            .expect("PE Python surface smoke script must run");
    }

    #[test]
    fn pe_python_documentation_uses_rust_comments() {
        crate::logging::init(true, false).unwrap();
        let script = r#"
import br3k

pe = br3k.pe
assert "Construct with file bytes" in pe.Image.__doc__
assert "checked RVA range" in pe.Image.read.__doc__
assert "no filesystem access" in pe.Image.from_file.__doc__
assert "original capture" in pe.recovery.Plan.build.__doc__
assert "optional matching" in pe.recovery.analyze.__doc__
assert "independent transactional state" in pe.Image.__doc__
"#;
        Vm::default().execute_script(script, None, &None).expect("Rust doc comments must reach Python runtime documentation");
    }

    #[test]
    fn pe_concrete_returns_preserve_python_values() {
        crate::logging::init(true, false).unwrap();
        let script = r#"
import br3k

pe = br3k.pe
section = pe.headers.Section(name=".text", virtual_address=0x1000, virtual_size=0x1000,
    raw_offset=0x400, raw_size=0x1000, characteristics=0x60000020)
synthetic = pe.headers.synthesize(bytes(0x3000), 0x140000000, [section],
    machine=pe.IMAGE_FILE_MACHINE_AMD64, entry_point_rva=0x1000)
assert isinstance(synthetic, pe.headers.SyntheticImage)
assert isinstance(synthetic.data, bytes) and synthetic.data is synthetic.data
image = pe.Image.from_mapped(synthetic.data, synthetic.image_base)
assert image.layout is pe.Layout.Mapped
assert isinstance(image.data, bytes) and isinstance(image.read(0x1000, 16), bytes)
assert isinstance(image.sections, list) and isinstance(image.sections[0], pe.headers.Section)
coff_offset = int.from_bytes(synthetic.data[0x3c:0x40], "little") + 4
header = pe.headers.parse_file_header(synthetic.data, coff_offset)
assert isinstance(header, pe.headers.FileHeader)
assert header.sections is header.sections
assert isinstance(header.sections[0], pe.headers.Section)
assert pe.headers.parse_file_header(b"invalid", 0) is None
assert pe.headers.parse_section_header(b"invalid", 0) is None
assert pe.headers.parse_section_table(b"invalid", 0) is None
assert image.tls.directory() is None
for directory, cls in ((image.debug, pe.headers.DataDirectory),
    (image.load_config, pe.load_config.Info), (image.clr, pe.clr.DirectoryInfo)):
    assert isinstance(directory.info(), cls)
symbols = pe.exports.Symbols([])
assert symbols.resolve_va(0) is None and symbols.resolve_all_va(0) == []
plan = pe.recovery.analyze(image, symbols)
assert isinstance(plan, pe.recovery.Plan) and plan.model is plan.model
assert isinstance(plan.diagnostics, list)
assert all(isinstance(item, pe.analysis.Diagnostic) for item in plan.diagnostics)
assert all(type(item.stage) is pe.analysis.Stage and type(item.severity) is pe.analysis.Severity for item in plan.diagnostics)
assert isinstance(plan.validate(), list)
options = pe.recovery.Options()
assert type(options.strength) is pe.recovery.Strength
assert isinstance(options.describe(), list) and all(isinstance(item, str) for item in options.describe())
"#;
        Vm::default().execute_script(script, None, &None).expect("Concrete PE returns must retain their runtime contracts");
    }

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
        collect_stubs(&workspace_root().join("stubs/br3k"), "br3k", &mut stubs);
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

    #[test]
    fn non_pe_python_documentation_and_argument_contracts() {
        crate::sysapi::ctx::SysApiCtx::init(crate::sysapi::ctx::InitOptions::default()).unwrap();
        let script = r#"
import br3k
from br3k import proc, fs, mem, resource, pdb, com, ipc, tx, sysapi, config

assert "independent memory" in proc.Process.__doc__
assert "FILE_OVERWRITE_IF" in fs.create_file.__doc__
assert "non-owning" in resource.BufferView.__doc__
assert "symbol RVAs" in pdb.Pdb.__doc__
assert "IRundown" in com.IRundown.__doc__
assert "named-pipe" in ipc.Channel.__doc__
assert "rollback" in tx.Transaction.__doc__
assert "DirectSyscall" in sysapi.init.__doc__
assert "YAML" in config.read_variables.__doc__
assert br3k.Process is proc.Process
assert br3k.FileMapping is fs.Mapping
assert br3k.BufferView is resource.BufferView
assert [item.value for item in br3k.ProcessOpenStrategy] == [item.value for item in proc.ProcessOpenStrategy]
data = b"documentation fixture"
view = resource.BufferView(data)
assert view.ptr != 0 and view.size == len(data)
assert mem.protection_text(mem.PAGE_EXECUTE_READ | mem.PAGE_GUARD) == "RX|GUARD"
assert mem.is_executable_protection(mem.PAGE_EXECUTE_READ)
assert not mem.is_readable_protection(mem.PAGE_READONLY | mem.PAGE_GUARD)
assert mem.type_text(mem.MEM_PRIVATE) == "MEM_PRIVATE"
process = proc.Process(pid="1")
try:
    process.open()
except ValueError:
    pass
else:
    raise AssertionError("an omitted open strategy must remain unset")
try:
    proc.Process(pid=1)
except TypeError:
    pass
else:
    raise AssertionError("PID currently requires a decimal string")
br3k.print("documentation", "fixture", sep=":", end="ignored", flush=True, file=None)
"#;
        Vm::default().execute_script(script, None, &None).expect("non-PE documentation and offline contracts must match runtime behavior");
    }

}
