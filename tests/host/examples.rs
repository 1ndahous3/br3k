use std::{fs, path::Path};
use serde::{Deserialize, Serialize};

use crate::support::Case;

fn read_only(script: &str) {
    let case = Case::new();
    let target = case.target();
    // These examples catch some per-module errors. VM feature tests provide semantic checks.
    case.run(&format!("scripts/pe/{script}.py"), &target.process_config());
}

fn validate_file(case: &Case, process_id: Option<u32>, module_name: Option<&str>, image_path: &Path, require_imports: bool) {
    #[derive(Serialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    struct Config<'a> {
        process_id: Option<u32>,
        module_name: Option<&'a str>,
        image_path: &'a Path,
        require_imports: bool,
    }
    assert!(image_path.is_file(), "missing output: {}", image_path.display());
    case.run("tests/vm/pe/validate_file.py", &Config { process_id, module_name, image_path, require_imports });
}

fn recover_module(module_name: Option<&str>) {
    let case = Case::new();
    let target = case.target();
    case.run("scripts/pe/recover_module.py", &target.module_config(module_name));
    let output = case.path().join(format!("recovered_{}", module_name.unwrap_or(target.name())));
    validate_file(&case, Some(target.pid()), module_name, &output, true);
}

#[test]
fn compare_memory_disk() {
    read_only("compare_memory_disk");
}

#[test]
fn find_hidden_modules() {
    read_only("find_hidden_modules");
}

#[test]
fn log_import_anomalies() {
    read_only("log_import_anomalies");
}

#[test]
fn scan_process_anomalies() {
    read_only("scan_process_anomalies");
}

#[test]
fn trace_api_references() {
    read_only("trace_api_references");
}

#[test]
fn recover_main() {
    recover_module(None);
}

#[test]
fn recover_ucrtbase() {
    recover_module(Some("ucrtbase.dll"));
}

#[test]
fn recover_unpacked() {
    let case = Case::new();
    let target = case.target();
    case.run("scripts/pe/recover_unpacked_process.py", &target.process_config());
    let outputs = fs::read_dir(case.path()).unwrap().map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with("unpacked_")).collect::<Vec<_>>();
    assert_eq!(outputs.len(), 1, "the scenario must emit exactly one image");
    // A selected hidden candidate can have a different machine type, for example under WOW64.
    validate_file(&case, None, None, &outputs[0], false);
}

#[test]
fn dump_process_modules() {
    let case = Case::new();
    let target = case.target();
    case.run("scripts/pe/dump_process_modules.py", &target.process_config());
    for name in [target.name(), "ucrtbase.dll", "ntdll.dll"] {
        let output = case.path().join(format!("dump_{name}"));
        validate_file(&case, Some(target.pid()), Some(name), &output, name != "ntdll.dll");
    }
}

#[derive(Deserialize)]
struct Baseline {
    modules: Vec<BaselineModule>,
}

#[derive(Deserialize)]
struct BaselineModule {
    name: String,
    error: Option<String>,
    size: Option<String>,
    normalized_header_hash: Option<String>,
    export_prologues: Option<PrologueResult>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PrologueResult {
    Hashes(Vec<Prologue>),
    Error { error: String },
}

#[derive(Deserialize)]
struct Prologue {
    rva: String,
    hash: String,
    size: usize,
    names: Vec<String>,
}

fn hex(value: &str) -> u64 {
    u64::from_str_radix(value.strip_prefix("0x").expect("hex prefix"), 16).expect("valid hex value")
}

#[test]
fn generate_pe_baseline() {
    let case = Case::new();
    let target = case.target();
    case.run("scripts/pe/generate_pe_baseline.py", &target.process_config());
    let baseline: Baseline = serde_norway::from_reader(fs::File::open(case.path().join("pe_baseline.yaml")).unwrap()).unwrap();
    for name in [target.name(), "ucrtbase.dll", "ntdll.dll"] {
        let module = baseline.modules.iter().find(|module| module.name.eq_ignore_ascii_case(name)).expect("missing baseline module");
        assert!(module.error.is_none(), "{name}: {:?}", module.error);
        hex(module.normalized_header_hash.as_deref().expect("missing header hash"));
        assert!(hex(module.size.as_deref().expect("missing image size")) > 0);
        let prologues = match module.export_prologues.as_ref().expect("missing export hashes") {
            PrologueResult::Hashes(items) => items,
            PrologueResult::Error { error } => panic!("{name}: {error}"),
        };
        if name.ends_with(".dll") {
            assert!(!prologues.is_empty(), "no export hashes for {name}");
        }
        for prologue in prologues {
            assert!(hex(&prologue.rva) > 0);
            hex(&prologue.hash);
            assert_eq!(prologue.size, 16);
            assert!(!prologue.names.is_empty());
        }
    }
}
