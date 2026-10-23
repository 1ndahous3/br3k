use std::path::Path;
use serde::Serialize;

use crate::support::{Case, ModuleConfig};

fn image_operations(scenario: &str, module_name: Option<&str>) {
    let case = Case::new();
    let target = case.target();
    case.run(&format!("tests/vm/pe/{scenario}.py"), &target.module_config(module_name));
}

fn recovery(module_name: Option<&str>) {
    #[derive(Serialize)]
    struct Config<'a> {
        #[serde(flatten)]
        module: ModuleConfig<'a>,
        #[serde(rename = "OUTPUT_PATH")]
        output_path: &'a Path,
    }
    let case = Case::new();
    let target = case.target();
    let output = case.path().join(format!("recovered_{}", module_name.unwrap_or(target.name())));
    case.run("tests/vm/pe/recovery.py", &Config { module: target.module_config(module_name), output_path: &output });
    assert!(output.is_file(), "missing recovered file: {}", output.display());
}

fn process_analysis(scenario: &str) {
    let case = Case::new();
    let target = case.target();
    case.run(&format!("tests/vm/pe/{scenario}.py"), &target.process_config());
}

#[test]
fn image_main() {
    image_operations("image", None);
}

#[test]
fn image_ucrtbase() {
    image_operations("image", Some("ucrtbase.dll"));
}

#[test]
fn image_ntdll() {
    image_operations("image", Some("ntdll.dll"));
}

#[test]
fn editing_main() {
    image_operations("editing", None);
}

#[test]
fn editing_ucrtbase() {
    image_operations("editing", Some("ucrtbase.dll"));
}

#[test]
fn editing_ntdll() {
    image_operations("editing", Some("ntdll.dll"));
}

#[test]
fn recovery_main() {
    recovery(None);
}

#[test]
fn recovery_ucrtbase() {
    recovery(Some("ucrtbase.dll"));
}

#[test]
fn scan() {
    process_analysis("scan");
}

#[test]
fn trace() {
    process_analysis("trace");
}

#[test]
fn capture_lifetime() {
    process_analysis("capture_lifetime");
}
