use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const EMBED_SCRIPT_ENV: &str = "BR3K_EMBED_SCRIPT";

fn rust_string_literal(value: &str) -> String {
    format!("{value:?}")
}

fn script_path_from_env() -> Option<PathBuf> {
    let value = env::var(EMBED_SCRIPT_ENV).ok()?;
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn absolute_script_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        let manifest_dir =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));
        let workspace_dir = manifest_dir.parent().unwrap_or(&manifest_dir);
        let workspace_path = workspace_dir.join(path);
        if workspace_path.exists() {
            workspace_path
        } else {
            manifest_dir.join(path)
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed={EMBED_SCRIPT_ENV}");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let out_file = out_dir.join("embedded_script.rs");

    let generated = match script_path_from_env() {
        Some(path) => {
            let path = absolute_script_path(&path);
            fs::read_to_string(&path).unwrap_or_else(|e| {
                panic!(
                    "{EMBED_SCRIPT_ENV} must point to a readable UTF-8 script file ({}): {e}",
                    path.display()
                )
            });

            let source_path = path.to_string_lossy();
            let script_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("script");

            println!("cargo:rerun-if-changed={source_path}");

            format!(
                "pub const EMBEDDED_SCRIPT: Option<&str> = Some(include_str!({}));\n\
                 pub const EMBEDDED_SCRIPT_PATH: Option<&str> = Some({});\n\
                 pub const EMBEDDED_SCRIPT_NAME: Option<&str> = Some({});\n",
                rust_string_literal(&source_path),
                rust_string_literal(&source_path),
                rust_string_literal(script_name),
            )
        }
        None => "pub const EMBEDDED_SCRIPT: Option<&str> = None;\n\
             pub const EMBEDDED_SCRIPT_PATH: Option<&str> = None;\n\
             pub const EMBEDDED_SCRIPT_NAME: Option<&str> = None;\n"
            .to_string(),
    };

    fs::write(out_file, generated).expect("failed to write generated embedded script module");
}
