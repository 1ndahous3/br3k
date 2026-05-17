mod prelude;
pub mod sysapi;
pub mod ipc;
mod str;
pub mod fs;
mod kdump;
mod pdb;
mod pe_module;
mod shellcode;

pub mod vm;
pub mod logging;

pub const BR3K_VERSION: &str = env!("BR3K_VERSION");

#[cfg(test)]
mod tests {
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
        assert_py_files_have_header("tests", TEST_SCRIPT_HEADER);
    }
}
