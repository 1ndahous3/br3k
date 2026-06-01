use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after Unix epoch")
        .as_nanos();

    env::temp_dir().join(format!("br3k-standalone-{}-{nanos}", std::process::id()))
}

fn cargo_path() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("standalone crate must be inside the workspace")
}

fn standalone_path(target_dir: &Path) -> PathBuf {
    target_dir
        .join("debug")
        .join(format!("br3k-standalone{}", env::consts::EXE_SUFFIX))
}

#[test]
fn standalone_runs_script_embedded_at_build_time() {
    let temp_dir = unique_test_dir();
    fs::create_dir_all(&temp_dir).expect("failed to create temporary test directory");

    let script_path = temp_dir.join("embedded_test.py");
    fs::write(&script_path, "print('br3k-embedded-script-test-marker')\n")
        .expect("failed to write embedded test script");

    let target_dir = temp_dir.join("target");
    let build_output = Command::new(cargo_path())
        .current_dir(workspace_root())
        .env("BR3K_EMBED_SCRIPT", &script_path)
        .arg("build")
        .arg("-p")
        .arg("br3k-standalone")
        .arg("--target-dir")
        .arg(&target_dir)
        .output()
        .expect("failed to run cargo build");

    assert!(
        build_output.status.success(),
        "standalone build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let standalone_path = standalone_path(&target_dir);
    let run_output = Command::new(&standalone_path)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", standalone_path.display()));

    assert!(
        run_output.status.success(),
        "standalone run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );

    let stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        stdout.contains("Mode: standalone embedded script"),
        "standalone embedded mode was not selected\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("br3k-embedded-script-test-marker"),
        "embedded script output was not observed\nstdout:\n{stdout}"
    );
}
