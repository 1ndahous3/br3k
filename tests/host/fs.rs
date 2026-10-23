use std::path::Path;
use serde::Serialize;

use crate::support::Case;

#[test]
fn file_operations() {
    #[derive(Serialize)]
    struct Config<'a> {
        #[serde(rename = "TARGET_FILE")]
        target_file: &'a Path,
    }
    let case = Case::new();
    let target = case.path().join("file-suite.tmp");
    case.run("tests/vm/fs/operations.py", &Config { target_file: &target });
    assert!(!target.exists(), "file suite left its target behind");
}
