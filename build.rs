use chrono::prelude::*;

const MAJOR_VERSION: u32 = 1;
const PATCH_VERSION: u32 = 0;
const SEQ_YEAR: i32 = 2025;

fn main() {
    let epoch = NaiveDate::from_ymd_opt(SEQ_YEAR, 1, 1).unwrap();
    let today = Utc::now().date_naive();
    let seq = (today - epoch).num_days();

    let version = format!("{MAJOR_VERSION}.{seq}.{PATCH_VERSION}");
    println!("cargo:rustc-env=BR3K_VERSION={}", version);
}