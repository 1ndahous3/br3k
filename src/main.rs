#![feature(default_field_values)]

mod prelude;
mod python;
mod sysapi_ctx;
mod sysapi;
mod str;
mod fs;
mod modules;
mod kdump;
mod pdb;
mod unique_resource;

use clap::{Arg, Command};
use log::info;

fn main() {
    env_logger::init();

    let matches = Command::new("br3k v0.2")
        .arg(
            Arg::new("script")
                .long("script")
                .help("Path to the Python script to execute"),
        )
        .get_matches();

    println!();
    println!(" ╔═══════════╗");
    println!(" ║ br3k v0.2 ║");
    println!(" ╚═══════════╝");
    println!();

    if let Some(script_path) = matches.get_one::<String>("script") {
        let script_data = std::fs::read_to_string(script_path).expect("Unable to open script file");

        let py = python::py_module::PythonCore::new();
        match py.execute_script(&script_data) {
            Ok(_) => {
                info!("Script executed successfully.");
            }
            Err(e) => {
                log::error!("Error executing script: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("Usage: br3k --script <script_path>");
    }
}
