use br3k::*;

use clap::{Arg, Command};

fn main() {
    env_logger::init();

    let matches = Command::new("br3k")
        .arg(
            Arg::new("script")
                .long("script")
                .help("Path to the Python script to execute"),
        )
        .get_matches();

    {
        let header = format!("br3k v{BR3K_VERSION}");
        let separator = "═".repeat(header.chars().count() + 2);

        println!();
        println!("╔{separator}╗");
        println!("  {header}  ");
        println!("╚{separator}╝");
    }

    if let Some(script_path) = matches.get_one::<String>("script") {
        let script_data = std::fs::read_to_string(script_path).expect("Unable to open script file");

        let py = python::py_module::PythonCore::new();
        match py.execute_script(&script_data) {
            Ok(_) => {
                println!("Script executed successfully.");
            }
            Err(e) => {
                eprintln!("Error executing script: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("Usage: br3k --script <script_path>");
    }
}
