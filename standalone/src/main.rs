use br3k::logging;
use br3k::vm;

use std::thread;

const SCRIPT_THREAD_STACK_SIZE: usize = 16 * 1024 * 1024;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_script.rs"));
}

fn execute_script(script_data: &'static str, script_path: String) {
    let script_handle = thread::Builder::new()
        .name("br3k-script".to_string())
        .stack_size(SCRIPT_THREAD_STACK_SIZE)
        .spawn(move || {
            let vm = vm::Vm::default();
            vm.execute_script(script_data, Some(script_path), &None)
        })
        .unwrap_or_else(|e| {
            eprintln!("Unable to start script thread: {e}");
            std::process::exit(1);
        });

    match script_handle.join() {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {
            eprintln!("Error executing script");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("Script thread panicked");
            std::process::exit(1);
        }
    }
}

fn main() {
    if let Err(e) = logging::init(true, false) {
        eprintln!("Unable to initialize logger: {e}");
    }

    let script_data = match embedded::EMBEDDED_SCRIPT {
        Some(script_data) => script_data,
        None => {
            println!("No embedded script. Build with BR3K_EMBED_SCRIPT=<path>");
            std::process::exit(1);
        }
    };
    let script_name = embedded::EMBEDDED_SCRIPT_NAME.unwrap_or("script");
    let script_path = embedded::EMBEDDED_SCRIPT_PATH.unwrap_or("<embedded-script>");

    println!("Mode: standalone embedded script ({script_name})");
    execute_script(script_data, script_path.to_owned());
}
