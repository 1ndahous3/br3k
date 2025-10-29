use clap::{Arg, Command};

use br3k::ipc;
use br3k::logging;
use br3k::sysapi;
use br3k::sysapi_ctx;
use br3k::python;

fn main() {
    logging::init(true, true);
    logging::log_header();

    let matches = Command::new("br3k")
        .arg(
            Arg::new("script")
                .long("script")
                .help("Path to the Python script to execute"),
        )
        .get_matches();

    if let Some(script_path) = matches.get_one::<String>("script") {
        log::info!("Mode: script file ({})", script_path);
        let script_data = std::fs::read_to_string(script_path).expect("Unable to open script file");

        let py = python::py_module::PythonCore::new();
        match py.execute_script(&script_data) {
            Ok(_) => {
                log::info!("Script executed successfully.");
            }
            Err(e) => {
                log::error!("Error executing script: {}", e);
                std::process::exit(1);
            }
        }
    }
    else {
        let pid: u32 = unsafe { (*sysapi::teb()).ClientId.UniqueProcess } as _;
        log::info!("Mode: IPC client ({pid})");

        sysapi_ctx::SysApiCtx::init(sysapi_ctx::InitOptions {
            ntdll_copy: false,
            ntdll_alt_api: false,
        });

        let pipe_handle = ipc::open_pipe(pid as _)
            .map_err(|status| {
                log::error!("Unable to open pipe: {}", sysapi::ntstatus_decode(status));
                std::process::exit(1);
            }).unwrap();

        let script_data = ipc::receive_data(*pipe_handle.get())
            .map_err(|status| {
                log::error!("Unable to read script from pipe: {}", sysapi::ntstatus_decode(status));
                std::process::exit(1);
            }).unwrap();

        let script = String::from_utf8(script_data).unwrap();

        let py = python::py_module::PythonCore::new();
        match py.execute_script(&script) {
            Ok(_) => {
                log::info!("Script executed successfully.");
            }
            Err(e) => {
                log::error!("Error executing script: {}", e);
                std::process::exit(1);
            }
        }
    }
}
